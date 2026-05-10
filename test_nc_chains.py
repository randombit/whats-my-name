#!/usr/bin/env python3
"""
Differential test: verify every name-constraint chain produced by
`generate_nc_chains.py` with `openssl verify`, GnuTLS's `certtool
--verify`, the local `go-verify` helper (crypto/x509.Verify), and
(optionally) Botan's `cert_verify` CLI, and report any divergence.

The intent is not to assert that every validator matches in every case
(they make different policy choices in some places, and a divergence may
be deliberate) but to surface differences so they can be reviewed.

Default input is ./out. Generate it first with:

    python generate_nc_chains.py testcases --out out --force

Each chain directory is expected to contain a metadata.json (whose
`expected` field starts with `valid` or `invalid`/`reject`), a
`trust-anchor.pem` for the shared root, and a sequence of numbered
`NN-id.cert.pem` files (root at NN=00, leaf at the highest NN).

Botan's CLI is autodiscovered from $BOTAN or $PATH. BoringSSL's `verify`
shim (boringssl-verify) is autodiscovered from $BORINGSSL or $PATH. The
Go, Rust, .NET, Java, and wolfSSL helpers are autodiscovered from
$GO_VERIFY / $RUST_VERIFY / $DOTNET_VERIFY / $JAVA_VERIFY /
$WOLFSSL_VERIFY, then ./bin/<name> relative to this script (where
`make` puts them), then $PATH. If a validator's binary isn't available
the script warns on stderr and continues with the rest. Pass
--no-openssl / --no-gnutls / --no-botan / --no-go / --no-rust
/ --no-dotnet / --no-java / --no-boringssl / --no-wolfssl to skip a
specific validator, or pass `--validators=openssl,botan,...` to limit
the run to just the named ones (any of: openssl, libressl, boringssl,
awslc, botan, gnutls, go, rust, dotnet, java, pyca, wolfssl).

When Go fails with `x509: unhandled critical extension` and every
other enabled validator says valid, Go's failure is treated as an
abstention rather than a divergence (Go can't make a decision about
the cert; it isn't disagreeing). The counted-as-clean chains are
annotated with `(go abstained)` in --verbose output and reported in
the summary line.

Wrong-direction chains (those that didn't end up clean) are grouped
into two buckets so security-impact bugs surface separately from
over-rejection bugs:

  Accepts-invalid: the testcase has `expected=invalid` but at least
    one validator accepted. This is the direction with security
    impact - a name constraint that should have rejected the chain
    didn't.
  Rejects-valid:   the testcase has `expected=valid` but at least
    one validator rejected. False-positive direction.

Within each bucket, chains where *every* validator went the wrong
way are tagged `[universal]` and sorted first; those either point at
a universal blind spot or at a wrong `expected` annotation in the
testcase JSON.

Exit code is 0 if no divergences are found, 1 otherwise.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _version_oneliner(args: list[str], env: dict[str, str] | None = None) -> str:
    """Run `args`, return the first non-empty trimmed line of combined output.

    Used to report each enabled validator's version. We don't trust exit
    codes (some CLIs print to stderr and return non-zero on `--help`-style
    flags), we just take the first line that has content. A failure to
    invoke the binary turns into a synthetic `(version: ...)` string so
    the rest of the run continues.
    """
    try:
        r = subprocess.run(args, capture_output=True, text=True, env=env)
    except FileNotFoundError as exc:
        return f"(version unavailable: {exc.strerror or exc})"
    out = (r.stdout + r.stderr).strip()
    for line in out.splitlines():
        s = line.strip()
        if s:
            return s
    return "(version: empty output)"


def run_openssl(leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run `openssl verify`. Returns (validated, combined output)."""
    args = ["openssl", "verify"]
    for u in untrusted:
        args += ["-untrusted", str(u)]
    args += ["-CAfile", str(root), str(leaf)]
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def version_openssl() -> str:
    return _version_oneliner(["openssl", "version"])


def version_libressl(cli: Path) -> str:
    return _version_oneliner([str(cli), "version"])


def version_boringssl(cli: Path) -> str:
    return _version_oneliner([str(cli), "--version"])


def version_awslc(cli: Path) -> str:
    return _version_oneliner([str(cli), "version"])


def version_botan(cli: Path) -> str:
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(cli.parent) + ":" + env.get("LD_LIBRARY_PATH", "")
    # `botan version` prints just the version number with no library prefix;
    # tag it so the output column is self-describing.
    raw = _version_oneliner([str(cli), "version"], env=env)
    if raw and not raw.lower().startswith("botan"):
        return f"Botan {raw}"
    return raw


def version_gnutls() -> str:
    return _version_oneliner(["certtool", "--version"])


def version_go(cli: Path) -> str:
    return _version_oneliner([str(cli), "-version"])


def version_rust(cli: Path) -> str:
    return _version_oneliner([str(cli), "--version"])


def version_dotnet(cli: Path) -> str:
    return _version_oneliner([str(cli), "--version"])


def version_java(cli: Path) -> str:
    return _version_oneliner([str(cli), "--version"])


def version_pyca(cli: Path) -> str:
    return _version_oneliner([sys.executable, str(cli), "--version"])


def version_wolfssl(cli: Path) -> str:
    return _version_oneliner([str(cli), "--version"])


def run_libressl(libressl_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run LibreSSL's `verify` CLI. Argument shape matches OpenSSL's `verify`.

    LibreSSL forked from OpenSSL but maintains an independent name-constraints
    implementation; worth a separate slot in the quorum.

    Like AWS-LC, LibreSSL's `verify` only honors the last `-untrusted` argument,
    so for chains with more than one intermediate we bundle them into a single
    concatenated PEM file and pass that.
    """
    args = [str(libressl_cli), "verify"]
    bundle: tempfile._TemporaryFileWrapper | None = None
    try:
        if len(untrusted) > 1:
            bundle = tempfile.NamedTemporaryFile(
                prefix="libressl-untrusted-", suffix=".pem", delete=False
            )
            for u in untrusted:
                bundle.write(u.read_bytes())
            bundle.close()
            args += ["-untrusted", bundle.name]
        else:
            for u in untrusted:
                args += ["-untrusted", str(u)]
        args += ["-CAfile", str(root), str(leaf)]
        r = subprocess.run(args, capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    finally:
        if bundle is not None:
            os.unlink(bundle.name)


def run_boringssl(boringssl_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the BoringSSL `verify` shim (boringssl-verify).

    Argument shape matches OpenSSL's `verify`. Unlike AWS-LC and LibreSSL,
    boringssl-verify's argv parser collects every `-untrusted` flag, so we
    can pass each intermediate as its own argument — no bundling needed.
    """
    args = [str(boringssl_cli), "-CAfile", str(root)]
    for u in untrusted:
        args += ["-untrusted", str(u)]
    args.append(str(leaf))
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def run_awslc(awslc_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run AWS-LC's `verify` CLI. AWS-LC forked BoringSSL (which forked OpenSSL);
    the CLI advertises itself as `OpenSSL 1.1.1 (compatible; AWS-LC ...)` and
    accepts the OpenSSL -CAfile / -untrusted flags.

    Unlike upstream OpenSSL, AWS-LC's `verify` only honors the last `-untrusted`
    argument on the command line, so chains with more than one intermediate
    silently lose all but one. It does accept a bundle of concatenated PEMs in
    a single `-untrusted` file, so when there's more than one intermediate we
    concatenate them into a tempfile and pass that.
    """
    args = [str(awslc_cli), "verify"]
    bundle: tempfile._TemporaryFileWrapper | None = None
    try:
        if len(untrusted) > 1:
            bundle = tempfile.NamedTemporaryFile(
                prefix="awslc-untrusted-", suffix=".pem", delete=False
            )
            for u in untrusted:
                bundle.write(u.read_bytes())
            bundle.close()
            args += ["-untrusted", bundle.name]
        else:
            for u in untrusted:
                args += ["-untrusted", str(u)]
        args += ["-CAfile", str(root), str(leaf)]
        r = subprocess.run(args, capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    finally:
        if bundle is not None:
            os.unlink(bundle.name)


def run_botan(botan_cli: Path, leaf: Path, ca_certs: list[Path]) -> tuple[bool, str]:
    """Run Botan's `cert_verify`. Returns (validated, output line)."""
    env = os.environ.copy()
    # If botan_cli is a binary inside an in-tree build, the matching
    # libbotan-*.so usually sits next to it; prepend that directory to
    # LD_LIBRARY_PATH so the CLI can load it.
    env["LD_LIBRARY_PATH"] = (
        str(botan_cli.parent) + ":" + env.get("LD_LIBRARY_PATH", "")
    )
    args = [str(botan_cli), "cert_verify", str(leaf)] + [str(c) for c in ca_certs]
    r = subprocess.run(args, capture_output=True, text=True, env=env)
    out = r.stdout.strip() or r.stderr.strip()
    return out.startswith("Certificate passes"), out


def run_go(go_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the local go-verify helper (crypto/x509.Verify). Returns (validated, output)."""
    args = [str(go_cli), "-ca", str(root)]
    for u in untrusted:
        args += ["-intermediate", str(u)]
    args.append(str(leaf))
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out


def run_rust(rust_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the local rust-verify helper (rustls-webpki). Returns (validated, output)."""
    args = [str(rust_cli), "--ca", str(root)]
    for u in untrusted:
        args += ["--intermediate", str(u)]
    args.append(str(leaf))
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out


def run_dotnet(dotnet_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the local dotnet-verifier helper (.NET X509Chain). Returns (validated, output)."""
    args = [str(dotnet_cli), "--ca", str(root)]
    for u in untrusted:
        args += ["--intermediate", str(u)]
    args.append(str(leaf))
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out


def run_java(java_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the local java-verify helper (PKIX CertPathValidator). Returns (validated, output)."""
    args = [str(java_cli), "--ca", str(root)]
    for u in untrusted:
        args += ["--intermediate", str(u)]
    args.append(str(leaf))
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out


def run_wolfssl(wolfssl_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the local wolfssl-verify helper (TLS-handshake verifier).

    Unlike the other helpers, this one validates the chain the way wolfSSL
    does it for a TLS peer rather than via the CertManager API: an in-process
    server presents the leaf + intermediates as its certificate chain and an
    in-process client, trusting only the root, validates them through
    wolfSSL's ProcessPeerCerts path. The CertManager API has no concept of an
    untrusted intermediate (every loaded cert becomes a trust anchor), so it
    can't model a real peer-chain validation; the TLS path can.

    Argv shape: `-CAfile <root> -key <leaf-key> <chain-bundle>`, where the
    bundle is leaf-first then intermediates toward (excluding) the root. We
    build the bundle in a tempfile from `leaf` + reversed(`untrusted`) so the
    leaf's direct issuer comes first after the leaf. The leaf's private key
    sits next to its cert as `NN-id.key.pem`; the server needs it to complete
    the handshake so an accepted chain yields a clean success.
    """
    key_path = Path(str(leaf).replace(".cert.pem", ".key.pem"))
    if not key_path.is_file():
        return False, f"wolfssl: leaf key not found next to {leaf.name} (expected {key_path.name})"

    bundle: tempfile._TemporaryFileWrapper | None = None
    try:
        bundle = tempfile.NamedTemporaryFile(
            prefix="wolfssl-chain-", suffix=".pem", delete=False
        )
        # Leaf first, then intermediates from leaf-side up toward the root.
        bundle.write(leaf.read_bytes())
        for u in reversed(untrusted):
            bundle.write(u.read_bytes())
        bundle.close()

        args = [str(wolfssl_cli), "-CAfile", str(root), "-key", str(key_path), bundle.name]
        r = subprocess.run(args, capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    finally:
        if bundle is not None:
            os.unlink(bundle.name)


def run_pyca(pyca_cli: Path, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run the local pyca-verify helper (python-cryptography x509.verification).

    pyca-verify is a Python script; we invoke it under the same interpreter
    as the harness via `sys.executable` so its `cryptography` import binds
    to the same package install. Running it out-of-process means the
    in-process Python work for one chain doesn't hold the GIL while the
    other (subprocess-based) validators are waiting their turn.
    """
    args = [sys.executable, str(pyca_cli), "--ca", str(root)]
    for u in untrusted:
        args += ["--intermediate", str(u)]
    args.append(str(leaf))
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    return r.returncode == 0, out


def run_gnutls(leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
    """Run GnuTLS `certtool --verify`. Returns (validated, summary).

    certtool reads the chain (leaf first, then intermediates) from stdin
    and the trust anchor from --load-ca-certificate. Its exit status is
    unreliable for this purpose: certtool returns 0 even when chain
    verification fails. We parse the final 'Chain verification output:'
    line instead.
    """
    chain_pem = b"".join(p.read_bytes() for p in (leaf, *untrusted))
    args = ["certtool", "--verify", "--load-ca-certificate", str(root)]
    r = subprocess.run(args, input=chain_pem, capture_output=True)
    text = (r.stdout + r.stderr).decode("utf-8", errors="replace").strip()
    # The summary line is what gnutls considers the chain's verdict;
    # per-cert "Output:" lines may say "Verified" for some certs even
    # when the overall chain fails.
    summary = ""
    for line in text.splitlines():
        if line.startswith("Chain verification output:"):
            summary = line[len("Chain verification output:"):].strip()
    ok = summary.startswith("Verified")
    return ok, summary or text


# Matches "NN-id.cert.pem" generated by generate_nc_chains.py. The leading
# integer determines chain order.
CERT_FILE_RE = re.compile(r"^(\d+)-.+\.cert\.pem$")


# --- per-validator output cleaning ---------------------------------------
#
# Each helper has its own verbosity quirks: OpenSSL prints subject DN +
# error code + file path + raw OPENSSL_NO error string, GnuTLS prints
# per-cert blocks, BoringSSL prefixes its lines with the leaf path, Java
# could throw a stack trace, etc. The harness already records pass/fail
# in the (ok, output) tuple's first slot, so the `output` field only
# needs to convey *why*. These cleaners take the raw subprocess output
# and produce a single-line summary suited for the report.
#
# Cleaners are intentionally conservative: when an output shape isn't
# recognised they fall back to the first non-empty line of input. That
# way an unfamiliar error string makes the run noisier (and obvious)
# rather than silently disappearing.

# Anchored to the "error N at M depth lookup:[ ]<msg>" shape that
# OpenSSL, LibreSSL, and AWS-LC all emit on verify failure.
_OPENSSL_ERR_RE = re.compile(
    r"^error\s+(\d+)\s+at\s+\d+\s+depth\s+lookup[: ]\s*(.+)$"
)


def _first_nonempty_line(raw: str) -> str:
    for line in raw.splitlines():
        s = line.strip()
        if s:
            return s
    return raw.strip()


def _clean_openssl_family(raw: str) -> str:
    """Trim openssl/libressl/awslc `verify` output to one line.

    Success looks like `<path>: OK`. Failure is a multi-line shape:

        <subject DN>
        error N at M depth lookup: <message>
        error <path>: verification failed
        <hex>:error:<long openssl tag>:...

    LibreSSL sometimes repeats the `error N at M depth lookup:` block
    once per cert in the chain; we dedupe. The hex/`OPENSSL_NO_*` line,
    the subject DN, and the `<path>: verification failed` trailer add
    no information beyond what the lookup-error message already gives.
    """
    if not raw:
        return ""
    # Success case: one-line "<path>: OK".
    for line in raw.splitlines():
        if line.strip().endswith(": OK"):
            return "OK"

    errors: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        m = _OPENSSL_ERR_RE.match(line.strip())
        if m:
            msg = f"error {m.group(1)}: {m.group(2).strip()}"
            if msg not in seen:
                seen.add(msg)
                errors.append(msg)
    if errors:
        return " | ".join(errors)
    return _first_nonempty_line(raw)


def _clean_boringssl(raw: str) -> str:
    """Trim boringssl-verify output.

    Success is `<path>: OK`. Failure looks like:

        <path>: verification failed
        error: ----- Certificate i=N (<subject DN>) -----
        ERROR: <actual message>
        [WARNING: ...]

    The shim's `printf("error: %s\\n", err.DiagnosticString())` collides
    the `error:` prefix with the diagnostic's leading `----- Certificate
    i=N (...) -----` separator, so an earlier version of this cleaner
    that picked the `error:`-prefixed line surfaced the subject DN
    header instead of the failure. The actual reason is on subsequent
    `ERROR: ` lines emitted by BoringSSL's `CertErrors::ToDebugString()`.
    """
    if not raw:
        return ""
    for line in raw.splitlines():
        if line.strip().endswith(": OK"):
            return "OK"
    errors: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("ERROR: "):
            msg = s[len("ERROR: "):]
            if msg not in seen:
                seen.add(msg)
                errors.append(msg)
        elif s.startswith("WARNING: "):
            msg = "warn: " + s[len("WARNING: "):]
            if msg not in seen:
                seen.add(msg)
                errors.append(msg)
    if errors:
        return " | ".join(errors)
    # No ERROR/WARNING lines in the diagnostic — fall back to the first
    # line of substance, skipping the path-prefixed status line and the
    # "----- Certificate i=N (...) -----" header.
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.endswith(": verification failed") or s.endswith(": OK"):
            continue
        if s.startswith("error: -----") or (s.startswith("-----") and s.endswith("-----")):
            continue
        return s
    return _first_nonempty_line(raw)


def _clean_botan(raw: str) -> str:
    """Trim Botan's cert_verify output.

    Botan prints one line. Drop the leading boilerplate so the message
    column shows the actual reason rather than "Certificate did not
    validate - <reason>".
    """
    s = _first_nonempty_line(raw)
    if s.startswith("Certificate passes"):
        return "OK"
    prefix = "Certificate did not validate - "
    if s.startswith(prefix):
        return s[len(prefix):]
    return s


def _clean_gnutls(raw: str) -> str:
    """Trim GnuTLS certtool output.

    `run_gnutls` already extracted the `Chain verification output:`
    summary line, so what reaches this cleaner is short. Just normalise
    whitespace and drop the trailing period that certtool likes to emit.
    """
    s = _first_nonempty_line(raw).rstrip(". ").strip()
    if s.startswith("Verified"):
        return "OK"
    return s


def _clean_java(raw: str) -> str:
    """Trim java-verify output.

    The Java helper now collapses RuntimeExceptions to a single line
    `verify failed: <ClassName>: <message>`, so there's normally only
    one line of output. If the JVM itself dies with a stack trace
    (NoClassDefFoundError etc.) we still get multi-line stderr; in that
    case keep the first non-empty line.
    """
    return _first_nonempty_line(raw)


def _clean_wolfssl(raw: str) -> str:
    """Trim wolfssl-verify output.

    Success is `<path>: OK`. Failure looks like:

        <path>: verification failed
        error: <wc_GetErrorString text> (<wolfCrypt errno>)

    Both shapes collapse to a single short line. The numeric errno is
    kept because some failure cases share the same human-readable
    string but different codes (and the differential report is more
    useful when those don't alias).
    """
    if not raw:
        return ""
    for line in raw.splitlines():
        if line.strip().endswith(": OK"):
            return "OK"
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("error: "):
            return s[len("error: "):]
    # Fall back to the first non-status line so a surprise error shape
    # still surfaces in the report rather than disappearing.
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.endswith(": verification failed"):
            continue
        return s
    return _first_nonempty_line(raw)


def _clean_default(raw: str) -> str:
    return _first_nonempty_line(raw)


CLEANERS: dict[str, "callable[[str], str]"] = {
    "openssl": _clean_openssl_family,
    "libressl": _clean_openssl_family,
    "awslc": _clean_openssl_family,
    "boringssl": _clean_boringssl,
    "botan": _clean_botan,
    "gnutls": _clean_gnutls,
    "java": _clean_java,
    "wolfssl": _clean_wolfssl,
}


def clean_output(name: str, raw: str) -> str:
    return CLEANERS.get(name, _clean_default)(raw)


def expected_from_metadata(value: str | None) -> bool | None:
    """Map a metadata `expected` string to a boolean, or None if unknown."""
    if not value:
        return None
    s = value.strip().lower()
    if s.startswith("valid"):
        return True
    if s.startswith("invalid") or s.startswith("reject"):
        return False
    return None


def discover_chains(out_dir: Path):
    """Yield (label, leaf, root, untrusted, expected_valid).

    Walks each chain subdirectory under `out_dir`, reads its
    `metadata.json`, and orders the per-chain certs by numeric prefix.
    The lowest-numbered cert is the root, the highest is the leaf,
    everything in between is an untrusted intermediate.
    """
    for chain_dir in sorted(out_dir.iterdir()):
        if not chain_dir.is_dir():
            continue
        metadata_path = chain_dir / "metadata.json"
        if not metadata_path.is_file():
            continue
        try:
            meta = json.loads(metadata_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"skip {chain_dir.name}: bad metadata.json ({exc})", file=sys.stderr)
            continue

        name = meta.get("name") or chain_dir.name
        expected = expected_from_metadata(meta.get("expected"))
        if expected is None:
            print(
                f"skip {name}: metadata.expected={meta.get('expected')!r} not "
                "recognized (expected to start with 'valid', 'invalid', or 'reject')",
                file=sys.stderr,
            )
            continue

        numbered: list[tuple[int, Path]] = []
        for path in chain_dir.iterdir():
            m = CERT_FILE_RE.match(path.name)
            if m:
                numbered.append((int(m.group(1)), path))
        if len(numbered) < 2:
            print(f"skip {name}: need at least two cert files", file=sys.stderr)
            continue
        numbered.sort(key=lambda p: p[0])
        certs = [p for _, p in numbered]
        root, *middle, leaf = certs
        yield (name, leaf, root, middle, expected)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Differentially verify generated name-constraint chains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "out",
        nargs="?",
        type=Path,
        default=Path("out"),
        help="Directory containing generated chain subdirectories (default: ./out)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every validator's verdict for each diverging chain, "
             "and emit a one-line `ok` summary for chains where every "
             "validator agreed with expected. Default lists only the "
             "diverging validators per chain (with a count of how many "
             "agreed) and omits the matching chains entirely.",
    )
    parser.add_argument(
        "--botan-cli",
        type=Path,
        default=None,
        help="Path to Botan's `botan` CLI. Defaults to $BOTAN or `botan` on $PATH.",
    )
    parser.add_argument(
        "--go-cli",
        type=Path,
        default=None,
        help="Path to the go-verify binary. Defaults to $GO_VERIFY, "
             "./bin/go-verify next to this script, or `go-verify` on $PATH.",
    )
    parser.add_argument(
        "--rust-cli",
        type=Path,
        default=None,
        help="Path to the rust-verify binary. Defaults to $RUST_VERIFY, "
             "./bin/rust-verify next to this script, or `rust-verify` on $PATH.",
    )
    parser.add_argument(
        "--dotnet-cli",
        type=Path,
        default=None,
        help="Path to the dotnet-verify binary. Defaults to $DOTNET_VERIFY, "
             "./bin/dotnet-verify next to this script, or `dotnet-verify` on $PATH.",
    )
    parser.add_argument(
        "--java-cli",
        type=Path,
        default=None,
        help="Path to the java-verify launcher. Defaults to $JAVA_VERIFY, "
             "./bin/java-verify next to this script, or `java-verify` on $PATH.",
    )
    parser.add_argument(
        "--pyca-cli",
        type=Path,
        default=None,
        help="Path to the pyca-verify script. Defaults to $PYCA_VERIFY, "
             "./bin/pyca-verify next to this script, or `pyca-verify` on $PATH. "
             "Always invoked through `sys.executable` so it picks up the same "
             "cryptography install as the harness.",
    )
    parser.add_argument(
        "--wolfssl-cli",
        type=Path,
        default=None,
        help="Path to the wolfssl-verify binary. Defaults to $WOLFSSL_VERIFY, "
             "./bin/wolfssl-verify next to this script, or `wolfssl-verify` on $PATH.",
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=None,
        metavar="N",
        help="Number of validator runs to execute concurrently. Default is "
             "Python's ThreadPoolExecutor default (min(32, cpu_count + 4)). "
             "Pass 1 to force serial execution.",
    )
    parser.add_argument(
        "--validators",
        type=str,
        default=None,
        metavar="LIST",
        help="Comma-separated allowlist of validators to run (e.g. "
             "`--validators=openssl,botan,dotnet`). When set, only the "
             "named validators are enabled; all others are skipped. "
             "Valid names: openssl, libressl, boringssl, awslc, botan, "
             "gnutls, go, rust, dotnet, java, pyca. Default is to run "
             "every validator.",
    )
    parser.add_argument(
        "--no-openssl",
        action="store_true",
        help="Skip `openssl verify`.",
    )
    parser.add_argument(
        "--libressl-cli",
        type=Path,
        default=None,
        help="Path to LibreSSL's openssl CLI. Defaults to $LIBRESSL or "
             "`libressl-openssl` on $PATH.",
    )
    parser.add_argument(
        "--no-libressl",
        action="store_true",
        help="Skip LibreSSL `verify`.",
    )
    parser.add_argument(
        "--boringssl-cli",
        type=Path,
        default=None,
        help="Path to the BoringSSL verify shim. Defaults to $BORINGSSL or "
             "`boringssl-verify` on $PATH.",
    )
    parser.add_argument(
        "--no-boringssl",
        action="store_true",
        help="Skip BoringSSL `verify` shim.",
    )
    parser.add_argument(
        "--awslc-cli",
        type=Path,
        default=None,
        help="Path to AWS-LC's openssl-alike CLI. Defaults to $AWSLC or "
             "`aws-lc` on $PATH.",
    )
    parser.add_argument(
        "--no-awslc",
        action="store_true",
        help="Skip AWS-LC `verify`.",
    )
    parser.add_argument(
        "--no-gnutls",
        action="store_true",
        help="Skip GnuTLS `certtool --verify`.",
    )
    parser.add_argument(
        "--no-botan",
        action="store_true",
        help="Skip Botan `cert_verify`.",
    )
    parser.add_argument(
        "--no-go",
        action="store_true",
        help="Skip the local go-verify helper.",
    )
    parser.add_argument(
        "--no-rust",
        action="store_true",
        help="Skip the local rust-verify helper.",
    )
    parser.add_argument(
        "--no-dotnet",
        action="store_true",
        help="Skip the local dotnet-verifier helper.",
    )
    parser.add_argument(
        "--no-java",
        action="store_true",
        help="Skip the local java-verify helper.",
    )
    parser.add_argument(
        "--no-pyca",
        action="store_true",
        help="Skip the python-cryptography x509.verification verifier.",
    )
    parser.add_argument(
        "--no-wolfssl",
        action="store_true",
        help="Skip the local wolfssl-verify helper.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out
    if not out_dir.is_dir():
        print(f"error: {out_dir} is not a directory", file=sys.stderr)
        return 1

    known_validators = (
        "openssl", "libressl", "boringssl", "awslc", "botan", "gnutls",
        "go", "rust", "dotnet", "java", "pyca", "wolfssl",
    )
    if args.validators is not None:
        requested = [v.strip() for v in args.validators.split(",") if v.strip()]
        unknown = [v for v in requested if v not in known_validators]
        if unknown:
            print(
                f"error: unknown validator(s) in --validators: "
                f"{', '.join(unknown)}",
                file=sys.stderr,
            )
            print(f"  known: {', '.join(known_validators)}", file=sys.stderr)
            return 1
        selected = set(requested)
    else:
        selected = set(known_validators)

    def resolve_tool(name: str, override: Path | None, env_var: str | None) -> Path | None:
        if override is not None:
            return override if override.exists() else None
        if env_var:
            envval = os.environ.get(env_var)
            if envval:
                p = Path(envval)
                if p.exists():
                    return p
        found = shutil.which(name)
        return Path(found) if found else None

    want_openssl = "openssl" in selected and not args.no_openssl
    use_openssl = want_openssl and shutil.which("openssl") is not None
    if want_openssl and not use_openssl:
        print("openssl not found in PATH; skipping OpenSSL checks", file=sys.stderr)

    libressl_cli: Path | None = None
    want_libressl = "libressl" in selected and not args.no_libressl
    if want_libressl:
        libressl_cli = resolve_tool("libressl-openssl", args.libressl_cli, "LIBRESSL")
        if libressl_cli is None:
            print(
                "libressl-openssl not found (set --libressl-cli or $LIBRESSL); "
                "skipping LibreSSL checks",
                file=sys.stderr,
            )
    use_libressl = libressl_cli is not None

    boringssl_cli: Path | None = None
    want_boringssl = "boringssl" in selected and not args.no_boringssl
    if want_boringssl:
        boringssl_cli = resolve_tool("boringssl-verify", args.boringssl_cli, "BORINGSSL")
        if boringssl_cli is None:
            print(
                "boringssl-verify not found (set --boringssl-cli or $BORINGSSL); "
                "skipping BoringSSL checks",
                file=sys.stderr,
            )
    use_boringssl = boringssl_cli is not None

    awslc_cli: Path | None = None
    want_awslc = "awslc" in selected and not args.no_awslc
    if want_awslc:
        awslc_cli = resolve_tool("aws-lc", args.awslc_cli, "AWSLC")
        if awslc_cli is None:
            print(
                "aws-lc not found (set --awslc-cli or $AWSLC); "
                "skipping AWS-LC checks",
                file=sys.stderr,
            )
    use_awslc = awslc_cli is not None

    want_gnutls = "gnutls" in selected and not args.no_gnutls
    use_gnutls = want_gnutls and shutil.which("certtool") is not None
    if want_gnutls and not use_gnutls:
        print("certtool not found in PATH; skipping GnuTLS checks", file=sys.stderr)

    botan_cli: Path | None = None
    want_botan = "botan" in selected and not args.no_botan
    if want_botan:
        botan_cli = resolve_tool("botan", args.botan_cli, "BOTAN")
        if botan_cli is None:
            print(
                "botan CLI not found (set --botan-cli or $BOTAN); skipping Botan checks",
                file=sys.stderr,
            )
    use_botan = botan_cli is not None

    # All three local verifier helpers are built by `make` into ./bin
    # next to this script. We accept an explicit override, then $ENV, then
    # ./bin/<name>, then $PATH.
    bin_dir = Path(__file__).resolve().parent / "bin"

    def resolve_local(name: str, override: Path | None, env_var: str) -> Path | None:
        if override is not None:
            return override if override.exists() else None
        envval = os.environ.get(env_var)
        if envval:
            p = Path(envval)
            if p.exists():
                return p
        local = bin_dir / name
        if local.exists():
            return local
        found = shutil.which(name)
        return Path(found) if found else None

    go_cli: Path | None = None
    want_go = "go" in selected and not args.no_go
    if want_go:
        go_cli = resolve_local("go-verify", args.go_cli, "GO_VERIFY")
        if go_cli is None:
            print(
                "go-verify not found (run `make go-verify` or set "
                "--go-cli / $GO_VERIFY); skipping Go checks",
                file=sys.stderr,
            )
    use_go = go_cli is not None

    rust_cli: Path | None = None
    want_rust = "rust" in selected and not args.no_rust
    if want_rust:
        rust_cli = resolve_local("rust-verify", args.rust_cli, "RUST_VERIFY")
        if rust_cli is None:
            print(
                "rust-verify not found (run `make rust-verify` or set "
                "--rust-cli / $RUST_VERIFY); skipping Rust checks",
                file=sys.stderr,
            )
    use_rust = rust_cli is not None

    dotnet_cli: Path | None = None
    want_dotnet = "dotnet" in selected and not args.no_dotnet
    if want_dotnet:
        dotnet_cli = resolve_local("dotnet-verify", args.dotnet_cli, "DOTNET_VERIFY")
        if dotnet_cli is None:
            print(
                "dotnet-verify not found (run `make dotnet-verify` or set "
                "--dotnet-cli / $DOTNET_VERIFY); skipping .NET checks",
                file=sys.stderr,
            )
    use_dotnet = dotnet_cli is not None

    java_cli: Path | None = None
    want_java = "java" in selected and not args.no_java
    if want_java:
        java_cli = resolve_local("java-verify", args.java_cli, "JAVA_VERIFY")
        if java_cli is None:
            print(
                "java-verify not found (run `make java-verify` or set "
                "--java-cli / $JAVA_VERIFY); skipping Java checks",
                file=sys.stderr,
            )
    use_java = java_cli is not None

    pyca_cli: Path | None = None
    want_pyca = "pyca" in selected and not args.no_pyca
    if want_pyca:
        pyca_cli = resolve_local("pyca-verify", args.pyca_cli, "PYCA_VERIFY")
        if pyca_cli is None:
            print(
                "pyca-verify not found (run `make pyca-verify` or set "
                "--pyca-cli / $PYCA_VERIFY); skipping pyca checks",
                file=sys.stderr,
            )
    use_pyca = pyca_cli is not None

    wolfssl_cli: Path | None = None
    want_wolfssl = "wolfssl" in selected and not args.no_wolfssl
    if want_wolfssl:
        wolfssl_cli = resolve_local("wolfssl-verify", args.wolfssl_cli, "WOLFSSL_VERIFY")
        if wolfssl_cli is None:
            print(
                "wolfssl-verify not found (run `make wolfssl-verify` or set "
                "--wolfssl-cli / $WOLFSSL_VERIFY); skipping wolfSSL checks",
                file=sys.stderr,
            )
    use_wolfssl = wolfssl_cli is not None

    if not (use_openssl or use_libressl or use_boringssl or use_awslc or use_gnutls or use_botan or use_go or use_rust or use_dotnet or use_java or use_pyca or use_wolfssl):
        print("no validators enabled; nothing to do", file=sys.stderr)
        return 1

    # Identify each enabled validator before running anything. These strings
    # also appear in the final summary so a reader of a saved report can tell
    # which library versions were exercised without re-running the harness.
    version_specs: list[tuple[str, object]] = []
    if use_openssl:
        version_specs.append(("openssl", lambda: version_openssl()))
    if use_libressl:
        version_specs.append(("libressl", lambda: version_libressl(libressl_cli)))
    if use_boringssl:
        version_specs.append(("boringssl", lambda: version_boringssl(boringssl_cli)))
    if use_awslc:
        version_specs.append(("awslc", lambda: version_awslc(awslc_cli)))
    if use_botan:
        version_specs.append(("botan", lambda: version_botan(botan_cli)))
    if use_gnutls:
        version_specs.append(("gnutls", lambda: version_gnutls()))
    if use_go:
        version_specs.append(("go", lambda: version_go(go_cli)))
    if use_rust:
        version_specs.append(("rust", lambda: version_rust(rust_cli)))
    if use_dotnet:
        version_specs.append(("dotnet", lambda: version_dotnet(dotnet_cli)))
    if use_java:
        version_specs.append(("java", lambda: version_java(java_cli)))
    if use_pyca:
        version_specs.append(("pyca", lambda: version_pyca(pyca_cli)))
    if use_wolfssl:
        version_specs.append(("wolfssl", lambda: version_wolfssl(wolfssl_cli)))

    versions: dict[str, str] = {}
    for name, fn in version_specs:
        try:
            versions[name] = fn()
        except Exception as exc:
            versions[name] = f"(version error: {type(exc).__name__}: {exc})"

    width = max((len(n) for n in versions), default=0)
    print("Validator versions:")
    for name, _ in version_specs:
        print(f"  {name:<{width}}  {versions[name]}")
    print()

    cases = list(discover_chains(out_dir))
    if not cases:
        print(f"no chains found under {out_dir}", file=sys.stderr)
        return 1

    clean = 0
    go_abstained = 0
    # accepts_invalid: expected=invalid AND at least one validator said valid.
    #   These are the security-impact direction — a CA's name constraints
    #   were not enforced. Universal cases (every validator accepted) usually
    #   mean a corpus-wide blind spot or a wrong `expected` annotation.
    # rejects_valid: expected=valid AND at least one validator said invalid.
    #   These are the false-positive direction — a validator rejected a chain
    #   the RFC says is fine. Less severe by itself but still real bugs;
    #   universal cases here usually mean the testcase's `expected` is wrong.
    accepts_invalid: list[dict] = []
    rejects_valid: list[dict] = []
    # Map (validator_name, direction_str) -> list of labels where that
    # validator was alone in disagreeing with all the others. Direction
    # is "alone in accepting" (the outlier says valid while the others
    # all say invalid) or "alone in rejecting" (the outlier says invalid
    # while the others all say valid). Independent of the metadata
    # expected value - this is purely about which validator is the odd
    # one out among the validators we ran.
    outliers: dict[tuple[str, str], list[str]] = {}

    # Validators run as a flat pool of (chain_index, validator_name) work
    # items so a single slow validator (Java's JVM startup alone is ~200ms
    # per invocation) doesn't serialize the whole run. Each helper is
    # already a subprocess that releases the GIL during `subprocess.run`,
    # so threads are the right primitive — we're orchestrating
    # I/O-style waits, not CPU work.
    #
    # The canonical validator order is preserved for output by iterating
    # `enabled_order` when assembling each chain's results list, regardless
    # of completion order.
    # Each entry pairs a validator name with a thunk taking
    # (leaf, root, untrusted) and returning (ok, output). Resolved CLI paths
    # / Cargo-side state are captured by the lambda's closure.
    enabled_order: list[tuple[str, object]] = []
    if use_openssl:
        enabled_order.append(("openssl", lambda leaf, root, untrusted: run_openssl(leaf, root, untrusted)))
    if use_libressl:
        enabled_order.append(("libressl", lambda leaf, root, untrusted: run_libressl(libressl_cli, leaf, root, untrusted)))
    if use_boringssl:
        enabled_order.append(("boringssl", lambda leaf, root, untrusted: run_boringssl(boringssl_cli, leaf, root, untrusted)))
    if use_awslc:
        enabled_order.append(("awslc", lambda leaf, root, untrusted: run_awslc(awslc_cli, leaf, root, untrusted)))
    if use_botan:
        # Botan's cert_verify takes the leaf followed by all trust-anchor /
        # intermediate certs; it needs the intermediates available even if
        # they're not roots.
        enabled_order.append(("botan", lambda leaf, root, untrusted: run_botan(botan_cli, leaf, [root, *untrusted])))
    if use_gnutls:
        enabled_order.append(("gnutls", lambda leaf, root, untrusted: run_gnutls(leaf, root, untrusted)))
    if use_go:
        enabled_order.append(("go", lambda leaf, root, untrusted: run_go(go_cli, leaf, root, untrusted)))
    if use_rust:
        enabled_order.append(("rust", lambda leaf, root, untrusted: run_rust(rust_cli, leaf, root, untrusted)))
    if use_dotnet:
        enabled_order.append(("dotnet", lambda leaf, root, untrusted: run_dotnet(dotnet_cli, leaf, root, untrusted)))
    if use_java:
        enabled_order.append(("java", lambda leaf, root, untrusted: run_java(java_cli, leaf, root, untrusted)))
    if use_pyca:
        enabled_order.append(("pyca", lambda leaf, root, untrusted: run_pyca(pyca_cli, leaf, root, untrusted)))
    if use_wolfssl:
        enabled_order.append(("wolfssl", lambda leaf, root, untrusted: run_wolfssl(wolfssl_cli, leaf, root, untrusted)))

    def _run_one(name: str, fn, leaf: Path, root: Path, untrusted: list[Path]) -> tuple[bool, str]:
        # The pool catches and re-raises through fut.result(); we want a
        # synthetic verdict instead so one buggy helper doesn't crash the
        # whole run.
        try:
            return fn(leaf, root, untrusted)
        except Exception as exc:
            return False, f"{name}: harness error: {type(exc).__name__}: {exc}"

    # chain_results[i][name] = (ok, out)
    chain_results: list[dict[str, tuple[bool, str]]] = [dict() for _ in cases]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures: dict[concurrent.futures.Future, tuple[int, str]] = {}
        for chain_idx, (label, leaf, root, untrusted, expected) in enumerate(cases):
            for name, fn in enabled_order:
                fut = ex.submit(_run_one, name, fn, leaf, root, untrusted)
                futures[fut] = (chain_idx, name)
        for fut in concurrent.futures.as_completed(futures):
            chain_idx, name = futures[fut]
            ok, raw = fut.result()
            chain_results[chain_idx][name] = (ok, clean_output(name, raw))

    for chain_idx, (label, leaf, root, untrusted, expected) in enumerate(cases):
        per = chain_results[chain_idx]
        results: list[tuple[str, bool, str]] = [
            (name, *per[name]) for name, _ in enabled_order
        ]

        # Go's `x509: unhandled critical extension` failure is an
        # abstention, not a verdict. When every other validator says
        # valid, treat Go as agreeing for the purpose of categorization.
        # The original Go output is preserved in `results` for reporting.
        adjusted = list(results)
        go_abstained_here = False
        if use_go and len(results) > 1:
            go_idx = next(i for i, (n, _, _) in enumerate(results) if n == "go")
            go_name, go_ok, go_out = results[go_idx]
            others = [(n, ok, o) for n, ok, o in results if n != "go"]
            if (
                not go_ok
                and "x509: unhandled critical extension" in go_out
                and all(ok for _, ok, _ in others)
            ):
                adjusted[go_idx] = (go_name, True, go_out)
                go_abstained_here = True
                go_abstained += 1

        verdicts = {ok for _, ok, _ in adjusted}
        all_agree = len(verdicts) == 1
        matches_expected = all(ok == expected for _, ok, _ in adjusted)

        if all_agree and matches_expected:
            clean += 1
            if args.verbose:
                v = "accept" if adjusted[0][1] else "reject"
                e = "accept" if expected else "reject"
                tag = " (go abstained)" if go_abstained_here else ""
                print(f"  ok  {label}: all={v} expected={e}{tag}")
        else:
            # Classify the failure direction by the testcase's expected
            # verdict. `adjusted` includes Go's abstention-as-valid
            # rewrite, so a chain only enters one of these buckets if a
            # real validator went the wrong way.
            wrong_names = [n for n, ok, _ in adjusted if ok != expected]
            universal = (len(wrong_names) == len(adjusted))
            record = {
                "label": label,
                "expected": expected,
                "results": results,
                "wrong_names": wrong_names,
                "universal": universal,
            }
            if expected is False:
                # expected=invalid: at least one validator accepted
                # (otherwise all_agree && matches_expected would have
                # been true and we'd be in `clean`).
                accepts_invalid.append(record)
            else:
                rejects_valid.append(record)

        # Outlier tracking: separate from the expected/inter buckets,
        # independent of metadata.expected. We need at least three
        # validators to have a meaningful "1 vs rest" notion. Use the
        # original `results` (not `adjusted`), so a Go abstention shows
        # up as an outlier rather than being silently rewritten.
        if len(results) >= 3:
            valid_names = [n for n, ok, _ in results if ok]
            invalid_names = [n for n, ok, _ in results if not ok]
            if len(valid_names) == 1 and len(invalid_names) >= 2:
                outliers.setdefault((valid_names[0], "alone in accepting"), []).append(label)
            elif len(invalid_names) == 1 and len(valid_names) >= 2:
                outliers.setdefault((invalid_names[0], "alone in rejecting"), []).append(label)

    print()
    enabled = [name for name, use in (
        ("openssl", use_openssl),
        ("libressl", use_libressl),
        ("boringssl", use_boringssl),
        ("awslc", use_awslc),
        ("botan", use_botan),
        ("gnutls", use_gnutls),
        ("go", use_go),
        ("rust", use_rust),
        ("dotnet", use_dotnet),
        ("java", use_java),
        ("pyca", use_pyca),
        ("wolfssl", use_wolfssl),
    ) if use]
    abstain_note = (
        f" (incl. {go_abstained} where Go abstained with `unhandled critical extension`)"
        if go_abstained
        else ""
    )

    def _count_universal(records: list[dict]) -> int:
        return sum(1 for r in records if r["universal"])

    accepts_universal = _count_universal(accepts_invalid)
    rejects_universal = _count_universal(rejects_valid)
    print(
        f"Tested {len(cases)} chains with {len(enabled)} validators\n"
        f"{len(accepts_invalid)} accepts-invalid ({accepts_universal} universal)\n"
        f"{len(rejects_valid)} rejects-valid ({rejects_universal} universal)\n"
    )

    # Per-validator wrong-direction tallies. A validator contributes to
    # the accepts-invalid column whenever it accepted a chain whose
    # testcase expected=invalid, and to the rejects-valid column whenever
    # it rejected a chain whose testcase expected=valid. This is the
    # bug-counts-per-implementation view the per-chain detail below
    # doesn't summarise.
    per_validator_ai = {name: 0 for name in enabled}
    per_validator_rv = {name: 0 for name in enabled}
    for r in accepts_invalid:
        for name, ok, _ in r["results"]:
            if ok:  # expected=invalid && validator said accept
                per_validator_ai[name] += 1
    for r in rejects_valid:
        for name, ok, _ in r["results"]:
            if not ok:  # expected=valid && validator said reject
                per_validator_rv[name] += 1
    name_w = max(len(n) for n in enabled)
    ai_w = max(len(str(per_validator_ai[n])) for n in enabled)
    rv_w = max(len(str(per_validator_rv[n])) for n in enabled)
    print()
    print("Per-validator wrong-direction tallies:")
    for name in enabled:
        print(
            f"  {name:<{name_w}}  "
            f"{per_validator_ai[name]:>{ai_w}} accepts-invalid, "
            f"{per_validator_rv[name]:>{rv_w}} rejects-valid"
        )

    def print_record(d: dict) -> None:
        v_exp = "accept" if d["expected"] else "reject"
        universal_tag = " [universal]" if d["universal"] else ""
        print(f"  - {d['label']}{universal_tag}")

        differing = [(n, ok, out) for n, ok, out in d["results"] if ok != d["expected"]]

        # Verbose mode keeps the full per-validator listing (canonical
        # order) so a reader can see who agreed and what each said.
        if args.verbose:
            for name, ok, out in d["results"]:
                v = "accept" if ok else "reject"
                tag = (" (matches expected)" if ok == d["expected"]
                       else " (differs from expected)")
                tail = "" if ok else f" ({out})"
                print(f"      {name:<8}: {v}{tag}{tail}")
            print(f"      {'expected':<8}: {v_exp}")
            return

        # Default mode: collapse the wrong-direction validators. Within a
        # bucket they're homogeneous (accepts-invalid records have only
        # accepting outliers, rejects-valid only rejecting ones), but both
        # are handled for safety. Acceptances carry no useful per-validator
        # message (the verdict word is all the information), so list them on
        # a single name-sorted line; rejections keep their reason, one per
        # line, sorted by name.
        accepting = sorted(n for n, ok, _ in differing if ok)
        rejecting = sorted((n, out) for n, ok, out in differing if not ok)
        if accepting:
            print(f"      Validators accepting: {', '.join(accepting)}")
        for name, out in rejecting:
            print(f"      {name}: reject ({out})")

    # Sort each bucket so universal cases come first within the bucket
    # (likely-wrong-expected or universal-bug class), then partial ones
    # alphabetically. Within each subgroup the order is alphabetic for
    # stable diff-able reports.
    def _sort_key(r: dict) -> tuple[int, str]:
        return (0 if r["universal"] else 1, r["label"])

    if accepts_invalid:
        print()
        print(
            f"Accepts-invalid ({len(accepts_invalid)} chains where the testcase "
            f"expected=invalid but at least one validator accepted; "
            f"{accepts_universal} were accepted by every validator):"
        )
        for d in sorted(accepts_invalid, key=_sort_key):
            print_record(d)

    if rejects_valid:
        print()
        print(
            f"Rejects-valid ({len(rejects_valid)} chains where the testcase "
            f"expected=valid but at least one validator rejected; "
            f"{rejects_universal} were rejected by every validator):"
        )
        for d in sorted(rejects_valid, key=_sort_key):
            print_record(d)

    if outliers:
        total_outliers = sum(len(v) for v in outliers.values())
        print()
        print(
            f"Single-validator outliers ({total_outliers} chains where one "
            "validator disagreed with all the others, regardless of metadata.expected):"
        )
        for (name, direction), labels in sorted(outliers.items()):
            print(f"  {name} {direction} ({len(labels)} cases):")
            for lbl in sorted(labels):
                print(f"    - {lbl}")

    return 1 if (accepts_invalid or rejects_valid) else 0


if __name__ == "__main__":
    sys.exit(main())
