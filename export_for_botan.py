#!/usr/bin/env python3
"""Repackage generated chains for Botan's name-constraint corpus tests.

Input:  an output directory produced by generate_nc_chains.py
        (one subdir per testcase with chain.pem + metadata.json,
         plus a shared trust-anchor.pem).

Output: a flat directory containing
        - root.pem                  (copy of trust-anchor.pem)
        - <testcase>.pem            (copy of <testcase>/chain.pem)
        - expected.txt              (lines of "<testcase>:<botan-result>")

The mapping from metadata.expected to Botan's result string is a best-effort
translation of the abstract verdict to the Botan error string the corpus
test expects. Inspect expected.txt and adjust by hand for any case where the
heuristic guesses wrong.
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

VERIFIED = "Verified"
NC_VIOLATION = "Certificate does not pass name constraint"
ENCODING_ERROR = "Certificate extension encoding error"
UNKNOWN_CRIT = "Unknown critical extension encountered"
ISSUER_NOT_FOUND = "Certificate issuer not found"
NON_CA_ISSUER = "CA certificate not allowed to issue certs"
IP_BLOCKS_INVALID = "IP Address Blocks extension invalid"
FAILED_TO_DECODE = "Certificate failed to decode"

# Name-pattern overrides — checked before the expected-field mapping.
# Order matters: first matching substring wins.
NAME_OVERRIDES = [
    # Structurally malformed cert/extension contents.
    ("issuer-name-mismatch", ISSUER_NOT_FOUND),
    ("non-ca-issuer", NON_CA_ISSUER),
    ("unknown-critical-extension", UNKNOWN_CRIT),
    ("malformed-policy-constraints", UNKNOWN_CRIT),
    ("rfc3779-ipaddrblocks-malformed", IP_BLOCKS_INVALID),

    # Inputs that are rejected at parse time before even reaching validation
    ("critical-aia-intermediate", ENCODING_ERROR),
    ("dn-empty-permitted-subtree-valid", ENCODING_ERROR),
    ("dn-printablestring-tag-with-non-printable-chars-invalid", FAILED_TO_DECODE),
    ("dns-constraint-trailing-dot-invalid", ENCODING_ERROR),
    ("dns-constraint-with-underscore-invalid", ENCODING_ERROR),
    ("dns-constraint-with-wildcard-invalid", ENCODING_ERROR),
    ("dns-double-dot-san", ENCODING_ERROR),
    ("dns-empty-permitted-subtree", ENCODING_ERROR),
    ("dns-empty-san", ENCODING_ERROR),
    ("dns-leading-empty-label", ENCODING_ERROR),
    ("dns-non-ascii-raw-san", ENCODING_ERROR),
    ("dns-san-embedded-nul-evades-constraint-invalid", ENCODING_ERROR),
    ("dns-space-san", ENCODING_ERROR),
    ("email-constraint-leading-at-invalid", ENCODING_ERROR),
    ("email-constraint-mailbox-with-leading-dot-host-invalid", ENCODING_ERROR),
    ("email-embedded-nul", ENCODING_ERROR),
    ("email-multiple-at-raw-san", ENCODING_ERROR),
    ("email-pkcs9-dn-embedded-nul-evades-constraint-invalid", FAILED_TO_DECODE),
    ("email-quoted-localpart-not-equal-invalid", ENCODING_ERROR),
    ("email-san-no-at-invalid", ENCODING_ERROR),
    ("empty-dns-excluded-rejects-everything-invalid", ENCODING_ERROR),
    ("empty-dns-permitted-allows-anything-valid", ENCODING_ERROR),
    ("empty-email-excluded-rejects-everything-invalid", ENCODING_ERROR),
    ("empty-email-permitted-allows-anything-invalid", ENCODING_ERROR),
    ("empty-name-constraints-extension", ENCODING_ERROR),
    ("empty-san-sequence-invalid", ENCODING_ERROR),
    ("empty-uri-excluded-rejects-everything-invalid", ENCODING_ERROR),
    ("empty-uri-permitted-allows-anything-invalid", ENCODING_ERROR),
    ("general-name-context-class-mismatch", ENCODING_ERROR),
    ("general-name-empty-context-tag", ENCODING_ERROR),
    ("general-subtree-with-extra-fields", ENCODING_ERROR),
    ("ip-san-wrong-length", ENCODING_ERROR),
    ("name-constraints-both-empty-invalid", ENCODING_ERROR),
    ("name-constraints-minimum-nonzero-invalid", ENCODING_ERROR),
    ("policy-invalid-leaf-extension", ENCODING_ERROR),
    ("rfc3779-asidentifiers-malformed", ENCODING_ERROR),
    ("smtp-utf8-ulabel-domain-permit-valid", ENCODING_ERROR),
    ("smtputf8-ulabel-domain-permit-valid", ENCODING_ERROR),
    ("uri-constraint-not-fqdn", ENCODING_ERROR),
    ("uri-constraint-with-port-invalid", ENCODING_ERROR),
    ("uri-double-trailing-dot-san-invalid", ENCODING_ERROR),
    ("uri-excluded-no-authority", ENCODING_ERROR),
    ("uri-ipv6-zone-host", ENCODING_ERROR),
    ("uri-no-authority", ENCODING_ERROR),
    ("uri-non-numeric-port-invalid", ENCODING_ERROR),
    ("uri-relative-san", ENCODING_ERROR),
    ("wildcard-middle-label-san-invalid", ENCODING_ERROR),
    ("wildcard-multi-label-san-invalid", ENCODING_ERROR),
]


def map_expected(name: str, expected: str) -> str:
    for fragment, result in NAME_OVERRIDES:
        if fragment in name:
            return result
    if expected.startswith("valid"):
        return VERIFIED
    # Everything else — invalid*, reject*, reject-or-process-* — maps to the
    # generic name-constraint violation string by default.
    return NC_VIOLATION


def export(src: Path, dst: Path, force: bool) -> int:
    if not src.is_dir():
        sys.exit(f"source directory not found: {src}")

    root_src = src / "trust-anchor.pem"
    if not root_src.is_file():
        sys.exit(f"missing trust anchor: {root_src}")

    if dst.exists():
        if not force:
            sys.exit(f"destination exists (use --force): {dst}")
        if not dst.is_dir():
            sys.exit(f"destination exists and is not a directory: {dst}")
    else:
        dst.mkdir(parents=True)

    shutil.copyfile(root_src, dst / "root.pem")

    entries: list[tuple[str, str]] = []
    skipped: list[str] = []

    for case_dir in sorted(p for p in src.iterdir() if p.is_dir()):
        meta_path = case_dir / "metadata.json"
        chain_path = case_dir / "chain.pem"
        if not meta_path.is_file() or not chain_path.is_file():
            skipped.append(case_dir.name)
            continue
        meta = json.loads(meta_path.read_text())
        name = meta.get("name", case_dir.name)
        expected = meta.get("expected", "")
        shutil.copyfile(chain_path, dst / f"{name}.pem")
        entries.append((name, map_expected(name, expected)))

    entries.sort()
    with (dst / "expected.txt").open("w") as fh:
        for name, result in entries:
            fh.write(f"{name}:{result}\n")

    print(f"wrote {len(entries)} chains to {dst}")
    if skipped:
        print(f"skipped (missing metadata.json or chain.pem): {len(skipped)}",
              file=sys.stderr)
        for n in skipped:
            print(f"  {n}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", type=Path,
                    help="input directory (output of generate_nc_chains.py)")
    ap.add_argument("dest", type=Path,
                    help="output directory to populate")
    ap.add_argument("--force", action="store_true",
                    help="reuse existing destination directory")
    args = ap.parse_args()
    return export(args.source, args.dest, args.force)


if __name__ == "__main__":
    sys.exit(main())
