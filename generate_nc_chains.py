#!/usr/bin/env python3
"""Generate X.509 certificate chains from a name-constraints DSL.

Each input JSON file is one test case containing an ordered ``certs`` array.
Certificates may reference earlier certificates in the same chain by ``issuer``.
The script writes PEM keys, certificates, and bundle files under one output
directory per test case.

Example:

    python generate_nc_chains.py examples/name_constraints --out out --force

The DSL intentionally stays close to RFC 5280 names:

    {
      "name": "dns-permitted-valid",
      "expected": "valid",
      "certs": [
        {"id": "root", "ca": true, "self_signed": true,
         "subject": "CN=Test Root,O=NC Tests,C=US"},
        {"id": "int", "ca": true, "issuer": "root",
         "subject": "CN=Constrained CA,O=NC Tests,C=US",
         "name_constraints": {"critical": true,
           "permitted": {"dns": ["example.com"]}}},
        {"id": "leaf", "issuer": "int", "subject": "",
         "san": {"dns": ["www.example.com"]}}
      ]
    }

Supported name forms in SANs and constraints are ``dns``, ``email``/``rfc822``,
``uri``, ``ip``, ``directory_name``/``dir``, ``registered_id``, and
``other_name``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import (
    ExtendedKeyUsageOID,
    NameOID,
    ObjectIdentifier,
)


DEFAULT_START_DATE = "2026-01-01"
DEFAULT_DURATION_DAYS = 3650
DEFAULT_RSA_BITS = 2048
DEFAULT_HASH = "sha256"

NAME_OIDS = {
    "c": NameOID.COUNTRY_NAME,
    "country": NameOID.COUNTRY_NAME,
    "st": NameOID.STATE_OR_PROVINCE_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "l": NameOID.LOCALITY_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "o": NameOID.ORGANIZATION_NAME,
    "org": NameOID.ORGANIZATION_NAME,
    "organization": NameOID.ORGANIZATION_NAME,
    "ou": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "cn": NameOID.COMMON_NAME,
    "common_name": NameOID.COMMON_NAME,
    "email": NameOID.EMAIL_ADDRESS,
    "email_address": NameOID.EMAIL_ADDRESS,
    "serial": NameOID.SERIAL_NUMBER,
    "serial_number": NameOID.SERIAL_NUMBER,
    "dc": NameOID.DOMAIN_COMPONENT,
    "domain_component": NameOID.DOMAIN_COMPONENT,
    "uid": NameOID.USER_ID,
    "user_id": NameOID.USER_ID,
    "title": NameOID.TITLE,
    "gn": NameOID.GIVEN_NAME,
    "given_name": NameOID.GIVEN_NAME,
    "sn": NameOID.SURNAME,
    "surname": NameOID.SURNAME,
}

# Maps DSL string-encoding names to ASN.1 string types for the encoded
# attribute value. Lets a test pin an attribute to e.g. PrintableString
# or BMPString instead of cryptography's default UTF8String.
STRING_TYPES = {
    "utf8": _ASN1Type.UTF8String,
    "utf8_string": _ASN1Type.UTF8String,
    "printable": _ASN1Type.PrintableString,
    "printable_string": _ASN1Type.PrintableString,
    "ia5": _ASN1Type.IA5String,
    "ia5_string": _ASN1Type.IA5String,
    "bmp": _ASN1Type.BMPString,
    "bmp_string": _ASN1Type.BMPString,
    "universal": _ASN1Type.UniversalString,
    "universal_string": _ASN1Type.UniversalString,
    "t61": _ASN1Type.T61String,
    "t61_string": _ASN1Type.T61String,
    "teletex": _ASN1Type.T61String,
    "teletex_string": _ASN1Type.T61String,
    "numeric": _ASN1Type.NumericString,
    "numeric_string": _ASN1Type.NumericString,
    "visible": _ASN1Type.VisibleString,
    "visible_string": _ASN1Type.VisibleString,
}

EKU_OIDS = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
}


class DslError(ValueError):
    """Raised when the DSL is malformed."""


@dataclass(frozen=True)
class GeneratedCert:
    cert_id: str
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    cert: x509.Certificate
    is_ca: bool
    # Raw DER override. Set when a spec uses subject_der_* (or other future
    # escape hatches) to produce bytes cryptography cannot round-trip via
    # load_der_x509_certificate (e.g. SETs in non-canonical DER order). The
    # `cert` field is still the pre-rewrite x509.Certificate to keep the
    # subject/issuer/public-key accessors working for child certs; on-disk
    # output is taken from raw_der when it is set.
    raw_der: bytes | None = None
    # The raw subject Name TLV when subject_der_* rewrote it. A child issued by
    # this cert inherits these bytes as its issuer field so the chain links
    # byte-for-byte (cryptography would otherwise re-canonicalize the parsed
    # Name and the issuer/subject DER could diverge). None when the subject is
    # whatever cryptography emitted, in which case the parsed Name already
    # round-trips identically.
    raw_subject: bytes | None = None

    def cert_bytes(self, encoding: serialization.Encoding) -> bytes:
        if self.raw_der is None:
            return self.cert.public_bytes(encoding)
        if encoding is serialization.Encoding.DER:
            return self.raw_der
        if encoding is serialization.Encoding.PEM:
            return _der_to_pem(self.raw_der, "CERTIFICATE")
        raise DslError(f"unsupported encoding for raw-DER override: {encoding}")


def _der_to_pem(der: bytes, label: str) -> bytes:
    import base64
    b64 = base64.b64encode(der).decode("ascii")
    lines = [f"-----BEGIN {label}-----"]
    lines += [b64[i:i + 64] for i in range(0, len(b64), 64)]
    lines.append(f"-----END {label}-----")
    return ("\n".join(lines) + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate certificate chains from a JSON name-constraints DSL.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output per chain:
  NN-id.key.pem       private key for each generated certificate
  NN-id.cert.pem      certificate for each generated certificate
  chain.pem           leaf first, then intermediates, excluding trust anchor
  trust-anchor.pem    shared root/trust-anchor certificate
  all.pem             certificates in generation order
  metadata.json       copied chain metadata and generated file names

Output at --out:
  trust-anchor.pem     shared root/trust-anchor certificate for all cases
  trust-anchor.key.pem shared root/trust-anchor private key
""".strip(),
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="JSON test case files or directories containing *.json test cases",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("out"),
        help="Output directory (default: out)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing per-chain output directories",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="CHAIN",
        help="Generate only the named chain; may be repeated",
    )
    parser.add_argument(
        "--start-date",
        type=parse_start_date,
        default=parse_start_date(DEFAULT_START_DATE),
        metavar="YYYY-MM-DD",
        help=f"Default notBefore for generated certs in UTC (default: {DEFAULT_START_DATE}). "
             "Per-cert `not_before` overrides this for that certificate.",
    )
    parser.add_argument(
        "--duration",
        type=positive_int,
        default=DEFAULT_DURATION_DAYS,
        metavar="DAYS",
        help=f"Default certificate lifetime in days (default: {DEFAULT_DURATION_DAYS}). "
             "Per-cert `days` or `not_after` overrides this for that certificate.",
    )
    parser.add_argument(
        "--key-type",
        choices=("ecdsa", "rsa"),
        default="ecdsa",
        help="Default key type (default: ecdsa)",
    )
    parser.add_argument(
        "--rsa-bits",
        type=positive_int,
        default=DEFAULT_RSA_BITS,
        help=f"Default RSA key size in bits (default: {DEFAULT_RSA_BITS})",
    )
    parser.add_argument(
        "--curve",
        default="secp256r1",
        help="Default EC curve when --key-type is ec/ecdsa (default: secp256r1)",
    )
    parser.add_argument(
        "--hash",
        choices=("sha256", "sha384", "sha512"),
        default=DEFAULT_HASH,
        help=f"Certificate signature hash (default: {DEFAULT_HASH})",
    )

    args = parser.parse_args()

    try:
        defaults = {
            "start_date": args.start_date,
            "duration_days": args.duration,
            "key_type": args.key_type,
            "rsa_bits": args.rsa_bits,
            "curve": args.curve,
            "hash": args.hash,
        }
        generated = generate_cases(
            discover_case_files(args.inputs),
            defaults,
            args.out,
            args.force,
            set(args.only),
        )
    except (DslError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for chain_name, output_dir in generated:
        print(f"generated {chain_name}: {output_dir}")
    return 0


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        document = json.load(f)
    if not isinstance(document, dict):
        raise DslError("top-level DSL value must be a JSON object")
    return document


def discover_case_files(inputs: list[Path]) -> list[Path]:
    files: list[Path] = []
    for input_path in inputs:
        if input_path.is_dir():
            found = sorted(path for path in input_path.rglob("*.json") if path.is_file())
            if not found:
                raise DslError(f"no JSON test cases found under directory: {input_path}")
            files.extend(found)
            continue
        if input_path.is_file():
            files.append(input_path)
            continue
        raise DslError(f"input path does not exist or is not a file/directory: {input_path}")
    return files


def generate_cases(
    case_files: list[Path],
    defaults: dict[str, Any],
    out_dir: Path,
    force: bool,
    only: set[str],
) -> list[tuple[str, Path]]:
    out_dir.mkdir(parents=True, exist_ok=True)

    selected_cases: list[tuple[str, dict[str, Any]]] = []
    seen_names: set[str] = set()
    for case_file in case_files:
        chain_obj = load_json(case_file)
        if "chains" in chain_obj or "defaults" in chain_obj:
            raise DslError(
                f"{case_file}: each JSON file must be a single test case object; "
                "pass defaults such as --start-date, --duration, --key-type, and "
                "--rsa-bits on the command line"
            )

        chain_name = require_string(chain_obj.get("name"), f"{case_file}.name")
        if chain_name in seen_names:
            raise DslError(f"duplicate chain name: {chain_name}")
        seen_names.add(chain_name)
        if only and chain_name not in only:
            continue

        selected_cases.append((chain_name, chain_obj))

    if only:
        missing = only.difference(seen_names)
        if missing:
            raise DslError("unknown chain(s) requested with --only: " + ", ".join(sorted(missing)))

    if not selected_cases:
        return []

    shared_trust_anchor = build_shared_trust_anchor(selected_cases[0][1], defaults)
    write_pem_certificate(out_dir / "trust-anchor.pem", shared_trust_anchor.cert)
    write_pem_private_key(out_dir / "trust-anchor.key.pem", shared_trust_anchor.key)

    generated: list[tuple[str, Path]] = []
    for chain_name, chain_obj in selected_cases:
        chain_dir = out_dir / safe_filename(chain_name)
        generate_chain(chain_obj, defaults, chain_dir, force, shared_trust_anchor)
        generated.append((chain_name, chain_dir))
    return generated


def build_shared_trust_anchor(chain: dict[str, Any], defaults: dict[str, Any]) -> GeneratedCert:
    cert_specs = chain.get("certs")
    if not isinstance(cert_specs, list) or not cert_specs:
        raise DslError(f"chain {chain['name']!r} must contain a non-empty 'certs' array")
    root_spec = require_object(cert_specs[0], f"{chain['name']}.certs[0]")
    validate_trust_anchor_spec(root_spec, chain["name"], None)
    return build_certificate(root_spec, defaults, {}, 0, chain["name"])


def generate_chain(
    chain: dict[str, Any],
    defaults: dict[str, Any],
    chain_dir: Path,
    force: bool,
    shared_trust_anchor: GeneratedCert,
) -> None:
    cert_specs = chain.get("certs")
    if not isinstance(cert_specs, list) or not cert_specs:
        raise DslError(f"chain {chain['name']!r} must contain a non-empty 'certs' array")

    if chain_dir.exists():
        if not force:
            raise DslError(f"output directory already exists: {chain_dir} (use --force)")
        shutil.rmtree(chain_dir)
    chain_dir.mkdir(parents=True)

    generated_by_id: dict[str, GeneratedCert] = {}
    generated_in_order: list[GeneratedCert] = []
    files: list[dict[str, str]] = []

    for index, raw_spec in enumerate(cert_specs):
        spec = require_object(raw_spec, f"{chain['name']}.certs[{index}]")
        cert_id = require_string(spec.get("id"), f"{chain['name']}.certs[{index}].id")
        if cert_id in generated_by_id:
            raise DslError(f"duplicate certificate id in chain {chain['name']!r}: {cert_id}")

        if index == 0:
            validate_trust_anchor_spec(spec, chain["name"], shared_trust_anchor.cert.subject)
            generated_cert = GeneratedCert(
                cert_id=cert_id,
                key=shared_trust_anchor.key,
                cert=shared_trust_anchor.cert,
                is_ca=shared_trust_anchor.is_ca,
            )
        else:
            generated_cert = build_certificate(spec, defaults, generated_by_id, index, chain["name"])
        generated_by_id[cert_id] = generated_cert
        generated_in_order.append(generated_cert)

        prefix = f"{index:02d}-{safe_filename(cert_id)}"
        key_file = f"{prefix}.key.pem"
        cert_file = f"{prefix}.cert.pem"
        write_pem_private_key(chain_dir / key_file, generated_cert.key)
        (chain_dir / cert_file).write_bytes(generated_cert.cert_bytes(serialization.Encoding.PEM))
        files.append({"id": cert_id, "key": key_file, "cert": cert_file})

    write_bundle(chain_dir / "all.pem", generated_in_order)
    write_chain_bundle(chain_dir / "chain.pem", generated_in_order)
    write_trust_anchor(chain_dir / "trust-anchor.pem", generated_in_order)
    write_metadata(chain_dir / "metadata.json", chain, files)


def validate_trust_anchor_spec(
    spec: dict[str, Any],
    chain_name: str,
    shared_subject: x509.Name | None,
) -> None:
    cert_id = require_string(spec.get("id"), f"{chain_name}.certs[0].id")
    is_ca = bool(spec.get("ca", spec.get("is_ca", False)))
    if not is_ca:
        raise DslError(f"{chain_name}: first certificate {cert_id!r} must be a CA trust-anchor placeholder")

    issuer_ref = spec.get("issuer")
    self_signed = bool(spec.get("self_signed", False)) or issuer_ref in (None, "self")
    if not self_signed:
        raise DslError(f"{chain_name}: first certificate {cert_id!r} must be self-signed")

    subject = parse_name(spec.get("subject", {"cn": cert_id}), f"{chain_name}.certs[0].subject")
    if shared_subject is not None and subject != shared_subject:
        raise DslError(
            f"{chain_name}: first certificate subject must match the shared trust-anchor subject "
            "when generating multiple cases in one run"
        )


def build_certificate(
    spec: dict[str, Any],
    defaults: dict[str, Any],
    generated_by_id: dict[str, GeneratedCert],
    index: int,
    chain_name: str,
) -> GeneratedCert:
    cert_id = require_string(spec.get("id"), "cert.id")
    is_ca = bool(spec.get("ca", spec.get("is_ca", False)))
    subject = parse_name(spec.get("subject", {"cn": cert_id}), f"{cert_id}.subject")
    key = generate_key(spec.get("key"), defaults, chain_name, cert_id)

    issuer_ref = spec.get("issuer")
    self_signed = bool(spec.get("self_signed", False)) or issuer_ref in (None, "self")
    if index > 0 and issuer_ref is None and not spec.get("self_signed", False):
        raise DslError(f"{cert_id}: non-root certificates must specify 'issuer'")

    if self_signed:
        issuer_name = subject
        issuer_key = key
        issuer_cert = None
    else:
        if not isinstance(issuer_ref, str):
            raise DslError(f"{cert_id}.issuer must be a certificate id string")
        issuer_cert = generated_by_id.get(issuer_ref)
        if issuer_cert is None:
            raise DslError(f"{cert_id}: issuer {issuer_ref!r} has not been generated earlier")
        if not issuer_cert.is_ca and not spec.get("allow_non_ca_issuer", False):
            raise DslError(f"{cert_id}: issuer {issuer_ref!r} is not a CA")
        if "issuer_subject" in spec:
            issuer_name = parse_name(spec["issuer_subject"], f"{cert_id}.issuer_subject")
        else:
            issuer_name = issuer_cert.cert.subject
        issuer_key = issuer_cert.key

    not_before, not_after = validity_window(spec, defaults)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(serial_number(spec, chain_name, cert_id))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    path_len = spec.get("path_len", spec.get("path_length"))
    if path_len is not None and not isinstance(path_len, int):
        raise DslError(f"{cert_id}.path_len must be an integer or null")
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_len if is_ca else None),
        critical=True,
    )
    builder = builder.add_extension(default_key_usage(is_ca), critical=True)

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.key.public_key()),
            critical=False,
        )

    san = parse_general_names(spec.get("san", spec.get("subject_alt_name")), f"{cert_id}.san")
    if san:
        san_critical = spec.get("san_critical")
        if san_critical is None:
            san_critical = len(subject) == 0
        if _names_have_raw(san):
            san_ext: x509.ExtensionType = x509.UnrecognizedExtension(
                ObjectIdentifier("2.5.29.17"), _assemble_general_names_der(san)
            )
        else:
            san_ext = x509.SubjectAlternativeName(san)
        builder = builder.add_extension(san_ext, critical=bool(san_critical))
    elif len(subject) == 0:
        raise DslError(f"{cert_id}: empty subject requires at least one SAN")

    name_constraints = spec.get("name_constraints")
    if name_constraints is not None:
        if not is_ca:
            raise DslError(f"{cert_id}: RFC 5280 permits nameConstraints only in CA certificates")
        nc = parse_name_constraints(name_constraints, cert_id)
        builder = builder.add_extension(nc[0], critical=nc[1])

    eku_names = spec.get("eku", spec.get("extended_key_usage"))
    if eku_names is None and not is_ca and spec.get("default_server_eku", True):
        eku_names = ["server_auth"]
    if eku_names:
        builder = builder.add_extension(parse_eku(eku_names, cert_id), critical=False)

    for extension in parse_unknown_extensions(spec.get("unknown_extensions"), cert_id):
        builder = builder.add_extension(extension[0], critical=extension[1])

    hash_algo = parse_hash(defaults.get("hash", DEFAULT_HASH))
    sign_kwargs: dict[str, Any] = {
        "private_key": issuer_key,
        "algorithm": hash_algo,
    }
    if isinstance(issuer_key, ec.EllipticCurvePrivateKey):
        # RFC 6979 deterministic ECDSA: makes the signature reproducible
        # for a given (key, message). Exposed by python-cryptography 44+.
        sign_kwargs["ecdsa_deterministic"] = True
    cert = builder.sign(**sign_kwargs)

    # Escape hatches that operate below the level cryptography will emit. They
    # rewrite the TBSCertificate after signing and re-sign the result:
    #   * subject_der_* replaces the subject SEQUENCE (non-canonical SET
    #     orderings of multi-AVA RDNs, exotic string types, etc).
    #   * issuer_der_* replaces the issuer SEQUENCE, independently of the
    #     subject — lets a chain encode a deliberate issuer/subject DN mismatch
    #     or an exotic issuer encoding (PrintableString vs UTF8String, etc).
    #   * raw_extensions splices extra Extension TLVs into the [3] extensions
    #     SEQUENCE OF without going through cryptography's add_extension, which
    #     dedups by OID — so it can emit duplicate / out-of-spec extensions
    #     (two nameConstraints, two SAN, a second basicConstraints, ...).
    # We keep the original cert object for downstream lookups (issuer subject,
    # public key, etc.) but write the rewritten DER to disk via raw_der.
    raw_subject = _parse_raw_subject(spec, cert_id)
    raw_ext_blobs = _parse_raw_extensions(spec, cert_id)
    raw_issuer = _parse_raw_issuer(spec, cert_id)
    if raw_issuer is not None and "issuer_subject" in spec:
        raise DslError(
            f"{cert_id}: specify either issuer_der_* or issuer_subject, not both"
        )
    # Inherit a raw-rewritten parent subject as this cert's issuer so the chain
    # links byte-for-byte. Skip when the issuer DN was explicitly chosen via
    # issuer_subject/issuer_der_* (the test wants a specific issuer encoding).
    if (
        raw_issuer is None
        and "issuer_subject" not in spec
        and issuer_cert is not None
        and issuer_cert.raw_subject is not None
    ):
        raw_issuer = issuer_cert.raw_subject

    raw_der: bytes | None = None
    if raw_subject is not None or raw_issuer is not None or raw_ext_blobs:
        raw_der = _rewrite_tbs_and_resign(
            cert, raw_subject, raw_issuer, raw_ext_blobs, issuer_key, hash_algo, cert_id
        )

    return GeneratedCert(
        cert_id=cert_id, key=key, cert=cert, is_ca=is_ca,
        raw_der=raw_der, raw_subject=raw_subject,
    )


def _parse_raw_subject(spec: dict[str, Any], cert_id: str) -> bytes | None:
    has_hex = "subject_der_hex" in spec
    has_ascii = "subject_der_ascii2der" in spec
    if not (has_hex or has_ascii):
        return None
    if has_hex and has_ascii:
        raise DslError(
            f"{cert_id}: specify either subject_der_hex or subject_der_ascii2der, not both"
        )
    if has_hex:
        text = require_string(spec["subject_der_hex"], f"{cert_id}.subject_der_hex")
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise DslError(f"{cert_id}.subject_der_hex is not valid hex") from exc
    return run_ascii2der(
        require_string(spec["subject_der_ascii2der"], f"{cert_id}.subject_der_ascii2der"),
        f"{cert_id}.subject_der_ascii2der",
    )


def _parse_raw_issuer(spec: dict[str, Any], cert_id: str) -> bytes | None:
    """Raw DER for the issuer Name TLV, from issuer_der_hex / issuer_der_ascii2der."""
    has_hex = "issuer_der_hex" in spec
    has_ascii = "issuer_der_ascii2der" in spec
    if not (has_hex or has_ascii):
        return None
    if has_hex and has_ascii:
        raise DslError(
            f"{cert_id}: specify either issuer_der_hex or issuer_der_ascii2der, not both"
        )
    if has_hex:
        text = require_string(spec["issuer_der_hex"], f"{cert_id}.issuer_der_hex")
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise DslError(f"{cert_id}.issuer_der_hex is not valid hex") from exc
    return run_ascii2der(
        require_string(spec["issuer_der_ascii2der"], f"{cert_id}.issuer_der_ascii2der"),
        f"{cert_id}.issuer_der_ascii2der",
    )


def _parse_raw_extensions(spec: dict[str, Any], cert_id: str) -> list[bytes]:
    """Parse the `raw_extensions` hatch into a list of Extension TLV byte blobs.

    Each entry is one of:
      * ``{"oid": "...", "critical": bool, "value_hex"|"value_ascii2der": ...}``
        — the generator assembles a well-formed Extension SEQUENCE { extnID,
        [critical], extnValue OCTET STRING } from the parts. ``value_*`` is the
        inner extension value, exactly as for ``unknown_extensions`` (it is
        wrapped in the OCTET STRING for you).
      * ``{"der_hex"|"der_ascii2der": ...}`` — a verbatim blob appended into the
        extensions SEQUENCE OF as-is. Normally a complete Extension TLV, but the
        bytes are not validated, so malformed shapes can be emitted too.

    Unlike ``unknown_extensions`` these never pass through cryptography's
    add_extension, so they may duplicate an OID already present (or each other),
    which is exactly what makes duplicate-extension differentials expressible.
    """
    value = spec.get("raw_extensions")
    if value is None:
        return []
    blobs: list[bytes] = []
    for index, item in enumerate(listify(value, f"{cert_id}.raw_extensions")):
        loc = f"{cert_id}.raw_extensions[{index}]"
        obj = require_object(item, loc)
        has_verbatim = "der_hex" in obj or "der_ascii2der" in obj
        has_structured = "oid" in obj
        if has_verbatim and has_structured:
            raise DslError(
                f"{loc}: specify either a verbatim der_* extension or an "
                "oid+value_* extension, not both"
            )
        if has_verbatim:
            blobs.append(_parse_verbatim_der(obj, loc))
        elif has_structured:
            blobs.append(_assemble_extension(obj, loc))
        else:
            raise DslError(
                f"{loc} must contain 'oid' (with value_hex/value_ascii2der) "
                "or a verbatim 'der_hex'/'der_ascii2der'"
            )
    return blobs


def _parse_verbatim_der(obj: dict[str, Any], loc: str) -> bytes:
    has_hex = "der_hex" in obj
    has_ascii = "der_ascii2der" in obj
    if has_hex and has_ascii:
        raise DslError(f"{loc}: specify either der_hex or der_ascii2der, not both")
    if has_hex:
        text = require_string(obj["der_hex"], f"{loc}.der_hex")
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise DslError(f"{loc}.der_hex is not valid hex") from exc
    return run_ascii2der(require_string(obj["der_ascii2der"], f"{loc}.der_ascii2der"), loc)


def _assemble_extension(obj: dict[str, Any], loc: str) -> bytes:
    """Build a DER Extension TLV from oid + critical + value_* parts."""
    oid_der = _encode_oid_der(require_string(obj["oid"], f"{loc}.oid"), f"{loc}.oid")
    extn_value = parse_der_value(obj, loc)
    body = oid_der
    if bool(obj.get("critical", False)):
        body += b"\x01\x01\xff"  # critical BOOLEAN TRUE (DEFAULT FALSE is omitted)
    body += der_string(0x04, extn_value)  # extnValue OCTET STRING
    return der_string(0x30, body)


def _encode_oid_der(dotted: str, loc: str) -> bytes:
    """Encode a dotted OID string into its full DER TLV (tag 0x06)."""
    text = dotted.strip()
    if not re.fullmatch(r"\d+(?:\.\d+)+", text):
        raise DslError(f"{loc}: invalid OID {dotted!r}")
    arcs = [int(p) for p in text.split(".")]
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise DslError(f"{loc}: invalid OID {dotted!r}")
    body = _base128(40 * arcs[0] + arcs[1])
    for arc in arcs[2:]:
        body += _base128(arc)
    return der_string(0x06, body)


def _base128(value: int) -> bytes:
    """Base-128 (7-bit) big-endian encoding of an OID subidentifier."""
    if value == 0:
        return b"\x00"
    septets = []
    while value > 0:
        septets.append(value & 0x7F)
        value >>= 7
    septets.reverse()
    return bytes([s | 0x80 for s in septets[:-1]] + [septets[-1]])


def _validate_single_tlv(raw: bytes | None, label: str, what: str) -> None:
    """Require `raw` to be a single, length-exact DER SEQUENCE TLV (or None)."""
    if raw is None:
        return
    if not raw or raw[0] != 0x30:
        raise DslError(f"{label}: {what} must be a DER SEQUENCE TLV starting with 0x30")
    _tag, _start, _vstart, vend = _read_der_tlv(raw, 0, label)
    if vend != len(raw):
        raise DslError(
            f"{label}: {what} has {len(raw) - vend} trailing byte(s) after the SEQUENCE TLV"
        )


def _rewrite_tbs_and_resign(
    cert: x509.Certificate,
    raw_subject: bytes | None,
    raw_issuer: bytes | None,
    raw_ext_blobs: list[bytes],
    issuer_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    hash_algo: hashes.HashAlgorithm,
    cert_id: str,
) -> bytes:
    """Splice the subject, issuer, and/or extra extensions into the TBS and re-sign.

    `raw_subject` / `raw_issuer`, when given, replace the corresponding Name TLV.
    `raw_ext_blobs`, when non-empty, are appended verbatim to the [3] extensions
    SEQUENCE OF (after the extensions cryptography already emitted). Any
    combination may be applied in one pass; the rewritten TBS is signed once and
    returned as the full certificate DER.
    """
    _validate_single_tlv(raw_subject, f"{cert_id}.subject_der_*", "raw subject")
    _validate_single_tlv(raw_issuer, f"{cert_id}.issuer_der_*", "raw issuer")

    der = cert.public_bytes(serialization.Encoding.DER)
    # Outer Certificate ::= SEQUENCE { tbsCertificate, sigAlg, signature }
    tag, _, body_start, body_end = _read_der_tlv(der, 0, f"{cert_id}.outer")
    if tag != 0x30:
        raise DslError(f"{cert_id}: outer certificate is not a SEQUENCE")

    # tbsCertificate SEQUENCE
    tbs_tag, tbs_start, tbs_val_start, tbs_val_end = _read_der_tlv(der, body_start, f"{cert_id}.tbs")
    if tbs_tag != 0x30:
        raise DslError(f"{cert_id}: tbsCertificate is not a SEQUENCE")

    # signatureAlgorithm (kept verbatim) + signature (replaced).
    sig_alg_start = tbs_val_end
    _, _, _, sig_alg_end = _read_der_tlv(der, sig_alg_start, f"{cert_id}.sigAlg")
    sig_alg_tlv = der[sig_alg_start:sig_alg_end]

    # Walk the tbs fields. TBSCertificate fields, in order:
    #   [0] EXPLICIT version (optional), serial INTEGER, signature AlgId,
    #   issuer Name, validity, subject Name, subjectPublicKeyInfo,
    #   [1] issuerUniqueID (opt), [2] subjectUniqueID (opt), [3] extensions (opt).
    pos = tbs_val_start
    field_tag, _, _, field_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.field0")
    if field_tag == 0xA0:  # [0] EXPLICIT version
        pos = field_end
        field_tag, _, _, field_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.serial")
    pos = field_end  # serial INTEGER
    _, _, _, field_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.sigAlgInner")
    pos = field_end  # signature AlgorithmIdentifier
    issuer_tlv_start = pos
    _, _, _, issuer_tlv_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.issuer")
    pos = issuer_tlv_end  # issuer Name
    _, _, _, field_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.validity")
    pos = field_end  # validity
    subject_tlv_start = pos
    _, _, _, subject_tlv_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.subject")
    pos = subject_tlv_end
    _, _, _, field_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.spki")
    pos = field_end  # subjectPublicKeyInfo
    # Scan any trailing optional fields for the [3] extensions wrapper.
    ext_tlv_start = ext_tlv_end = ext_val_start = ext_val_end = None
    while pos < tbs_val_end:
        t, t_start, v_start, v_end = _read_der_tlv(der, pos, f"{cert_id}.tbs.trailing")
        if t == 0xA3:  # [3] EXPLICIT extensions
            ext_tlv_start, ext_val_start, ext_val_end = t_start, v_start, v_end
            ext_tlv_end = v_end
            break
        pos = v_end

    # Build the list of (start, end, replacement) edits inside the TBS value.
    edits: list[tuple[int, int, bytes]] = []
    if raw_issuer is not None:
        edits.append((issuer_tlv_start, issuer_tlv_end, raw_issuer))
    if raw_subject is not None:
        edits.append((subject_tlv_start, subject_tlv_end, raw_subject))
    if raw_ext_blobs:
        if ext_tlv_start is None:
            raise DslError(
                f"{cert_id}.raw_extensions: certificate has no [3] extensions block to extend"
            )
        # The [3] wrapper holds a single SEQUENCE OF Extension; append into it.
        seq_tag, _, seq_val_start, seq_val_end = _read_der_tlv(
            der, ext_val_start, f"{cert_id}.tbs.extensions.seq"
        )
        if seq_tag != 0x30:
            raise DslError(f"{cert_id}: extensions field is not a SEQUENCE")
        new_inner = der[seq_val_start:seq_val_end] + b"".join(raw_ext_blobs)
        new_ext_block = der_string(0xA3, der_string(0x30, new_inner))
        edits.append((ext_tlv_start, ext_tlv_end, new_ext_block))

    edits.sort(key=lambda e: e[0])
    pieces: list[bytes] = []
    cursor = tbs_val_start
    for start, end, replacement in edits:
        pieces.append(der[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(der[cursor:tbs_val_end])
    new_tbs_tlv = der_string(0x30, b"".join(pieces))

    new_signature = _sign_tbs(new_tbs_tlv, issuer_key, hash_algo)
    new_signature_tlv = der_string(0x03, b"\x00" + new_signature)

    return der_string(0x30, new_tbs_tlv + sig_alg_tlv + new_signature_tlv)


def _read_der_tlv(buf: bytes, pos: int, location: str) -> tuple[int, int, int, int]:
    """Parse one DER TLV starting at pos.

    Returns (tag, tlv_start, value_start, value_end). Only single-octet tags
    (tag number < 31) are supported; that covers every field used in X.509
    certificate bodies.
    """
    if pos >= len(buf):
        raise DslError(f"{location}: truncated DER at byte {pos}")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DslError(f"{location}: multi-byte tags are not supported")
    tlv_start = pos
    pos += 1
    if pos >= len(buf):
        raise DslError(f"{location}: truncated DER after tag")
    length_byte = buf[pos]
    pos += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        n = length_byte & 0x7F
        if n == 0 or pos + n > len(buf):
            raise DslError(f"{location}: indefinite or truncated DER length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    value_start = pos
    value_end = value_start + length
    if value_end > len(buf):
        raise DslError(f"{location}: DER length runs past end of buffer")
    return tag, tlv_start, value_start, value_end


def _sign_tbs(
    tbs_bytes: bytes,
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    hash_algo: hashes.HashAlgorithm,
) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(tbs_bytes, padding.PKCS1v15(), hash_algo)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(tbs_bytes, ec.ECDSA(hash_algo, deterministic_signing=True))
    raise DslError("unsupported signing key type")


@dataclass(frozen=True)
class RawGeneralName:
    """A GeneralName supplied as verbatim DER (full TLV, including context tag).

    Used by the GeneralName-level raw hatch so a single exotic name — a
    directoryName with a multi-AVA / non-canonical-SET / exotic-string RDN, a
    malformed iPAddress, an arbitrary tag — can be dropped into a SAN or a
    name-constraint subtree without hand-encoding the surrounding extension.
    When any name in a SAN or NameConstraints is raw, the whole extension is
    assembled at the DER level and injected as an UnrecognizedExtension; when
    none is raw, the typed cryptography path is used unchanged.
    """
    der: bytes


def _names_have_raw(names: list[Any]) -> bool:
    return any(isinstance(n, RawGeneralName) for n in names)


def _general_name_der(gn: Any) -> bytes:
    """DER of one GeneralName TLV — verbatim for raw, via cryptography for typed."""
    if isinstance(gn, RawGeneralName):
        return gn.der
    # cryptography exposes no per-GeneralName serializer, but SubjectAlternativeName
    # does; wrap the single name, then strip the outer SEQUENCE to recover the TLV.
    wrapped = x509.SubjectAlternativeName([gn]).public_bytes()
    _tag, _start, value_start, value_end = _read_der_tlv(wrapped, 0, "general_name")
    return wrapped[value_start:value_end]


def _assemble_general_names_der(names: list[Any]) -> bytes:
    """Assemble GeneralNames ::= SEQUENCE OF GeneralName (the SAN extnValue)."""
    return der_string(0x30, b"".join(_general_name_der(n) for n in names))


def _assemble_name_constraints_der(permitted: list[Any], excluded: list[Any]) -> bytes:
    """Assemble NameConstraints ::= SEQUENCE { [0] permitted, [1] excluded }."""
    def subtrees(names: list[Any], tag: int) -> bytes:
        if not names:
            return b""
        # GeneralSubtree ::= SEQUENCE { base GeneralName } (minimum/maximum omitted).
        body = b"".join(der_string(0x30, _general_name_der(n)) for n in names)
        return der_string(tag, body)
    return der_string(0x30, subtrees(permitted, 0xA0) + subtrees(excluded, 0xA1))


def parse_name_constraints(value: Any, cert_id: str) -> tuple[x509.ExtensionType, bool]:
    obj = require_object(value, f"{cert_id}.name_constraints")
    critical = bool(obj.get("critical", True))
    permitted = parse_general_names(obj.get("permitted"), f"{cert_id}.name_constraints.permitted")
    excluded = parse_general_names(obj.get("excluded"), f"{cert_id}.name_constraints.excluded")
    if not permitted and not excluded:
        raise DslError(f"{cert_id}.name_constraints must contain permitted or excluded names")
    if _names_have_raw(permitted) or _names_have_raw(excluded):
        value_der = _assemble_name_constraints_der(permitted, excluded)
        return x509.UnrecognizedExtension(ObjectIdentifier("2.5.29.30"), value_der), critical
    return x509.NameConstraints(permitted_subtrees=permitted or None, excluded_subtrees=excluded or None), critical


def parse_general_names(value: Any, location: str) -> list[x509.GeneralName]:
    if value is None:
        return []
    names: list[x509.GeneralName] = []
    if isinstance(value, dict):
        for raw_kind, raw_values in value.items():
            kind = normalize_name_kind(raw_kind)
            for item in listify(raw_values, f"{location}.{raw_kind}"):
                names.append(parse_general_name(kind, item, f"{location}.{raw_kind}"))
        return names
    if isinstance(value, list):
        for index, item in enumerate(value):
            item_obj = require_object(item, f"{location}[{index}]")
            loc = f"{location}[{index}]"
            # Fully-raw GeneralName: verbatim TLV (any tag), no type/value needed.
            if "general_name_der_hex" in item_obj or "general_name_der_ascii2der" in item_obj:
                names.append(RawGeneralName(_raw_der_value(item_obj, "general_name_der", loc)))
                continue
            raw_kind = item_obj.get("type", item_obj.get("kind"))
            kind = normalize_name_kind(require_string(raw_kind, f"{loc}.type"))
            if "value" not in item_obj:
                raise DslError(f"{loc} must contain 'value'")
            names.append(parse_general_name(kind, item_obj["value"], f"{loc}.value"))
        return names
    raise DslError(f"{location} must be an object or an array")


def _raw_der_value(obj: dict[str, Any], prefix: str, location: str) -> bytes:
    """Read raw DER from ``{prefix}_hex`` or ``{prefix}_ascii2der`` on ``obj``."""
    has_hex = f"{prefix}_hex" in obj
    has_ascii = f"{prefix}_ascii2der" in obj
    if has_hex and has_ascii:
        raise DslError(f"{location}: specify either {prefix}_hex or {prefix}_ascii2der, not both")
    if has_hex:
        text = require_string(obj[f"{prefix}_hex"], f"{location}.{prefix}_hex")
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            raise DslError(f"{location}.{prefix}_hex is not valid hex") from exc
    if has_ascii:
        return run_ascii2der(
            require_string(obj[f"{prefix}_ascii2der"], f"{location}.{prefix}_ascii2der"), location
        )
    raise DslError(f"{location} must contain {prefix}_hex or {prefix}_ascii2der")


def parse_general_name(kind: str, value: Any, location: str) -> x509.GeneralName | RawGeneralName:
    # directoryName raw hatch: value carries the inner Name SEQUENCE as DER, which
    # we wrap in the [4] EXPLICIT directoryName tag. Lets a multi-AVA / non-canonical
    # / exotic-string DN go straight into a constraint or SAN (same value_der_* the
    # subject hatch uses). A normal directoryName value is a DN string/dict/list.
    if kind == "directory_name" and isinstance(value, dict) and (
        "value_der_hex" in value or "value_der_ascii2der" in value
    ):
        name_der = _raw_der_value(value, "value_der", location)
        return RawGeneralName(der_string(0xA4, name_der))
    if kind == "dns":
        return x509.DNSName(require_string(value, location))
    if kind == "email":
        return x509.RFC822Name(require_string(value, location))
    if kind == "uri":
        return x509.UniformResourceIdentifier(require_string(value, location))
    if kind == "ip":
        text = require_string(value, location)
        ip_value = ipaddress.ip_network(text, strict=False) if "/" in text else ipaddress.ip_address(text)
        return x509.IPAddress(ip_value)
    if kind == "directory_name":
        return x509.DirectoryName(parse_name(value, location))
    if kind == "registered_id":
        return x509.RegisteredID(ObjectIdentifier(require_string(value, location)))
    if kind == "other_name":
        return parse_other_name(value, location)
    raise DslError(f"{location}: unsupported GeneralName type {kind!r}")


def parse_other_name(value: Any, location: str) -> x509.OtherName:
    obj = require_object(value, location)
    oid = ObjectIdentifier(require_string(obj.get("oid"), f"{location}.oid"))
    if "value_der_hex" in obj:
        try:
            der_value = bytes.fromhex(require_string(obj["value_der_hex"], f"{location}.value_der_hex"))
        except ValueError as exc:
            raise DslError(f"{location}.value_der_hex is not valid hex") from exc
    elif "utf8" in obj:
        der_value = der_string(0x0C, require_string(obj["utf8"], f"{location}.utf8").encode("utf-8"))
    elif "ia5" in obj:
        der_value = der_string(0x16, require_string(obj["ia5"], f"{location}.ia5").encode("ascii"))
    else:
        raise DslError(f"{location} must contain value_der_hex, utf8, or ia5")
    return x509.OtherName(oid, der_value)


def normalize_name_kind(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "rfc822": "email",
        "rfc822_name": "email",
        "mail": "email",
        "email_address": "email",
        "ip_address": "ip",
        "ipaddress": "ip",
        "directoryname": "directory_name",
        "directory": "directory_name",
        "dir": "directory_name",
        "dn": "directory_name",
        "rid": "registered_id",
        "registeredid": "registered_id",
        "registered_id": "registered_id",
        "othername": "other_name",
        "other_name": "other_name",
    }
    return aliases.get(normalized, normalized)


def der_string(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_length(len(value)) + value


def der_length(length: int) -> bytes:
    if length < 0:
        raise DslError("DER length must be non-negative")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def parse_name(value: Any, location: str) -> x509.Name:
    """Parse a DN into an x509.Name.

    Accepted forms:
      - string: ``"C=US,O=Example,CN=Alice"`` (RFC 4514-ish, escapes with ``\\``).
      - dict:   ``{"c": "US", "o": "Example"}`` — each key is one single-AVA RDN.
      - list:   ordered list of RDNs. Each element is either an AVA object
                ``{"type": "cn", "value": "Alice", "encoding": "printable_string"}``
                — a single-AVA RDN — or a nested list of such objects — a
                multi-AVA RDN like ``CN=Alice+UID=alice``.

    The ``encoding`` (alias ``string_type``/``value_type``) field pins the ASN.1
    string type of the encoded value (e.g. ``printable_string``, ``bmp_string``,
    ``t61_string``); useful for cases that probe whether comparisons fold
    string-encoding form.
    """
    if value is None:
        return x509.Name([])
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return x509.Name([])
        rdns = [[attr] for attr in parse_name_string(text, location)]
        return _rdns_to_name(rdns)
    if isinstance(value, dict):
        rdns: list[list[x509.NameAttribute]] = []
        for key, raw_value in value.items():
            oid = name_oid(key, f"{location}.{key}")
            for item in listify(raw_value, f"{location}.{key}"):
                rdns.append([x509.NameAttribute(oid, require_string(item, f"{location}.{key}"))])
        return _rdns_to_name(rdns)
    if isinstance(value, list):
        rdns = []
        for index, item in enumerate(value):
            rdn_loc = f"{location}[{index}]"
            if isinstance(item, list):
                if not item:
                    raise DslError(f"{rdn_loc} multi-AVA RDN must contain at least one attribute")
                rdns.append([_parse_ava(ava, f"{rdn_loc}[{j}]") for j, ava in enumerate(item)])
            else:
                rdns.append([_parse_ava(item, rdn_loc)])
        return _rdns_to_name(rdns)
    raise DslError(f"{location} must be a DN string, object, or array")


def _parse_ava(item: Any, location: str) -> x509.NameAttribute:
    obj = require_object(item, location)
    raw_oid = obj.get("oid", obj.get("type"))
    oid = name_oid(require_string(raw_oid, f"{location}.type"), f"{location}.type")
    value = require_string(obj.get("value"), f"{location}.value")
    encoding = obj.get("encoding", obj.get("string_type", obj.get("value_type")))
    asn1_type = None
    if encoding is not None:
        normalized = str(encoding).strip().lower().replace("-", "_")
        asn1_type = STRING_TYPES.get(normalized)
        if asn1_type is None:
            raise DslError(f"{location}.encoding: unsupported string type {encoding!r}")

    # `validate: false` lets a test emit AVAs that cryptography would otherwise
    # reject for violating X.520 length/syntax constraints — empty values,
    # 3-char countryName, etc. Pinning an `encoding` also implies skipping
    # validation, because validation reaches into specific string types.
    validate = obj.get("validate", True)
    skip_validate = (not validate) or asn1_type is not None

    kwargs: dict[str, Any] = {}
    if asn1_type is not None:
        kwargs["_type"] = asn1_type
    if skip_validate:
        kwargs["_validate"] = False
    return x509.NameAttribute(oid, value, **kwargs)


def _rdns_to_name(rdns: list[list[x509.NameAttribute]]) -> x509.Name:
    if not rdns:
        return x509.Name([])
    return x509.Name([x509.RelativeDistinguishedName(attrs) for attrs in rdns])


def parse_name_string(value: str, location: str) -> list[x509.NameAttribute]:
    if value.startswith("/"):
        pieces = [piece for piece in value.split("/") if piece]
    else:
        pieces = split_unescaped(value, ",")

    attrs: list[x509.NameAttribute] = []
    for piece in pieces:
        key_value = split_once_unescaped(piece, "=")
        if key_value is None:
            raise DslError(f"{location}: DN component lacks '=': {piece!r}")
        key, raw_value = key_value
        attrs.append(x509.NameAttribute(name_oid(key.strip(), location), unescape_dn_value(raw_value.strip())))
    return attrs


def name_oid(value: str, location: str) -> ObjectIdentifier:
    normalized = value.strip().lower().replace("-", "_")
    if normalized in NAME_OIDS:
        return NAME_OIDS[normalized]
    if re.fullmatch(r"\d+(?:\.\d+)+", value.strip()):
        return ObjectIdentifier(value.strip())
    raise DslError(f"{location}: unsupported DN attribute type {value!r}")


def split_unescaped(value: str, delimiter: str) -> list[str]:
    pieces: list[str] = []
    current: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == delimiter:
            pieces.append("".join(current))
            current = []
            continue
        current.append(char)
    if escaped:
        current.append("\\")
    pieces.append("".join(current))
    return pieces


def split_once_unescaped(value: str, delimiter: str) -> tuple[str, str] | None:
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == delimiter:
            return value[:index], value[index + 1 :]
    return None


def unescape_dn_value(value: str) -> str:
    result: list[str] = []
    escaped = False
    for char in value:
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        result.append(char)
    if escaped:
        result.append("\\")
    return "".join(result)


def generate_key(
    key_spec: Any,
    defaults: dict[str, Any],
    chain_name: str,
    cert_id: str,
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    spec = object_or_empty(key_spec, "key")
    key_type = str(spec.get("type", defaults.get("key_type", "rsa"))).lower()
    if key_type == "rsa":
        # RSA prime generation is non-deterministic in the cryptography lib
        # (it goes through OpenSSL's PRNG with no injectable seed). Tests
        # that need a deterministic build should use ECDSA.
        bits = spec.get("bits", defaults.get("rsa_bits", DEFAULT_RSA_BITS))
        if not isinstance(bits, int) or bits < 2048:
            raise DslError("RSA key bits must be an integer >= 2048")
        return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    if key_type == "ecdsa":
        curve_name = str(spec.get("curve", defaults.get("curve", "secp256r1"))).lower()
        curves = {
            "secp256r1": ec.SECP256R1,
            "prime256v1": ec.SECP256R1,
            "p-256": ec.SECP256R1,
            "secp384r1": ec.SECP384R1,
            "p-384": ec.SECP384R1,
            "secp521r1": ec.SECP521R1,
            "p-521": ec.SECP521R1,
        }
        curve = curves.get(curve_name)
        if curve is None:
            raise DslError(f"unsupported EC curve: {curve_name}")
        return deterministic_ec_key(curve(), chain_name, cert_id)
    raise DslError(f"unsupported key type: {key_type}")


# Curve orders for the curves this generator supports. Hardcoded so we
# don't depend on a library-specific accessor.
_EC_CURVE_ORDER: dict[type, int] = {
    ec.SECP256R1: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ec.SECP384R1: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    ec.SECP521R1: 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
}


def deterministic_ec_key(
    curve: ec.EllipticCurve, chain_name: str, cert_id: str
) -> ec.EllipticCurvePrivateKey:
    """Derive an EC private key from sha256("key" + chain + cert).

    The hash output is widened (with shake_256) to (curve_bits + 64)
    bits to keep the modular-reduction bias negligible, reduced mod
    (n-1), and shifted by 1 so the result is in [1, n-1].
    """
    order = _EC_CURVE_ORDER.get(type(curve))
    if order is None:
        raise DslError(f"deterministic EC keygen not implemented for curve {curve.name!r}")
    nbytes = (curve.key_size + 64 + 7) // 8
    raw = hashlib.shake_256(f"key{chain_name}{cert_id}".encode("utf-8")).digest(nbytes)
    scalar = (int.from_bytes(raw, "big") % (order - 1)) + 1
    return ec.derive_private_key(scalar, curve)


def default_key_usage(is_ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=not is_ca,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=is_ca,
        crl_sign=is_ca,
        encipher_only=False,
        decipher_only=False,
    )


def parse_eku(value: Any, cert_id: str) -> x509.ExtendedKeyUsage:
    oids: list[ObjectIdentifier] = []
    for item in listify(value, f"{cert_id}.eku"):
        text = require_string(item, f"{cert_id}.eku")
        normalized = text.strip().lower().replace("-", "_")
        if normalized in EKU_OIDS:
            oids.append(EKU_OIDS[normalized])
        elif re.fullmatch(r"\d+(?:\.\d+)+", text.strip()):
            oids.append(ObjectIdentifier(text.strip()))
        else:
            raise DslError(f"{cert_id}.eku: unsupported EKU {text!r}")
    return x509.ExtendedKeyUsage(oids)


def parse_unknown_extensions(value: Any, cert_id: str) -> list[tuple[x509.UnrecognizedExtension, bool]]:
    if value is None:
        return []
    extensions: list[tuple[x509.UnrecognizedExtension, bool]] = []
    for index, item in enumerate(listify(value, f"{cert_id}.unknown_extensions")):
        obj = require_object(item, f"{cert_id}.unknown_extensions[{index}]")
        loc = f"{cert_id}.unknown_extensions[{index}]"
        oid = ObjectIdentifier(require_string(obj.get("oid"), f"{loc}.oid"))
        extension_value = parse_der_value(obj, f"{loc}")
        extensions.append((x509.UnrecognizedExtension(oid, extension_value), bool(obj.get("critical", False))))
    return extensions


def parse_der_value(obj: dict[str, Any], location: str) -> bytes:
    """Decode a DER value from either `value_hex` or `value_ascii2der`.

    `value_ascii2der` is a string in the der-ascii language (see
    https://github.com/google/der-ascii) and is converted by invoking
    the `ascii2der` binary, which must be on $PATH.
    """
    has_hex = "value_hex" in obj
    has_ascii = "value_ascii2der" in obj
    if has_hex and has_ascii:
        raise DslError(f"{location}: specify either value_hex or value_ascii2der, not both")
    if has_hex:
        hex_value = require_string(obj["value_hex"], f"{location}.value_hex")
        try:
            return bytes.fromhex(hex_value)
        except ValueError as exc:
            raise DslError(f"{location}.value_hex is not valid hex") from exc
    if has_ascii:
        source = require_string(obj["value_ascii2der"], f"{location}.value_ascii2der")
        return run_ascii2der(source, location)
    raise DslError(f"{location} must contain value_hex or value_ascii2der")


def run_ascii2der(source: str, location: str) -> bytes:
    import subprocess
    try:
        completed = subprocess.run(
            ["ascii2der"],
            input=source.encode("utf-8"),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DslError(
            f"{location}.value_ascii2der requires `ascii2der` on PATH "
            "(install from https://github.com/google/der-ascii)"
        ) from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise DslError(f"{location}.value_ascii2der: ascii2der failed: {stderr}")
    return completed.stdout


def validity_window(spec: dict[str, Any], defaults: dict[str, Any]) -> tuple[datetime, datetime]:
    if "not_before" in spec:
        not_before = parse_datetime(require_string(spec["not_before"], "not_before"))
    else:
        not_before = defaults.get("start_date") or parse_start_date(DEFAULT_START_DATE)

    if "not_after" in spec:
        not_after = parse_datetime(require_string(spec["not_after"], "not_after"))
    else:
        days = spec.get("days", defaults.get("duration_days", DEFAULT_DURATION_DAYS))
        if not isinstance(days, int):
            raise DslError("days must be an integer")
        not_after = not_before + timedelta(days=days)

    if not_after <= not_before:
        raise DslError("not_after must be after not_before")
    return not_before, not_after


def parse_start_date(value: str) -> datetime:
    text = value.strip()
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--start-date must be YYYY-MM-DD (got {value!r})"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def parse_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def serial_number(spec: dict[str, Any], chain_name: str, cert_id: str) -> int:
    value = spec.get("serial")
    if value is None:
        return deterministic_serial(chain_name, cert_id)
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str):
        parsed = int(value, 0)
        if parsed > 0:
            return parsed
    raise DslError("serial must be a positive integer")


def deterministic_serial(chain_name: str, cert_id: str) -> int:
    """Derive a positive 159-bit serial from sha256("serial_number" + chain + cert).

    RFC 5280 allows up to 20 octets; we emit at most 159 bits so the DER
    INTEGER stays in 20 octets with the sign bit clear, matching what
    cryptography.x509.random_serial_number() produces.
    """
    digest = hashlib.sha256(f"serial_number{chain_name}{cert_id}".encode("utf-8")).digest()
    # Take 20 octets, clear the high bit of the leading octet to keep it positive,
    # and require non-zero (vanishingly unlikely, but cryptography rejects 0).
    head = digest[0] & 0x7F
    value = int.from_bytes(bytes([head]) + digest[1:20], "big")
    return value or 1


def parse_hash(value: Any) -> hashes.HashAlgorithm:
    name = str(value).strip().lower().replace("-", "")
    if name == "sha256":
        return hashes.SHA256()
    if name == "sha384":
        return hashes.SHA384()
    if name == "sha512":
        return hashes.SHA512()
    raise DslError(f"unsupported hash algorithm: {value!r}")


def positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def write_pem_private_key(path: Path, key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def write_pem_certificate(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def write_bundle(path: Path, generated: Iterable[GeneratedCert]) -> None:
    with path.open("wb") as f:
        for item in generated:
            f.write(item.cert_bytes(serialization.Encoding.PEM))


def write_chain_bundle(path: Path, generated: list[GeneratedCert]) -> None:
    if len(generated) < 2:
        write_bundle(path, [generated[-1]])
        return
    # Most validators expect the target first, then intermediates, excluding trust anchor.
    write_bundle(path, list(reversed(generated[1:])))


def write_trust_anchor(path: Path, generated: list[GeneratedCert]) -> None:
    path.write_bytes(generated[0].cert_bytes(serialization.Encoding.PEM))


def write_metadata(path: Path, chain: dict[str, Any], files: list[dict[str, str]]) -> None:
    metadata = {
        "name": chain.get("name"),
        "expected": chain.get("expected"),
        "description": chain.get("description"),
        "references": chain.get("references", []),
        "notes": chain.get("notes", []),
        "files": files,
    }
    path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_filename(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip(".-")
    if not safe:
        raise DslError(f"cannot turn {value!r} into a safe file name")
    return safe


def object_or_empty(value: Any, location: str) -> dict[str, Any]:
    if value is None:
        return {}
    return require_object(value, location)


def require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DslError(f"{location} must be an object")
    return value


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str):
        raise DslError(f"{location} must be a string")
    return value


def listify(value: Any, location: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, (str, int, bool, dict)):
        return [value]
    raise DslError(f"{location} must be a value or an array")


if __name__ == "__main__":
    raise SystemExit(main())
