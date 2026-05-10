//! rust-verify is a small CLI that runs rustls-webpki's path validation
//! against a leaf, optional intermediates, and a trust anchor PEM file.
//! It exists so test_nc_chains.py can include rustls-webpki among the
//! validators it runs.
//!
//! Usage:
//!
//!     rust-verify --ca ROOT [--intermediate FILE ...] [--at TIME] LEAF
//!
//! LEAF and the --intermediate / --ca files are PEM. A PEM file may
//! contain multiple certificates; any extras in the LEAF file beyond
//! the first are treated as intermediates.
//!
//! Exit codes:
//!
//!     0  - chain verified
//!     1  - chain rejected by webpki
//!     2  - usage error / I/O / parse error

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use webpki::{
    anchor_from_trusted_cert, ring::ECDSA_P256_SHA256, ring::ECDSA_P256_SHA384,
    ring::ECDSA_P384_SHA256, ring::ECDSA_P384_SHA384, ring::ED25519,
    ring::RSA_PKCS1_2048_8192_SHA256, ring::RSA_PKCS1_2048_8192_SHA384,
    ring::RSA_PKCS1_2048_8192_SHA512, ring::RSA_PKCS1_3072_8192_SHA384,
    ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY, ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY, EndEntityCert, KeyUsage,
};

/// Signature algorithms we accept. Covers the curve / hash mixes the
/// test corpus uses (RSA-PKCS1, ECDSA P-256/P-384, Ed25519, RSA-PSS).
static ALL_SIG_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

// The rustls-webpki version is captured at build time by build.rs out of
// Cargo.lock and exposed via the RUSTLS_WEBPKI_VERSION rustc env var.
// The library itself doesn't expose a runtime version constant.
#[derive(Parser)]
#[command(
    about = "rustls-webpki path validation, leaf+intermediates+root",
    long_about = None,
    version = concat!(env!("CARGO_PKG_VERSION"), " (rustls-webpki ", env!("RUSTLS_WEBPKI_VERSION"), ")"),
)]
struct Args {
    /// PEM file containing one or more trust anchors (required).
    #[arg(long)]
    ca: PathBuf,

    /// PEM file with intermediate cert(s); may be repeated.
    #[arg(long = "intermediate")]
    intermediates: Vec<PathBuf>,

    /// Validation time in seconds since the Unix epoch.
    /// Defaults to 2030-01-01 00:00 UTC so that long-dated test chains
    /// (notBefore 2026-01-01, notAfter 2036-12-30) all fall inside
    /// their validity window.
    #[arg(long)]
    at: Option<i64>,

    /// PEM file for the leaf cert.
    leaf: PathBuf,
}

fn load_certs(path: &PathBuf) -> Result<Vec<Vec<u8>>, String> {
    let raw = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let parsed = pem::parse_many(&raw).map_err(|e| format!("PEM parse {}: {}", path.display(), e))?;
    let out: Vec<Vec<u8>> = parsed
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.into_contents())
        .collect();
    if out.is_empty() {
        return Err(format!("{}: no CERTIFICATE PEM blocks found", path.display()));
    }
    Ok(out)
}

fn run() -> Result<(), (i32, String)> {
    let args = Args::parse();

    let leaf_blocks = load_certs(&args.leaf).map_err(|e| (2, e))?;
    let mut intermediates_der: Vec<CertificateDer<'static>> = Vec::new();
    // Extra certs after the leaf in the LEAF file are intermediates.
    for extra in &leaf_blocks[1..] {
        intermediates_der.push(CertificateDer::from(extra.clone()));
    }
    for f in &args.intermediates {
        for blk in load_certs(f).map_err(|e| (2, e))? {
            intermediates_der.push(CertificateDer::from(blk));
        }
    }

    let leaf_der = CertificateDer::from(leaf_blocks[0].clone());
    let ee = EndEntityCert::try_from(&leaf_der)
        .map_err(|e| (2, format!("parse leaf: {:?}", e)))?;

    let ca_blocks = load_certs(&args.ca).map_err(|e| (2, e))?;
    let ca_ders: Vec<CertificateDer<'static>> = ca_blocks
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let trust_anchors: Vec<_> = ca_ders
        .iter()
        .map(|c| anchor_from_trusted_cert(c).map_err(|e| (2, format!("parse trust anchor: {:?}", e))))
        .collect::<Result<_, _>>()?;

    let at = args
        .at
        .map(|s| UnixTime::since_unix_epoch(std::time::Duration::from_secs(s as u64)))
        .unwrap_or_else(|| {
            // 2030-01-01 00:00:00 UTC
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_893_456_000))
        });

    // We don't require a specific EKU because the corpus mixes
    // serverAuth, no EKU, etc. KeyUsage::server_auth matches certs
    // that either omit EKU or include serverAuth - which mirrors the
    // permissive stance used by Go's ExtKeyUsageAny.
    let _ = ee
        .verify_for_usage(
            ALL_SIG_ALGS,
            &trust_anchors,
            intermediates_der.as_slice(),
            at,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| (1, format!("verify failed: {:?}", e)))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("verify ok");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => {
            println!("{}", msg);
            ExitCode::from(code as u8)
        }
    }
}
