// Emits RUSTLS_WEBPKI_VERSION as a rustc env var, parsed from Cargo.lock,
// so the resulting binary can report exactly which rustls-webpki it was
// built against when invoked with `--version`. The src dependency line in
// Cargo.toml is a semver range; the lockfile carries the concrete version.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let lock_path = Path::new(&manifest_dir).join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());

    let contents = fs::read_to_string(&lock_path).expect("read Cargo.lock");
    let mut version = "unknown".to_string();
    let mut in_block = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "name = \"rustls-webpki\"" {
            in_block = true;
            continue;
        }
        if in_block {
            if let Some(rest) = trimmed.strip_prefix("version = ") {
                version = rest.trim_matches('"').to_string();
                break;
            }
            if trimmed.starts_with("name = ") {
                // Hit the next dependency without finding a version line.
                break;
            }
        }
    }
    println!("cargo:rustc-env=RUSTLS_WEBPKI_VERSION={}", version);
}
