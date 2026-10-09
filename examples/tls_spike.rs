//! Actual TLS records carrying the fixed-canary vault protocol; no network service.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [root, kit, recipient] = args.as_slice() else {
        eprintln!("Usage: tls_spike <new-vault-dir> <new-dummy-kit-dir> <new-recipient-dir>");
        std::process::exit(2);
    };
    let report = aegis::vault::tls::run_synthetic_tls_drill(
        std::path::Path::new(root),
        std::path::Path::new(kit),
        std::path::Path::new(recipient),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() {
    eprintln!("Enable vault-spike on Unix for the synthetic TLS drill.");
    std::process::exit(2);
}
