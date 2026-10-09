//! Report unsupported production prerequisites; this performs no host inspection.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().len() != 1 {
        return Err("deployment_preflight accepts no host, attestation or key input".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&aegis::vault::deployment::deployment_prerequisites())?
    );
    Ok(())
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() {
    eprintln!("Enable vault-spike on Unix for the report-only deployment prerequisites.");
    std::process::exit(2);
}
