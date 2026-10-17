//! Fixed encrypted-vault-to-recipient drill. Every key/value is a disposable fixture.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, root, kit, recipient] = args.as_slice() else {
        eprintln!("Usage: vault_spike <create|inspect> <vault-dir> <separate-fixture-kit-dir> <recipient-dir>");
        std::process::exit(2);
    };
    let (root, kit, recipient) = (
        std::path::Path::new(root),
        std::path::Path::new(kit),
        std::path::Path::new(recipient),
    );
    match mode.as_str() {
        "create" => println!(
            "{}",
            serde_json::to_string_pretty(&aegis::vault::run_synthetic_vault_drill(
                root, kit, recipient
            )?)?
        ),
        "inspect" => println!(
            "{}",
            serde_json::to_string_pretty(&aegis::vault::inspect_synthetic_vault(
                root, kit, recipient
            )?)?
        ),
        _ => return Err("unsupported synthetic fixture command".into()),
    }
    Ok(())
}
#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() {
    eprintln!("Enable vault-spike on Unix for this synthetic-only fixture.");
    std::process::exit(2);
}
