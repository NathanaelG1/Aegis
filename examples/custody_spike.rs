//! Separate-role fixed-canary custody drill. No operational keys or live configuration.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, root, custody, recipient] = args.as_slice() else {
        eprintln!(
            "Usage: custody_spike <create|inspect> <vault-dir> <dummy-role-dir> <recipient-dir>"
        );
        std::process::exit(2);
    };
    let (root, custody, recipient) = (
        std::path::Path::new(root),
        std::path::Path::new(custody),
        std::path::Path::new(recipient),
    );
    match mode.as_str() {
        "create" => println!(
            "{}",
            serde_json::to_string_pretty(&aegis::vault::custody::run_synthetic_custody_drill(
                root, custody, recipient
            )?)?
        ),
        "inspect" => println!(
            "{}",
            serde_json::to_string_pretty(&aegis::vault::custody::inspect_synthetic_custody(
                root, custody, recipient
            )?)?
        ),
        _ => return Err("unsupported synthetic custody command".into()),
    }
    Ok(())
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() {
    eprintln!("Enable vault-spike on Unix for the separate-role synthetic custody drill.");
    std::process::exit(2);
}
