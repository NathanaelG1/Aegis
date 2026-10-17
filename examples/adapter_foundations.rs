//! Fixed-fixture adapter workflows. No real key, endpoint or enrollment input.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [destination] = args.as_slice() else {
        eprintln!("Usage: adapter_foundations <new-fixture-directory>");
        std::process::exit(2);
    };
    let root = std::path::Path::new(destination);
    // Refuse to overwrite or reuse an existing fixture.
    std::fs::create_dir(root)?;
    let entry = aegis::vault::entry::run_synthetic_operator_entry_drill()?;
    let recipient = aegis::vault::recipient_adapter::run_synthetic_recipient_adapter_drill()?;
    let transport = aegis::vault::transport::run_synthetic_transport_drill(
        &root.join("vault"),
        &root.join("dummy-kit"),
        &root.join("recipient"),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "synthetic_only": true,
            "operator_entry": entry,
            "recipient_adapter": recipient,
            "transport": transport,
            "live_deployment": aegis::vault::require_live_deployment().err(),
        }))?
    );
    Ok(())
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() {
    eprintln!("Enable vault-spike on Unix for the fixed-fixture adapter workflows.");
    std::process::exit(2);
}
