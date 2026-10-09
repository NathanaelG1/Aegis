//! Fixed-canary encrypted import. No credential, reader, identity or configuration input.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let destination = args
        .next()
        .ok_or("Usage: protected_entry <new-absolute-fixture-directory>")?;
    if args.next().is_some() {
        return Err("protected_entry accepts only one new fixture destination".into());
    }
    let report = aegis::vault::entry::protected_entry::run_synthetic_protected_entry_drill(
        std::path::Path::new(&destination),
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() {
    eprintln!("Enable vault-spike on Unix for the fixed-canary encrypted import.");
    std::process::exit(2);
}
