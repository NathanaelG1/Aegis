//! No-input disposable-key fixture. Never imports keys or outputs a JWT.
#[cfg(feature = "signing-spike")]
fn main() -> std::process::ExitCode {
    match aegis::signing::run_synthetic_signing_demo() {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("safe report")
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Synthetic signing exercise failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(feature = "signing-spike"))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable signing-spike for this disposable-key experiment.");
    std::process::ExitCode::from(2)
}
