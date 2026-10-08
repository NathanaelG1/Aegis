//! Fixed synthetic fixture only. Does not read arguments, environment, keys or repositories.
fn main() -> std::process::ExitCode {
    match aegis::github::run_synthetic_demo() {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("fixed safe report")
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Synthetic GitHub exercise failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
