//! Fixed synthetic journal drill. Existing journals can only be inspected, never resumed.
fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command, path] if command == "create" => aegis::github::create_synthetic_intent_drill(std::path::Path::new(path)).map(|()| {
            println!("Synthetic intent drill saved. Exit this process, then inspect. No real credentials or restored authority.");
        }),
        [command, path] if command == "inspect" => aegis::github::inspect_synthetic_intents(std::path::Path::new(path)).map(|report| {
            println!("{}", serde_json::to_string_pretty(&report).expect("safe report"));
        }),
        _ => { eprintln!("Usage: github_intent_spike create <new-absolute-directory> | inspect <existing-synthetic-directory>"); return std::process::ExitCode::from(2); }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Synthetic journal drill failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
