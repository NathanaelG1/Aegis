#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> std::process::ExitCode {
    use aegis::vault::{composed, process_recipient::synthetic_child_entry};
    if let Some(code) = synthetic_child_entry() {
        return code;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [root] => composed::run_synthetic_composed_drill(root.as_ref()).and_then(|r| {
            serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
        }),
        [command, root] if command == "inspect" => {
            composed::inspect_synthetic_composed(root.as_ref()).and_then(|r| {
                serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
            })
        }
        _ => {
            eprintln!("Usage: aegis-composed-canary <new-absolute-root> | inspect <existing-root>");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("Synthetic composed canary drill failed closed.");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable vault-spike on Unix for the synthetic composed canary drill.");
    std::process::ExitCode::from(2)
}
