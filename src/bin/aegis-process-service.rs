// Fixed dummy service drill. No listener, arbitrary input or deployment entry.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> std::process::ExitCode {
    use aegis::vault::process_service;
    if let Some(code) = process_service::synthetic_child_entry() {
        return code;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [root] => {
            process_service::run_synthetic_process_service_drill(root.as_ref()).and_then(|r| {
                serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
            })
        }
        [command, root] if command == "inspect" => {
            process_service::inspect_synthetic_process_service(root.as_ref()).and_then(|r| {
                serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
            })
        }
        _ => {
            eprintln!("Usage: aegis-process-service <new-absolute-root> | inspect <existing-root>");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("Synthetic process service drill failed closed.");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable vault-spike on Unix for the synthetic process service drill.");
    std::process::ExitCode::from(2)
}
