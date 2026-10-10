// Fixed dummy service drill. No listener, arbitrary input or deployment entry.
#[cfg(all(unix, feature = "application-slot"))]
fn main() -> std::process::ExitCode {
    use aegis::vault::{application_slot, process_service};
    if let Some(code) = process_service::synthetic_child_entry() {
        return code;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [root] => {
            application_slot::run_synthetic_application_slot_drill(root.as_ref()).and_then(|r| {
                serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
            })
        }
        [command, root] if command == "inspect" => {
            application_slot::inspect_synthetic_application_slot(root.as_ref()).and_then(|r| {
                serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
            })
        }
        _ => {
            eprintln!(
                "Usage: aegis-application-slot <new-absolute-root> | inspect <existing-root>"
            );
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("Synthetic application slot drill failed closed.");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(all(unix, feature = "application-slot")))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable application-slot on Unix for the synthetic application slot drill.");
    std::process::ExitCode::from(2)
}
