// Fixed two-canary composition. No listener, input selector or deployment entry.
#[cfg(all(unix, feature = "application-slot"))]
fn main() -> std::process::ExitCode {
    use aegis::vault::{application_rotation, process_service};
    if let Some(code) = process_service::synthetic_child_entry() {
        return code;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [root] => application_rotation::run_synthetic_application_rotation_drill(root.as_ref())
            .and_then(|r| {
                serde_json::to_string_pretty(&r).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
            }),
        [command, root] if command == "inspect" => {
            application_rotation::inspect_synthetic_application_rotation(root.as_ref()).and_then(
                |r| {
                    serde_json::to_string_pretty(&r)
                        .map_err(|_| aegis::ErrorCode::BrokerUnavailable)
                },
            )
        }
        _ => {
            eprintln!(
                "Usage: aegis-application-rotation <new-absolute-root> | inspect <existing-root>"
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
            eprintln!("Synthetic application rotation drill failed closed.");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(all(unix, feature = "application-slot")))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable application-slot on Unix for the synthetic application rotation drill.");
    std::process::ExitCode::from(2)
}
