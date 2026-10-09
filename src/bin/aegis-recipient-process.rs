// Standalone fixed-canary process drill. No operational recipient entry point.
#[cfg(all(unix, feature = "vault-spike"))]
fn main() -> std::process::ExitCode {
    use aegis::vault::process_recipient::{run_synthetic_process_drill, synthetic_child_entry};
    if let Some(code) = synthetic_child_entry() {
        return code;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [root, custody, state] = args.as_slice() else {
        eprintln!("Usage: aegis-recipient-process <new-vault-dir> <new-dummy-role-dir> <new-recipient-dir>");
        return std::process::ExitCode::from(2);
    };
    match run_synthetic_process_drill(root.as_ref(), custody.as_ref(), state.as_ref()).and_then(
        |report| {
            serde_json::to_string_pretty(&report).map_err(|_| aegis::ErrorCode::BrokerUnavailable)
        },
    ) {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("Synthetic recipient process drill failed closed.");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(not(all(unix, feature = "vault-spike")))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable vault-spike on Unix for the synthetic recipient process drill.");
    std::process::ExitCode::from(2)
}
