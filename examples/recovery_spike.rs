//! Two-process synthetic recovery drill. Never accepts credential values.

#[cfg(feature = "storage-spike")]
fn main() -> std::process::ExitCode {
    use aegis::storage::{create_saved_synthetic_drill, recover_saved_synthetic_drill};
    use std::path::Path;

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = match arguments.as_slice() {
        [mode, snapshot, kit] if mode == "create" => {
            create_saved_synthetic_drill(Path::new(snapshot), Path::new(kit)).map(|()| {
                println!("Synthetic snapshot and separate recovery kit saved. Exit setup before recovery. No recovery verification or production readiness claimed.");
            })
        }
        [mode, snapshot, kit, destination] if mode == "recover" => {
            recover_saved_synthetic_drill(
                Path::new(snapshot),
                Path::new(kit),
                Path::new(destination),
            )
            .map(|summary| {
                println!(
                    "Synthetic recovery drill succeeded: validated_credentials={}, disabled_grants={}, enabled_grants={}, restored_sessions={}. Experimental only.",
                    summary.validated_credentials,
                    summary.disabled_grants,
                    summary.enabled_grants,
                    summary.restored_sessions,
                );
            })
        }
        _ => {
            eprintln!("Usage: recovery_spike create <new-absolute-snapshot-directory> <new-absolute-kit-directory> | recover <snapshot-directory> <kit-directory> <new-absolute-destination>");
            return std::process::ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Synthetic recovery drill failed: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(not(feature = "storage-spike"))]
fn main() -> std::process::ExitCode {
    eprintln!("Enable the optional storage-spike feature for this synthetic-only example.");
    std::process::ExitCode::from(2)
}
