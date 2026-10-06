//! No secret inputs, provider networking, or persistent vault commands in this checkpoint.
use aegis::{
    fake::FakeProvider, protocol, Control, MonotonicClock, Parameters, PrepareInput, ProfileId,
    RequestId, SyntheticSetup,
};
use std::sync::Arc;

fn main() {
    // A binary panic must not dump arbitrary private strings. A trusted embedding host
    // owns its own panic/debug configuration; the library cannot enforce host behavior.
    std::panic::set_hook(Box::new(|_| eprintln!("broker_unavailable")));
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            println!("Aegis experimental: synthetic-only capability broker\n\nUsage: aegis demo | synthetic-agent | --version\n       aegis synthetic-broker --socket-dir <new-absolute-directory>\n       aegis mcp --socket <absolute-socket-path>\n\nNo real-secret input, live provider, persistent vault, or containment claim.");
            Ok(())
        }
        [arg] if arg == "--version" => {
            println!("aegis {} (synthetic-only)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [arg] if matches!(arg.as_str(), "--help" | "-h" | "help") => {
            println!("Aegis experimental, synthetic-only\n\nCommands:\n  demo                  Scripted trusted-host policy demo\n  synthetic-agent       Standalone strict JSON-lines fixture (no control channel)\n  synthetic-broker --socket-dir NEW_ABSOLUTE_DIRECTORY\n                        Foreground Unix broker; private terminal controls\n  mcp --socket ABSOLUTE_SOCKET_PATH\n                        Thin stdio client for an already running broker\n\nHuman control: inspect ID, approve ID, cancel ID, revoke, stop.\nNo real-secret input or live provider; see README.md for verified limits.");
            Ok(())
        }
        [arg] if arg == "demo" => demo(),
        [arg] if arg == "synthetic-agent" => {
            let (_, client) = Control::synthetic(
                SyntheticSetup::default(),
                Arc::new(MonotonicClock::default()),
                Arc::new(FakeProvider::default()),
            )?;
            protocol::serve(std::io::stdin().lock(), std::io::stdout().lock(), &client)?;
            Ok(())
        }
        [arg, flag, path] if arg == "mcp" && flag == "--socket" => mcp(std::path::Path::new(path)),
        [arg, flag, path] if arg == "synthetic-broker" && flag == "--socket-dir" => {
            foreground(std::path::Path::new(path), false)
        }
        [arg, flag, path, test_flag]
            if arg == "synthetic-broker"
                && flag == "--socket-dir"
                && test_flag == "--synthetic-control-pipe" =>
        {
            foreground(std::path::Path::new(path), true)
        }
        _ => Err(aegis::ErrorCode::InvalidRequest.into()),
    }
}
#[cfg(unix)]
fn mcp(socket: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let bridge = aegis::ipc::SocketBridge::connect(socket)?;
    aegis::mcp::serve(std::io::stdin().lock(), std::io::stdout().lock(), bridge)?;
    Ok(())
}
#[cfg(not(unix))]
fn mcp(_: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    Err(aegis::ErrorCode::InteractionRequired.into())
}

#[cfg(unix)]
fn foreground(
    directory: &std::path::Path,
    synthetic_pipe: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, IsTerminal};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    if !synthetic_pipe && !std::io::stdin().is_terminal() {
        return Err(aegis::ErrorCode::InteractionRequired.into());
    }
    let endpoint = aegis::ipc::Endpoint::create(directory)?;
    let principal = aegis::PrincipalId::new(format!("local-uid-{}", nix::unistd::geteuid()))?;
    let setup = SyntheticSetup {
        principal,
        ..SyntheticSetup::default()
    };
    let (control, client) = Control::synthetic(
        setup,
        Arc::new(MonotonicClock::default()),
        Arc::new(FakeProvider::default()),
    )?;
    let control = Arc::new(control);
    let running = Arc::new(AtomicBool::new(true));
    eprintln!(
        "synthetic_broker_ready {}",
        endpoint.socket_path().display()
    );
    eprintln!("Synthetic workflow only; same-account code can automate control. Commands: inspect ID, approve ID, cancel ID, revoke, stop.");
    let control_thread = control.clone();
    let run_thread = running.clone();
    let control_client = client.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut reviewed: Option<(u64, aegis::ApprovalView)> = None;
        for _ in 0..128 {
            let mut frame = Vec::new();
            let count = match std::io::Read::take(&mut stdin, 257).read_until(b'\n', &mut frame) {
                Ok(count) => count,
                Err(_) => break,
            };
            if count == 0 || frame.len() > 256 || frame.last() != Some(&b'\n') {
                break;
            }
            let line = match std::str::from_utf8(&frame) {
                Ok(line) => line,
                Err(_) => {
                    eprintln!("invalid_request");
                    continue;
                }
            };
            let words: Vec<_> = line.split_whitespace().collect();
            let outcome = match words.as_slice() {
                ["stop"] => { let _ = control_thread.stop(); run_thread.store(false, Ordering::SeqCst); break; },
                ["revoke"] => control_thread.revoke(),
                [method, handle] => match handle.parse::<u64>() {
                    Ok(id) => match *method {
                        "inspect" => control_thread.inspect_approval(id).map(|view| {
                            eprintln!("Resolved synthetic request: principal={} session={} operation=issue-status resource={} issue={} profile_revision={} credential=synthetic-fixture credential_version={} output_contract={} generation={} expiry={} remaining_uses={} mode=portable-workflow effects=synthetic-read output=repository_id,issue_number,state idle_seconds=600 maximum_seconds=1800", view.principal.as_str(), view.session, view.parameters.repository_id, view.parameters.issue_number, view.profile.revision, view.profile.credential.version, view.profile.output_contract, view.policy_generation, view.expires_at, view.remaining_uses);
                            reviewed = Some((id, view));
                        }),
                        "approve" => match reviewed.take() {
                            Some((reviewed_id, view)) if reviewed_id == id => control_thread.approve_reviewed(id, &view).map(|_| ()),
                            _ => Err(aegis::ErrorCode::ApprovalRequired),
                        },
                        "cancel" => control_client.cancel(id).map(|_| ()),
                        _ => Err(aegis::ErrorCode::InvalidRequest),
                    },
                    Err(_) => Err(aegis::ErrorCode::InvalidRequest),
                },
                _ => Err(aegis::ErrorCode::InvalidRequest),
            };
            match outcome {
                Ok(()) => eprintln!("synthetic_control_ok"),
                Err(error) => eprintln!("{error}"),
            }
        }
        let _ = control_thread.stop();
        run_thread.store(false, Ordering::SeqCst);
    });
    let started = Instant::now();
    let active = Arc::new(AtomicUsize::new(0));
    while running.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(1800) {
        if control.is_active().is_err() {
            break;
        }
        endpoint.accept_available(&client, active.clone())?;
        std::thread::sleep(Duration::from_millis(25));
    }
    control.stop()?;
    Ok(())
}
#[cfg(not(unix))]
fn foreground(_: &std::path::Path, _: bool) -> Result<(), Box<dyn std::error::Error>> {
    Err(aegis::ErrorCode::InteractionRequired.into())
}

fn demo() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Arc::new(FakeProvider::default());
    let (control, client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(MonotonicClock::default()),
        provider.clone(),
    )?;
    let input = PrepareInput {
        request_id: RequestId::new("demo-1")?,
        profile_id: ProfileId::new("issue-status")?,
        parameters: Parameters {
            repository_id: 4242,
            issue_number: 7,
        },
    };
    println!(
        "discovery: {}",
        serde_json::to_string(&client.discover_operations())?
    );
    let prepared = client.prepare(input.clone())?;
    println!(
        "before approval: {}",
        client.invoke(prepared.prepared_request_id).unwrap_err()
    );
    client.request_approval(prepared.prepared_request_id)?;
    let approval = control.inspect_approval(prepared.prepared_request_id)?;
    println!("synthetic trusted-host decision: repository={} issue={} uses={} (no proof of human presence)", approval.parameters.repository_id, approval.parameters.issue_number, approval.remaining_uses);
    control.approve(prepared.prepared_request_id)?;
    println!(
        "result: {}",
        serde_json::to_string(&client.invoke(prepared.prepared_request_id)?)?
    );
    println!(
        "retry: {}",
        serde_json::to_string(&client.invoke(prepared.prepared_request_id)?)?
    );
    let mut conflict = input.clone();
    conflict.parameters.issue_number = 8;
    println!(
        "same-ID changed input: {}",
        client.prepare(conflict).unwrap_err()
    );
    let mut denied = input;
    denied.request_id = RequestId::new("demo-2")?;
    denied.parameters.repository_id = 9999;
    println!("another resource: {}", client.prepare(denied).unwrap_err());
    control.revoke()?;
    println!(
        "provider dispatches={} remaining_uses={}",
        provider.calls(),
        control.remaining_uses()?
    );
    // Future adapters must use the same core. This fixture exposes no approval wire field.
    Ok(())
}
