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
            println!("Aegis experimental, synthetic-only\n\nCommands:\n  demo                  Scripted trusted-host policy demo\n  synthetic-agent       Standalone strict JSON-lines fixture (no control channel)\n  synthetic-broker --socket-dir NEW_ABSOLUTE_DIRECTORY\n                        Foreground Unix broker; private terminal controls\n  mcp --socket ABSOLUTE_SOCKET_PATH\n                        Legacy issue-status stdio client\n  synthetic-github-broker --socket-dir NEW_DIRECTORY --journal-dir NEW_DIRECTORY\n                        Fixed synthetic GitHub operation with retained intents\n  mcp-v2 --socket ABSOLUTE_SOCKET_PATH\n                        Version-2 typed-operation stdio client\n\nHuman control: inspect ID, approve ID, cancel ID, revoke, stop.\nNo real-secret input or live provider; see README.md for verified limits.");
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
        [arg, flag, path] if arg == "mcp-v2" && flag == "--socket" => {
            mcp_v2(std::path::Path::new(path))
        }
        [arg, socket_flag, socket, journal_flag, journal]
            if arg == "synthetic-github-broker"
                && socket_flag == "--socket-dir"
                && journal_flag == "--journal-dir" =>
        {
            github_foreground(
                std::path::Path::new(socket),
                std::path::Path::new(journal),
                false,
            )
        }
        [arg, socket_flag, socket, journal_flag, journal, test_flag]
            if arg == "synthetic-github-broker"
                && socket_flag == "--socket-dir"
                && journal_flag == "--journal-dir"
                && test_flag == "--synthetic-control-pipe" =>
        {
            github_foreground(
                std::path::Path::new(socket),
                std::path::Path::new(journal),
                true,
            )
        }
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
    foreground_profile(directory, synthetic_pipe, None)
}
#[cfg(unix)]
fn github_foreground(
    socket: &std::path::Path,
    journal: &std::path::Path,
    synthetic_pipe: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    foreground_profile(socket, synthetic_pipe, Some(journal))
}
#[cfg(not(unix))]
fn github_foreground(
    _: &std::path::Path,
    _: &std::path::Path,
    _: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(aegis::ErrorCode::InteractionRequired.into())
}
#[cfg(unix)]
fn mcp_v2(socket: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let bridge = aegis::ipc::SocketBridge::connect(socket)?;
    aegis::mcp::serve_v2(std::io::stdin().lock(), std::io::stdout().lock(), bridge)?;
    Ok(())
}
#[cfg(not(unix))]
fn mcp_v2(_: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    Err(aegis::ErrorCode::InteractionRequired.into())
}
#[cfg(unix)]
fn foreground_profile(
    directory: &std::path::Path,
    synthetic_pipe: bool,
    github_journal: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, IsTerminal};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    if !synthetic_pipe && !std::io::stdin().is_terminal() {
        return Err(aegis::ErrorCode::InteractionRequired.into());
    }
    let endpoint = aegis::ipc::Endpoint::create(directory)?;
    let principal = aegis::PrincipalId::new(format!("local-uid-{}", nix::unistd::geteuid()))?;
    let (control, client) = if let Some(journal) = github_journal {
        let setup = aegis::OperationSetup {
            principal,
            ..aegis::OperationSetup::synthetic_github()
        };
        Control::synthetic_github(setup, Arc::new(MonotonicClock::default()), journal)?
    } else {
        let setup = SyntheticSetup {
            principal,
            ..SyntheticSetup::default()
        };
        Control::synthetic(
            setup,
            Arc::new(MonotonicClock::default()),
            Arc::new(FakeProvider::default()),
        )?
    };
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
        let mut reviewed: Option<(u64, aegis::OperationApprovalView)> = None;
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
                ["revoke-tokens"] => control_thread.revoke_provider_tokens().map(|status| eprintln!("synthetic_provider_revocation {status:?}")),
                [method, handle] => match handle.parse::<u64>() {
                    Ok(id) => match *method {
                        "inspect" => control_thread.inspect_operation_approval(id).and_then(|view| {
                            match (&view.profile,&view.operation) {
                                (aegis::OperationProfile::IssueStatus(profile),aegis::OperationIntent::IssueStatus(parameters)) => {
                                    eprintln!("Resolved synthetic request: principal={} session={} operation=issue-status resource={} issue={} profile_revision={} credential=synthetic-fixture credential_version={} output_contract={} generation={} expiry={} remaining_uses={} mode=portable-workflow effects=synthetic-read output=repository_id,issue_number,state idle_seconds=600 maximum_seconds=1800", view.principal.as_str(), view.session, parameters.repository_id, parameters.issue_number, profile.revision, profile.credential.version, profile.output_contract, view.policy_generation, view.expires_at, view.remaining_uses);
                                }
                                (aegis::OperationProfile::GithubMetadata(profile),aegis::OperationIntent::GithubMetadata(parameters)) => {
                                    eprintln!("Resolved synthetic GitHub request: prepared_request_id={} request_id={} principal={} session={} operation=synthetic.github.repository-metadata.v1 app={} client={} installation={} owner={}:{} account_type=User repository={}:{} selection=selected signer={} signer_version={} profile_revision={} adapter_contract={} output_contract={} generation={} expiry={} remaining_uses={} permissions=metadata:read installation_contents={:?} installation_metadata={:?} limits={:?} effects=mock-token-mint,mock-metadata-read output=repository_id,private,archived real_keys=false",view.prepared_request_id,view.request_id.as_str(),view.principal.as_str(),view.session,profile.app_id,profile.client_id,profile.installation_id,profile.account_login,profile.account_id,parameters.repository_id,profile.repository_name,profile.credential.secret_id,profile.credential.version,profile.revision,profile.adapter_contract,profile.output_contract,view.policy_generation,view.expires_at,view.remaining_uses,profile.installation_contents,profile.installation_metadata,view.limits);
                                }
                                _=>return Err(aegis::ErrorCode::ScopeDenied),
                            }
                            reviewed=Some((id,view));Ok(())
                        }),
                        "approve" => match reviewed.take() {
                            Some((reviewed_id, view)) if reviewed_id == id => control_thread.approve_operation_reviewed(id, &view).map(|_| ()),
                            _ => Err(aegis::ErrorCode::ApprovalRequired),
                        },
                        "cancel" => control_client.cancel_operation(id).map(|_| ()),
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
