//! Disposable signing through reviewed core authority and the fixed mock provider.
#[cfg(feature = "signing-spike")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aegis::*;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        eprintln!("Usage: github_signed_spike <new-absolute-journal-directory>");
        std::process::exit(2);
    };
    let (control, client) = Control::synthetic_github_signed(
        OperationSetup::synthetic_github(),
        std::sync::Arc::new(MonotonicClock::default()),
        std::path::Path::new(path),
    )?;
    let id = client
        .prepare_operation(OperationPrepareInput {
            request_id: RequestId::new("signed-broker-demo")?,
            profile_id: ProfileId::new("github-metadata")?,
            operation: OperationIntent::GithubMetadata(GithubMetadataParameters {
                repository_id: 4242,
            }),
        })?
        .prepared_request_id;
    assert_eq!(
        client.invoke_operation(id),
        Err(ErrorCode::ApprovalRequired)
    );
    client.request_operation_approval(id)?;
    let review = control.inspect_operation_approval(id)?;
    // Fixed trusted-host test workflow; this is not authenticated human presence.
    control.approve_operation_reviewed(id, &review)?;
    let result = client.invoke_operation(id)?;
    assert_eq!(result.state, Lifecycle::Succeeded);
    assert_eq!(client.invoke_operation(id)?, result);
    println!("{}", serde_json::to_string_pretty(&result)?);
    println!(
        "Mock provider revocation: {:?}",
        control.revoke_provider_tokens()?
    );
    drop(client);
    drop(control);
    println!(
        "{}",
        serde_json::to_string_pretty(&github::inspect_synthetic_intents(std::path::Path::new(
            path
        ))?)?
    );
    Ok(())
}
#[cfg(not(feature = "signing-spike"))]
fn main() {
    eprintln!("Enable signing-spike for this disposable-key experiment.");
    std::process::exit(2);
}
