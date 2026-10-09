//! Fixed synthetic GitHub operation through the main broker and schema-2 journal.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aegis::*;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        eprintln!("Usage: github_broker_spike <new-absolute-journal-directory>");
        std::process::exit(2);
    };
    let (control, client) = Control::synthetic_github(
        OperationSetup::synthetic_github(),
        std::sync::Arc::new(MonotonicClock::default()),
        std::path::Path::new(path),
    )?;
    let prepared = client.prepare_operation(OperationPrepareInput {
        request_id: RequestId::new("broker-demo")?,
        profile_id: ProfileId::new("github-metadata")?,
        operation: OperationIntent::GithubMetadata(GithubMetadataParameters {
            repository_id: 4242,
        }),
    })?;
    let id = prepared.prepared_request_id;
    assert_eq!(
        client.invoke_operation(id),
        Err(ErrorCode::ApprovalRequired)
    );
    client.request_operation_approval(id)?;
    let review = control.inspect_operation_approval(id)?;
    println!("Synthetic trusted-host review only, no proof of human presence: {review:?}");
    control.approve_operation_reviewed(id, &review)?;
    let result = client.invoke_operation(id)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    assert_eq!(client.invoke_operation(id)?, result);
    println!(
        "Mock token revocation: {:?}",
        control.revoke_provider_tokens()?
    );
    drop(client);
    drop(control);
    println!(
        "{}",
        serde_json::to_string_pretty(&aegis::github::inspect_synthetic_intents(
            std::path::Path::new(path)
        )?)?
    );
    Ok(())
}
