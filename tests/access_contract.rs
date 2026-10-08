//! Acceptance regressions for the existing synthetic wire/core trust boundary.
//! These do not implement or test HTTP authentication, a reverse proxy or network ACLs.
use aegis::{
    fake::FakeProvider,
    mcp::{Adapter, Bridge},
    protocol, *,
};
use serde_json::{json, Value};
use std::sync::Arc;

fn fixture() -> (Control, AgentClient, Arc<FakeProvider>) {
    let provider = Arc::new(FakeProvider::default());
    let (control, client) = Control::synthetic(
        SyntheticSetup {
            principal: PrincipalId::new("enrolled-agent").unwrap(),
            ..SyntheticSetup::default()
        },
        Arc::new(ManualClock::default()),
        provider.clone(),
    )
    .unwrap();
    (control, client, provider)
}
fn prepare(version: u32) -> Value {
    let mut value = json!({"version":version,"action":{"method":"prepare_operation","params":{"request_id":"identity-contract","profile_id":"issue-status"}}});
    if version == 1 {
        value["action"]["params"]["parameters"] = json!({"repository_id":4242,"issue_number":7});
    } else {
        value["action"]["params"]["operation"] = json!({"kind":"synthetic.issue-status.v1","parameters":{"repository_id":4242,"issue_number":7}});
    }
    value
}
fn call(client: &AgentClient, value: &Value) -> protocol::Response {
    protocol::handle(client, &serde_json::to_vec(value).unwrap())
}
fn action(method: &str, id: u64) -> Value {
    json!({"version":2,"action":{"method":method,"params":{"prepared_request_id":id}}})
}
#[test]
fn wire_identity_network_and_proxy_claims_cannot_allocate_authority() {
    let claims = [
        ("principal", json!("human-admin")),
        ("authenticated", json!(true)),
        ("role", json!("administrator")),
        ("client_certificate", json!("claimed-certificate")),
        ("source_ip", json!("127.0.0.1")),
        ("private_network", json!(true)),
        ("network_member", json!(true)),
        ("Forwarded", json!("for=127.0.0.1;proto=https")),
        ("X-Forwarded-For", json!("10.0.0.1")),
        ("X-Authenticated-User", json!("human-admin")),
        ("trusted_proxy", json!(true)),
        ("acl_allowed", json!(true)),
    ];
    for version in [1, 2] {
        let (control, client, provider) = fixture();
        for (field, value) in &claims {
            for location in ["", "/action", "/action/params"] {
                let mut request = prepare(version);
                request
                    .pointer_mut(location)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert((*field).into(), value.clone());
                assert_eq!(
                    call(&client, &request).error,
                    Some(ErrorCode::InvalidRequest)
                );
            }
        }
        assert_eq!(client.operation_status(1), Err(ErrorCode::NotFound));
        assert_eq!(control.remaining_uses().unwrap(), 20);
        assert_eq!(provider.calls(), 0);
        let valid = call(&client, &prepare(version));
        assert_eq!(valid.result.unwrap()["prepared_request_id"], 1);
        assert_eq!(client.invoke_operation(1), Err(ErrorCode::ApprovalRequired));
    }
}
#[test]
fn alleged_acl_allow_and_admin_methods_cannot_mutate_a_pending_request() {
    let (control, client, provider) = fixture();
    let id = call(&client, &prepare(2)).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    client.request_operation_approval(id).unwrap();
    for method in ["invoke_approved", "get_run_status", "cancel"] {
        for field in [
            "acl_allowed",
            "approved",
            "human_present",
            "principal",
            "trusted_proxy",
        ] {
            let mut request = action(method, id);
            request["action"]["params"][field] = json!(true);
            assert_eq!(
                call(&client, &request).error,
                Some(ErrorCode::InvalidRequest)
            );
        }
    }
    for method in [
        "approve",
        "set_acl",
        "enroll_agent",
        "trust_proxy",
        "get_secret",
        "proxy_request",
    ] {
        assert_eq!(
            call(&client, &action(method, id)).error,
            Some(ErrorCode::InvalidRequest)
        );
    }
    assert_eq!(
        client.operation_status(id).unwrap().state,
        Lifecycle::AwaitingApproval
    );
    assert_eq!(
        client.invoke_operation(id),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(control.remaining_uses().unwrap(), 20);
    assert_eq!(provider.calls(), 0);
}
struct Local(AgentClient);
impl Bridge for Local {
    fn exchange(&mut self, request: &Value) -> protocol::Response {
        call(&self.0, request)
    }
}
fn rpc(id: u64, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})).unwrap()
}
#[test]
fn mcp_display_identity_cannot_change_the_host_bound_principal_or_approve() {
    for label in ["human-admin", "trusted-proxy", "private-network-owner"] {
        let (control, client, provider) = fixture();
        let mut adapter = Adapter::new_v2(Local(client.clone()));
        let initialized = adapter.handle(&rpc(1,"initialize",json!({"protocolVersion":"2025-11-25","capabilities":{"authenticated":true,"principal":"human-admin","private_network":true},"clientInfo":{"name":label,"title":"trusted administrator","version":"synthetic"}}))).unwrap();
        assert!(initialized.get("result").is_some());
        let prepared = adapter
            .handle(&rpc(
                2,
                "tools/call",
                json!({"name":"prepare_operation","arguments":prepare(2)["action"]["params"]}),
            ))
            .unwrap();
        let response: Value =
            serde_json::from_str(prepared["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        let id = response["result"]["prepared_request_id"].as_u64().unwrap();
        client.request_operation_approval(id).unwrap();
        let review = control.inspect_operation_approval(id).unwrap();
        assert_eq!(
            review.principal,
            PrincipalId::new("enrolled-agent").unwrap()
        );
        assert_eq!(
            client.invoke_operation(id),
            Err(ErrorCode::ApprovalRequired)
        );
        assert_eq!(provider.calls(), 0);
    }
}
#[test]
fn reviewed_subject_credential_resource_and_context_must_match_exactly() {
    let (control, client, provider) = fixture();
    let id = call(&client, &prepare(2)).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    client.request_operation_approval(id).unwrap();
    let review = control.inspect_operation_approval(id).unwrap();
    for change in [
        |r: &mut OperationApprovalView| r.principal = PrincipalId::new("human-admin").unwrap(),
        |r: &mut OperationApprovalView| r.session += 1,
        |r: &mut OperationApprovalView| r.policy_generation += 1,
        |r: &mut OperationApprovalView| r.limits.maximum_seconds += 1,
        |r: &mut OperationApprovalView| r.remaining_uses += 1,
        |r: &mut OperationApprovalView| r.expires_at += 1,
        |r: &mut OperationApprovalView| {
            if let OperationProfile::IssueStatus(p) = &mut r.profile {
                p.credential.version += 1;
            }
        },
        |r: &mut OperationApprovalView| {
            if let OperationIntent::IssueStatus(p) = &mut r.operation {
                p.repository_id = 999;
            }
        },
    ] {
        let mut changed = review.clone();
        change(&mut changed);
        assert_eq!(
            control.approve_operation_reviewed(id, &changed),
            Err(ErrorCode::ApprovalRequired)
        );
    }
    let (other_control, other_client, _) = fixture();
    let other_id = call(&other_client, &prepare(2)).result.unwrap()["prepared_request_id"]
        .as_u64()
        .unwrap();
    other_client.request_operation_approval(other_id).unwrap();
    let other_review = other_control.inspect_operation_approval(other_id).unwrap();
    assert_eq!(
        control.approve_operation_reviewed(id, &other_review),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(provider.calls(), 0);
    control.approve_operation_reviewed(id, &review).unwrap();
    control.revoke().unwrap();
    assert_eq!(client.invoke_operation(id), Err(ErrorCode::GrantRevoked));
    assert_eq!(provider.calls(), 0);
    assert_eq!(control.remaining_uses().unwrap(), 20);
}
