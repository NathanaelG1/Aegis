//! Policy and lifecycle evidence for the synthetic embedding API only.
//! These tests make no claims about OS isolation, private human presence, network
//! transports, or durable budgets. Custom executors are trusted test fixtures.

use aegis::fake::{Dispatch, Executor, FakeProvider, ProviderOutcome, RawStatus, SYNTHETIC_CANARY};
use aegis::{
    AgentClient, ApprovalMode, Control, ErrorCode, IssueState, Lifecycle, ManualClock, Parameters,
    PrepareInput, PrincipalId, Profile, ProfileId, RequestId, SyntheticSetup,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Duration;

struct Harness {
    control: Control,
    client: AgentClient,
    clock: Arc<ManualClock>,
    provider: Arc<FakeProvider>,
}

fn harness(setup: SyntheticSetup) -> Harness {
    let clock = Arc::new(ManualClock::default());
    let provider = Arc::new(FakeProvider::default());
    let (control, client) = Control::synthetic(setup, clock.clone(), provider.clone()).unwrap();
    Harness {
        control,
        client,
        clock,
        provider,
    }
}

fn input(request_id: &str, issue_number: u32) -> PrepareInput {
    PrepareInput {
        request_id: RequestId::new(request_id).unwrap(),
        profile_id: ProfileId::new("issue-status").unwrap(),
        parameters: Parameters {
            repository_id: 4242,
            issue_number,
        },
    }
}

fn prepare_approved(control: &Control, client: &AgentClient, request_id: &str) -> u64 {
    let prepared = client.prepare(input(request_id, 7)).unwrap();
    if prepared.state == Lifecycle::Prepared {
        client
            .request_approval(prepared.prepared_request_id)
            .unwrap();
        control.approve(prepared.prepared_request_id).unwrap();
    }
    prepared.prepared_request_id
}

fn assert_error<T>(result: Result<T, ErrorCode>, expected: ErrorCode) {
    match result {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("expected stable error {expected}"),
    }
}

fn valid_status(dispatch: &Dispatch) -> ProviderOutcome {
    ProviderOutcome::Status(RawStatus {
        repository_id: dispatch.parameters.repository_id,
        issue_number: dispatch.parameters.issue_number,
        state: "open".into(),
    })
}

/// A provider that reports entry before waiting. Tests hold a release guard so
/// a failed assertion cannot leave the provider thread blocked indefinitely.
struct BlockingProvider {
    calls: AtomicUsize,
    entered: mpsc::Sender<()>,
    released: Mutex<bool>,
    wake: Condvar,
}

impl BlockingProvider {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>) {
        let (entered, receiver) = mpsc::channel();
        (
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                entered,
                released: Mutex::new(false),
                wake: Condvar::new(),
            }),
            receiver,
        )
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Executor for BlockingProvider {
    fn execute(&self, dispatch: &Dispatch) -> ProviderOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
        valid_status(dispatch)
    }
}

struct ReleaseOnDrop(Arc<BlockingProvider>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn await_dispatch(receiver: &mpsc::Receiver<()>) {
    receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("provider should be entered after dispatch");
}

#[test]
fn discovery_is_an_unverified_catalog_and_does_not_dispatch() {
    let h = harness(SyntheticSetup::default());
    let catalog = h.client.discover_operations();
    assert!(!catalog.verified);
    assert_eq!(catalog.profile_id, Profile::synthetic().id);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn request_pauses_for_control_approval_and_resumes_with_a_projection() {
    let h = harness(SyntheticSetup::default());
    let prepared = h.client.prepare(input("approval-resume", 7)).unwrap();
    let id = prepared.prepared_request_id;
    assert_eq!(prepared.state, Lifecycle::Prepared);
    assert_error(h.client.invoke(id), ErrorCode::ApprovalRequired);
    assert_eq!(h.provider.calls(), 0);

    let awaiting = h.client.request_approval(id).unwrap();
    assert_eq!(awaiting.state, Lifecycle::AwaitingApproval);
    assert_eq!(h.client.request_approval(id).unwrap(), awaiting);
    assert_error(h.client.invoke(id), ErrorCode::ApprovalRequired);
    let display = h.control.inspect_approval(id).unwrap();
    assert_eq!(
        display.principal,
        PrincipalId::new("synthetic-host").unwrap()
    );
    assert_eq!(display.session, 1);
    assert_eq!(display.profile, Profile::synthetic());
    assert_eq!(display.parameters, input("approval-resume", 7).parameters);
    assert_eq!(display.policy_generation, 1);
    assert_eq!(display.expires_at, 15);
    assert_eq!(display.remaining_uses, 20);
    assert_eq!(h.control.approve(id).unwrap().state, Lifecycle::Approved);

    let completed = h.client.invoke(id).unwrap();
    assert_eq!(completed.state, Lifecycle::Succeeded);
    assert_eq!(completed.error, None);
    let result = completed.result.as_ref().unwrap();
    assert_eq!(result.repository_id, 4242);
    assert_eq!(result.issue_number, 7);
    assert_eq!(result.state, IssueState::Open);
    assert_eq!(h.control.remaining_uses().unwrap(), 19);
    assert_eq!(h.provider.calls(), 1);
    assert_eq!(h.client.status(id).unwrap(), completed);
    assert!(!serde_json::to_string(&completed)
        .unwrap()
        .contains(SYNTHETIC_CANARY));
    assert!(!format!("{completed:?}").contains(SYNTHETIC_CANARY));
}

#[test]
fn bounded_session_approval_is_selected_by_the_trusted_setup() {
    let h = harness(SyntheticSetup {
        approval_mode: ApprovalMode::BoundedSession,
        ..SyntheticSetup::default()
    });
    let prepared = h.client.prepare(input("bounded", 2)).unwrap();
    assert_eq!(prepared.state, Lifecycle::Approved);
    let completed = h.client.invoke(prepared.prepared_request_id).unwrap();
    assert_eq!(completed.result.unwrap().state, IssueState::Closed);
    assert_eq!(h.provider.calls(), 1);
}

#[test]
fn resource_and_operation_denials_precede_provider_work_and_budget_use() {
    let h = harness(SyntheticSetup::default());
    let mut another_resource = input("resource-denied", 7);
    another_resource.parameters.repository_id = 9000;
    assert_error(h.client.prepare(another_resource), ErrorCode::ScopeDenied);
    let mut another_operation = input("operation-denied", 7);
    another_operation.profile_id = ProfileId::new("delete-repository").unwrap();
    assert_error(h.client.prepare(another_operation), ErrorCode::ScopeDenied);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn invalid_numeric_parameters_cannot_prepare_a_request() {
    let h = harness(SyntheticSetup::default());
    for parameters in [
        Parameters {
            repository_id: 0,
            issue_number: 7,
        },
        Parameters {
            repository_id: 4242,
            issue_number: 0,
        },
    ] {
        let mut invalid = input("invalid-number", 7);
        invalid.parameters = parameters;
        assert_error(h.client.prepare(invalid), ErrorCode::InvalidRequest);
    }
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn approval_cannot_skip_the_pending_request_transition() {
    let h = harness(SyntheticSetup::default());
    let prepared = h.client.prepare(input("not-pending", 7)).unwrap();
    assert_error(
        h.control.approve(prepared.prepared_request_id),
        ErrorCode::InvalidRequest,
    );
    assert_error(
        h.client.invoke(prepared.prepared_request_id),
        ErrorCode::ApprovalRequired,
    );
    assert_eq!(h.provider.calls(), 0);
}

#[test]
fn changed_profile_revision_invalidates_prepared_and_approved_requests() {
    let h = harness(SyntheticSetup::default());
    let id = prepare_approved(&h.control, &h.client, "revision-change");
    let mut revised = Profile::synthetic();
    revised.revision = 2;
    h.control.replace_profile(revised).unwrap();
    assert_error(h.control.approve(id), ErrorCode::PolicyChanged);
    assert_error(h.client.invoke(id), ErrorCode::PolicyChanged);
    assert_error(
        h.client.prepare(input("new-revision", 8)),
        ErrorCode::PolicyChanged,
    );
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn changed_resource_invalidates_an_approved_request() {
    let h = harness(SyntheticSetup::default());
    let id = prepare_approved(&h.control, &h.client, "resource-change");
    let mut revised = Profile::synthetic();
    revised.repository_id = 9000;
    h.control.replace_profile(revised).unwrap();
    assert_error(h.client.invoke(id), ErrorCode::PolicyChanged);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn changed_exact_credential_version_does_not_follow_rotation() {
    let h = harness(SyntheticSetup::default());
    let id = prepare_approved(&h.control, &h.client, "credential-change");
    let mut revised = Profile::synthetic();
    revised.credential.version = 2;
    h.control.replace_profile(revised).unwrap();
    assert_error(h.client.invoke(id), ErrorCode::PolicyChanged);
    assert_error(
        h.client.prepare(input("rotated", 8)),
        ErrorCode::PolicyChanged,
    );
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn changed_generation_invalidates_a_plan_even_if_profile_fields_match() {
    let h = harness(SyntheticSetup::default());
    let id = prepare_approved(&h.control, &h.client, "generation-change");
    h.control.replace_profile(Profile::synthetic()).unwrap();
    assert_error(h.control.approve(id), ErrorCode::PolicyChanged);
    assert_error(h.client.invoke(id), ErrorCode::PolicyChanged);
    assert_eq!(h.provider.calls(), 0);
}

#[test]
fn unknown_adapter_output_contract_and_nonfixture_credentials_fail_setup() {
    let clock = Arc::new(ManualClock::default());
    let provider = Arc::new(FakeProvider::default());
    let mut invalid_profiles = Vec::new();
    let mut profile = Profile::synthetic();
    profile.adapter_contract = 2;
    invalid_profiles.push(profile);
    let mut profile = Profile::synthetic();
    profile.output_contract = 2;
    invalid_profiles.push(profile);
    let mut profile = Profile::synthetic();
    profile.credential.secret_id = "actual-secret-not-accepted".into();
    invalid_profiles.push(profile);
    let mut profile = Profile::synthetic();
    profile.credential.version = 0;
    invalid_profiles.push(profile);
    for profile in invalid_profiles {
        assert_error(
            Control::synthetic(
                SyntheticSetup {
                    profile,
                    ..SyntheticSetup::default()
                },
                clock.clone(),
                provider.clone(),
            ),
            ErrorCode::InvalidRequest,
        );
    }
    assert_eq!(provider.calls(), 0);
}

#[test]
fn same_request_id_returns_the_original_run_across_its_lifecycle() {
    let h = harness(SyntheticSetup::default());
    let request = input("idempotent", 7);
    let prepared = h.client.prepare(request.clone()).unwrap();
    assert_eq!(h.client.prepare(request.clone()).unwrap(), prepared);
    let id = prepared.prepared_request_id;
    let awaiting = h.client.request_approval(id).unwrap();
    assert_eq!(h.client.prepare(request.clone()).unwrap(), awaiting);
    let approved = h.control.approve(id).unwrap();
    assert_eq!(h.client.prepare(request.clone()).unwrap(), approved);
    let complete = h.client.invoke(id).unwrap();
    assert_eq!(h.client.prepare(request).unwrap(), complete);
    assert_eq!(h.client.invoke(id).unwrap(), complete);
    assert_eq!(h.client.request_approval(id).unwrap(), complete);
    assert_eq!(h.provider.calls(), 1);
    assert_eq!(h.control.remaining_uses().unwrap(), 19);
}

#[test]
fn same_request_id_with_different_canonical_fields_conflicts() {
    let h = harness(SyntheticSetup::default());
    let original = input("conflicting-id", 7);
    h.client.prepare(original.clone()).unwrap();
    let mut changes = Vec::new();
    let mut changed = original.clone();
    changed.parameters.issue_number = 8;
    changes.push(changed);
    let mut changed = original.clone();
    changed.parameters.repository_id = 9000;
    changes.push(changed);
    let mut changed = original;
    changed.profile_id = ProfileId::new("another-profile").unwrap();
    changes.push(changed);
    for changed in changes {
        assert_error(h.client.prepare(changed), ErrorCode::RequestIdConflict);
    }
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn simultaneous_requests_cannot_both_consume_the_final_use() {
    let h = harness(SyntheticSetup {
        uses: 1,
        ..SyntheticSetup::default()
    });
    let first = prepare_approved(&h.control, &h.client, "final-use-a");
    let second = prepare_approved(&h.control, &h.client, "final-use-b");
    let start = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for id in [first, second] {
        let client = h.client.clone();
        let start = start.clone();
        handles.push(thread::spawn(move || {
            start.wait();
            client.invoke(id)
        }));
    }
    start.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(view) if view.state == Lifecycle::Succeeded))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ErrorCode::BudgetExhausted)))
            .count(),
        1
    );
    assert_eq!(h.provider.calls(), 1);
    assert_eq!(h.control.remaining_uses().unwrap(), 0);
    assert_error(
        h.client.prepare(input("after-final", 9)),
        ErrorCode::BudgetExhausted,
    );
}

#[test]
fn duplicate_in_flight_invocation_reports_dispatch_without_repeating_work() {
    let (provider, receiver) = BlockingProvider::new();
    let _release = ReleaseOnDrop(provider.clone());
    let clock = Arc::new(ManualClock::default());
    let (control, client) =
        Control::synthetic(SyntheticSetup::default(), clock, provider.clone()).unwrap();
    let id = prepare_approved(&control, &client, "in-flight-retry");
    let worker = client.clone();
    let handle = thread::spawn(move || worker.invoke(id));
    await_dispatch(&receiver);
    assert_eq!(client.invoke(id).unwrap().state, Lifecycle::Dispatched);
    assert_eq!(client.status(id).unwrap().state, Lifecycle::Dispatched);
    assert_eq!(
        client.prepare(input("in-flight-retry", 7)).unwrap().state,
        Lifecycle::Dispatched
    );
    assert_eq!(provider.calls(), 1);
    assert_eq!(control.remaining_uses().unwrap(), 19);
    provider.release();
    let completed = handle.join().unwrap().unwrap();
    assert_eq!(client.invoke(id).unwrap(), completed);
    assert_eq!(provider.calls(), 1);
}

#[test]
fn cancellation_at_every_predispatch_stage_prevents_execution() {
    for stage in [
        Lifecycle::Prepared,
        Lifecycle::AwaitingApproval,
        Lifecycle::Approved,
    ] {
        let h = harness(SyntheticSetup::default());
        let id = h
            .client
            .prepare(input("cancel", 7))
            .unwrap()
            .prepared_request_id;
        if stage != Lifecycle::Prepared {
            h.client.request_approval(id).unwrap();
        }
        if stage == Lifecycle::Approved {
            h.control.approve(id).unwrap();
        }
        let canceled = h.client.cancel(id).unwrap();
        assert_eq!(canceled.state, Lifecycle::Canceled);
        assert_eq!(canceled.error, Some(ErrorCode::RequestCanceled));
        assert_eq!(h.client.cancel(id).unwrap(), canceled);
        assert_eq!(h.client.invoke(id).unwrap(), canceled);
        assert_eq!(h.client.request_approval(id).unwrap(), canceled);
        assert_error(h.control.approve(id), ErrorCode::RequestCanceled);
        assert_eq!(h.provider.calls(), 0);
        assert_eq!(h.control.remaining_uses().unwrap(), 20);
    }
}

#[test]
fn cancellation_after_dispatch_does_not_claim_to_retract_an_effect() {
    let (provider, receiver) = BlockingProvider::new();
    let _release = ReleaseOnDrop(provider.clone());
    let clock = Arc::new(ManualClock::default());
    let (control, client) =
        Control::synthetic(SyntheticSetup::default(), clock, provider.clone()).unwrap();
    let id = prepare_approved(&control, &client, "cancel-after-dispatch");
    let worker = client.clone();
    let handle = thread::spawn(move || worker.invoke(id));
    await_dispatch(&receiver);
    assert_eq!(client.cancel(id).unwrap().state, Lifecycle::Dispatched);
    provider.release();
    assert_eq!(handle.join().unwrap().unwrap().state, Lifecycle::Succeeded);
    assert_eq!(provider.calls(), 1);
    assert_eq!(control.remaining_uses().unwrap(), 19);
}

#[test]
fn request_expiry_at_the_exact_boundary_prevents_dispatch_without_consuming_use() {
    let h = harness(SyntheticSetup::default());
    let id = prepare_approved(&h.control, &h.client, "expired");
    h.clock.set(15);
    assert_error(h.client.invoke(id), ErrorCode::RequestExpired);
    let expired = h.client.status(id).unwrap();
    assert_eq!(expired.state, Lifecycle::Expired);
    assert_eq!(expired.error, Some(ErrorCode::RequestExpired));
    assert_eq!(h.client.invoke(id).unwrap(), expired);
    assert_eq!(h.client.prepare(input("expired", 7)).unwrap(), expired);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn expired_pending_requests_cannot_be_approved() {
    let h = harness(SyntheticSetup::default());
    let id = h
        .client
        .prepare(input("pending-expiry", 7))
        .unwrap()
        .prepared_request_id;
    h.client.request_approval(id).unwrap();
    h.clock.set(15);
    assert_error(h.control.approve(id), ErrorCode::RequestExpired);
    assert_eq!(h.client.status(id).unwrap().state, Lifecycle::Expired);
    assert_eq!(h.provider.calls(), 0);
}

#[test]
fn revocation_before_dispatch_blocks_preparation_approval_and_execution() {
    let h = harness(SyntheticSetup::default());
    let approved = prepare_approved(&h.control, &h.client, "revoke-approved");
    let awaiting = h
        .client
        .prepare(input("revoke-awaiting", 8))
        .unwrap()
        .prepared_request_id;
    h.client.request_approval(awaiting).unwrap();
    h.control.revoke().unwrap();
    assert_error(
        h.client.prepare(input("revoke-new", 9)),
        ErrorCode::GrantRevoked,
    );
    assert_error(h.control.approve(awaiting), ErrorCode::GrantRevoked);
    assert_error(h.client.invoke(approved), ErrorCode::GrantRevoked);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn revocation_after_dispatch_allows_completion_but_prevents_new_dispatch() {
    let (provider, receiver) = BlockingProvider::new();
    let _release = ReleaseOnDrop(provider.clone());
    let clock = Arc::new(ManualClock::default());
    let (control, client) =
        Control::synthetic(SyntheticSetup::default(), clock, provider.clone()).unwrap();
    let first = prepare_approved(&control, &client, "revoked-in-flight");
    let second = prepare_approved(&control, &client, "revoked-not-dispatched");
    let worker = client.clone();
    let handle = thread::spawn(move || worker.invoke(first));
    await_dispatch(&receiver);
    control.revoke().unwrap();
    assert_error(client.invoke(second), ErrorCode::GrantRevoked);
    assert_error(
        client.prepare(input("revoked-new", 9)),
        ErrorCode::GrantRevoked,
    );
    provider.release();
    let completed = handle.join().unwrap().unwrap();
    assert_eq!(completed.state, Lifecycle::Succeeded);
    assert_eq!(client.invoke(first).unwrap(), completed);
    assert_eq!(provider.calls(), 1);
    assert_eq!(control.remaining_uses().unwrap(), 19);
}

#[test]
fn stop_invalidates_all_cloned_agent_authority() {
    let h = harness(SyntheticSetup::default());
    let id = prepare_approved(&h.control, &h.client, "stop");
    let clone = h.client.clone();
    h.control.stop().unwrap();
    assert_error(h.client.invoke(id), ErrorCode::SessionExpired);
    assert_error(clone.invoke(id), ErrorCode::SessionExpired);
    assert_error(
        clone.prepare(input("after-stop", 8)),
        ErrorCode::SessionExpired,
    );
    assert_error(clone.request_approval(id), ErrorCode::SessionExpired);
    assert_error(clone.cancel(id), ErrorCode::SessionExpired);
    assert_error(clone.status(id), ErrorCode::SessionExpired);
    assert_error(h.control.approve(id), ErrorCode::SessionExpired);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn polling_preparation_approval_requests_and_denials_do_not_refresh_idle() {
    let h = harness(SyntheticSetup {
        idle_seconds: 20,
        maximum_seconds: 100,
        ..SyntheticSetup::default()
    });
    let id = h
        .client
        .prepare(input("idle-poll", 7))
        .unwrap()
        .prepared_request_id;
    h.clock.set(5);
    h.client.status(id).unwrap();
    h.clock.set(10);
    h.client.request_approval(id).unwrap();
    h.clock.set(14);
    h.control.approve(id).unwrap();
    h.clock.set(19);
    h.client.status(id).unwrap();
    h.client.prepare(input("idle-new-request", 8)).unwrap();
    let mut denied = input("idle-denied", 9);
    denied.parameters.repository_id = 9000;
    assert_error(h.client.prepare(denied), ErrorCode::ScopeDenied);
    h.clock.set(20);
    assert_error(h.client.status(id), ErrorCode::SessionExpired);
    assert_error(
        h.client.prepare(input("idle-after-expiry", 10)),
        ErrorCode::SessionExpired,
    );
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn successful_activity_refreshes_idle_but_never_the_maximum_lifetime() {
    let h = harness(SyntheticSetup {
        idle_seconds: 20,
        maximum_seconds: 50,
        ..SyntheticSetup::default()
    });
    h.clock.set(19);
    let first = prepare_approved(&h.control, &h.client, "idle-success-first");
    h.client.invoke(first).unwrap();
    h.clock.set(20);
    assert_eq!(h.client.status(first).unwrap().state, Lifecycle::Succeeded);
    h.clock.set(38);
    let second = prepare_approved(&h.control, &h.client, "idle-success-second");
    h.client.invoke(second).unwrap();
    h.clock.set(49);
    let third = prepare_approved(&h.control, &h.client, "idle-success-third");
    h.client.invoke(third).unwrap();
    h.clock.set(50);
    assert_error(h.client.status(third), ErrorCode::SessionExpired);
    assert_error(
        h.client.prepare(input("maximum-bound", 9)),
        ErrorCode::SessionExpired,
    );
    assert_eq!(h.provider.calls(), 3);
    assert_eq!(h.control.remaining_uses().unwrap(), 17);
}

#[test]
fn successful_provider_completion_after_idle_expiry_does_not_revive_authority() {
    let (provider, receiver) = BlockingProvider::new();
    let _release = ReleaseOnDrop(provider.clone());
    let clock = Arc::new(ManualClock::default());
    let setup = SyntheticSetup {
        idle_seconds: 20,
        maximum_seconds: 100,
        ..SyntheticSetup::default()
    };
    let (control, client) = Control::synthetic(setup, clock.clone(), provider.clone()).unwrap();
    clock.set(19);
    let id = prepare_approved(&control, &client, "late-idle-completion");
    let worker = client.clone();
    let handle = thread::spawn(move || worker.invoke(id));
    await_dispatch(&receiver);
    clock.set(20);
    provider.release();
    assert_eq!(handle.join().unwrap().unwrap().state, Lifecycle::Succeeded);
    assert_error(
        client.prepare(input("idle-resurrection", 8)),
        ErrorCode::SessionExpired,
    );
    assert_eq!(provider.calls(), 1);
    assert_eq!(control.remaining_uses().unwrap(), 19);
}

#[test]
fn provider_completion_observes_time_so_later_clock_rollback_invalidates_authority() {
    let (provider, receiver) = BlockingProvider::new();
    let _release = ReleaseOnDrop(provider.clone());
    let clock = Arc::new(ManualClock::default());
    let (control, client) =
        Control::synthetic(SyntheticSetup::default(), clock.clone(), provider.clone()).unwrap();
    clock.set(1);
    let id = prepare_approved(&control, &client, "completion-clock");
    let worker = client.clone();
    let handle = thread::spawn(move || worker.invoke(id));
    await_dispatch(&receiver);
    clock.set(5);
    provider.release();
    assert_eq!(handle.join().unwrap().unwrap().state, Lifecycle::Succeeded);
    clock.set(3);
    assert_error(
        client.prepare(input("clock-rollback", 8)),
        ErrorCode::SessionExpired,
    );
    clock.set(6);
    assert_error(
        client.prepare(input("rollback-stays-invalid", 8)),
        ErrorCode::SessionExpired,
    );
    assert_eq!(provider.calls(), 1);
}

#[test]
fn backwards_clock_before_dispatch_permanently_invalidates_the_session() {
    let h = harness(SyntheticSetup::default());
    h.clock.set(10);
    let id = prepare_approved(&h.control, &h.client, "clock-before-dispatch");
    h.clock.set(9);
    assert_error(h.client.invoke(id), ErrorCode::SessionExpired);
    h.clock.set(11);
    assert_error(h.client.invoke(id), ErrorCode::SessionExpired);
    assert_eq!(h.provider.calls(), 0);
    assert_eq!(h.control.remaining_uses().unwrap(), 20);
}

#[test]
fn request_retention_capacity_is_bounded_and_deduplication_is_preserved() {
    let h = harness(SyntheticSetup {
        maximum_requests: 2,
        ..SyntheticSetup::default()
    });
    let first_input = input("capacity-first", 7);
    let first = h.client.prepare(first_input.clone()).unwrap();
    let second = h.client.prepare(input("capacity-second", 8)).unwrap();
    h.client.cancel(second.prepared_request_id).unwrap();
    assert_error(
        h.client.prepare(input("capacity-third", 9)),
        ErrorCode::CapacityExceeded,
    );
    assert_eq!(h.client.prepare(first_input).unwrap(), first);
    assert_eq!(h.provider.calls(), 0);
}

#[test]
fn concurrency_capacity_is_enforced_and_released_after_completion() {
    let (provider, receiver) = BlockingProvider::new();
    let _release = ReleaseOnDrop(provider.clone());
    let clock = Arc::new(ManualClock::default());
    let setup = SyntheticSetup {
        maximum_concurrent: 1,
        ..SyntheticSetup::default()
    };
    let (control, client) = Control::synthetic(setup, clock, provider.clone()).unwrap();
    let first = prepare_approved(&control, &client, "concurrency-first");
    let second = prepare_approved(&control, &client, "concurrency-second");
    let worker = client.clone();
    let handle = thread::spawn(move || worker.invoke(first));
    await_dispatch(&receiver);
    assert_error(client.invoke(second), ErrorCode::CapacityExceeded);
    assert_eq!(provider.calls(), 1);
    assert_eq!(control.remaining_uses().unwrap(), 19);
    provider.release();
    assert_eq!(handle.join().unwrap().unwrap().state, Lifecycle::Succeeded);
    assert_eq!(client.invoke(second).unwrap().state, Lifecycle::Succeeded);
    assert_eq!(provider.calls(), 2);
    assert_eq!(control.remaining_uses().unwrap(), 18);
}

#[derive(Clone, Copy)]
enum FixtureOutcome {
    WrongRepository,
    WrongIssue,
    UnexpectedState,
    Unavailable,
    Unknown,
    Panic,
}

struct OutcomeProvider {
    outcome: FixtureOutcome,
    calls: AtomicUsize,
}

impl OutcomeProvider {
    fn new(outcome: FixtureOutcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Executor for OutcomeProvider {
    fn execute(&self, dispatch: &Dispatch) -> ProviderOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            FixtureOutcome::WrongRepository => ProviderOutcome::Status(RawStatus {
                repository_id: 9000,
                issue_number: dispatch.parameters.issue_number,
                state: "open".into(),
            }),
            FixtureOutcome::WrongIssue => ProviderOutcome::Status(RawStatus {
                repository_id: dispatch.parameters.repository_id,
                issue_number: dispatch.parameters.issue_number + 1,
                state: "open".into(),
            }),
            FixtureOutcome::UnexpectedState => ProviderOutcome::Status(RawStatus {
                repository_id: dispatch.parameters.repository_id,
                issue_number: dispatch.parameters.issue_number,
                state: SYNTHETIC_CANARY.into(),
            }),
            FixtureOutcome::Unavailable => ProviderOutcome::Unavailable,
            FixtureOutcome::Unknown => ProviderOutcome::Unknown,
            FixtureOutcome::Panic => panic!("synthetic executor fault"),
        }
    }
}

fn outcome_harness(
    outcome: FixtureOutcome,
    setup: SyntheticSetup,
) -> (Control, AgentClient, Arc<ManualClock>, Arc<OutcomeProvider>) {
    let clock = Arc::new(ManualClock::default());
    let provider = OutcomeProvider::new(outcome);
    let (control, client) = Control::synthetic(setup, clock.clone(), provider.clone()).unwrap();
    (control, client, clock, provider)
}

#[test]
fn invalid_provider_identifiers_and_state_are_rejected_without_raw_output() {
    for outcome in [
        FixtureOutcome::WrongRepository,
        FixtureOutcome::WrongIssue,
        FixtureOutcome::UnexpectedState,
    ] {
        let (control, client, _, provider) = outcome_harness(outcome, SyntheticSetup::default());
        let id = prepare_approved(&control, &client, "invalid-provider");
        let failed = client.invoke(id).unwrap();
        assert_eq!(failed.state, Lifecycle::Failed);
        assert_eq!(failed.error, Some(ErrorCode::InvalidProviderResult));
        assert_eq!(failed.result, None);
        assert!(!serde_json::to_string(&failed)
            .unwrap()
            .contains(SYNTHETIC_CANARY));
        assert!(!format!("{failed:?}").contains(SYNTHETIC_CANARY));
        assert_eq!(client.invoke(id).unwrap(), failed);
        assert_eq!(provider.calls(), 1);
        assert_eq!(control.remaining_uses().unwrap(), 19);
    }
}

fn assert_terminal_does_not_refund_or_retry(
    outcome: FixtureOutcome,
    state: Lifecycle,
    error: ErrorCode,
) {
    let setup = SyntheticSetup {
        uses: 1,
        ..SyntheticSetup::default()
    };
    let (control, client, _, provider) = outcome_harness(outcome, setup);
    let id = prepare_approved(&control, &client, "terminal-retry");
    let failed = client.invoke(id).unwrap();
    assert_eq!(failed.state, state);
    assert_eq!(failed.error, Some(error));
    assert_eq!(failed.result, None);
    assert_eq!(client.invoke(id).unwrap(), failed);
    assert_eq!(client.prepare(input("terminal-retry", 7)).unwrap(), failed);
    assert_eq!(provider.calls(), 1);
    assert_eq!(control.remaining_uses().unwrap(), 0);
    assert_error(
        client.prepare(input("terminal-budget", 8)),
        ErrorCode::BudgetExhausted,
    );
}

#[test]
fn provider_unavailable_is_a_terminal_failure_without_refund_or_retry() {
    assert_terminal_does_not_refund_or_retry(
        FixtureOutcome::Unavailable,
        Lifecycle::Failed,
        ErrorCode::ProviderUnavailable,
    );
}

#[test]
fn unknown_provider_outcome_is_retained_without_refund_or_retry() {
    assert_terminal_does_not_refund_or_retry(
        FixtureOutcome::Unknown,
        Lifecycle::OutcomeUnknown,
        ErrorCode::OutcomeUnknown,
    );
}

#[test]
fn trusted_executor_panic_becomes_unknown_without_refund_or_retry() {
    assert_terminal_does_not_refund_or_retry(
        FixtureOutcome::Panic,
        Lifecycle::OutcomeUnknown,
        ErrorCode::OutcomeUnknown,
    );
}

#[test]
fn unsuccessful_provider_work_does_not_refresh_idle() {
    for outcome in [
        FixtureOutcome::WrongRepository,
        FixtureOutcome::Unavailable,
        FixtureOutcome::Unknown,
        FixtureOutcome::Panic,
    ] {
        let setup = SyntheticSetup {
            idle_seconds: 20,
            maximum_seconds: 100,
            ..SyntheticSetup::default()
        };
        let (control, client, clock, provider) = outcome_harness(outcome, setup);
        clock.set(19);
        let id = prepare_approved(&control, &client, "failed-idle");
        client.invoke(id).unwrap();
        clock.set(20);
        assert_error(client.status(id), ErrorCode::SessionExpired);
        assert_eq!(provider.calls(), 1);
        assert_eq!(control.remaining_uses().unwrap(), 19);
    }
}

#[test]
fn zero_and_over_limit_session_configuration_is_rejected() {
    let default = SyntheticSetup::default();
    let mut configurations = Vec::new();
    for uses in [0, 1001] {
        configurations.push(SyntheticSetup {
            uses,
            ..default.clone()
        });
    }
    for idle_seconds in [0, 601] {
        configurations.push(SyntheticSetup {
            idle_seconds,
            ..default.clone()
        });
    }
    for maximum_seconds in [0, 1801] {
        configurations.push(SyntheticSetup {
            maximum_seconds,
            ..default.clone()
        });
    }
    for request_seconds in [0, 16] {
        configurations.push(SyntheticSetup {
            request_seconds,
            ..default.clone()
        });
    }
    for maximum_requests in [0, 129] {
        configurations.push(SyntheticSetup {
            maximum_requests,
            ..default.clone()
        });
    }
    for maximum_concurrent in [0, 5] {
        configurations.push(SyntheticSetup {
            maximum_concurrent,
            ..default.clone()
        });
    }
    let clock = Arc::new(ManualClock::default());
    let provider = Arc::new(FakeProvider::default());
    for setup in configurations {
        assert_error(
            Control::synthetic(setup, clock.clone(), provider.clone()),
            ErrorCode::InvalidRequest,
        );
    }
    assert_eq!(provider.calls(), 0);
}

#[test]
fn nonexistent_run_handles_cannot_grant_authority_or_dispatch() {
    let h = harness(SyntheticSetup::default());
    assert_error(h.client.invoke(999), ErrorCode::NotFound);
    assert_error(h.client.request_approval(999), ErrorCode::NotFound);
    assert_error(h.client.cancel(999), ErrorCode::NotFound);
    assert_error(h.client.status(999), ErrorCode::NotFound);
    assert_error(h.control.approve(999), ErrorCode::NotFound);
    assert_error(h.control.inspect_approval(999), ErrorCode::NotFound);
    assert_eq!(h.provider.calls(), 0);
}

#[test]
fn identifiers_and_unknown_authority_fields_fail_closed() {
    for invalid in [
        "",
        "human@example",
        "agent worker",
        "approval\ntrue",
        "é",
        "../control",
    ] {
        assert_error(RequestId::new(invalid), ErrorCode::InvalidRequest);
        assert_error(ProfileId::new(invalid), ErrorCode::InvalidRequest);
        assert_error(PrincipalId::new(invalid), ErrorCode::InvalidRequest);
    }
    assert_error(RequestId::new("a".repeat(65)), ErrorCode::InvalidRequest);
    assert!(RequestId::new("a".repeat(64)).is_ok());
    for extra in [
        "\"approved\":true",
        "\"principal\":\"human\"",
        "\"credential\":\"synthetic-fixture\"",
        "\"url\":\"https://example.invalid\"",
    ] {
        let json = format!("{{\"request_id\":\"wire\",\"profile_id\":\"issue-status\",\"parameters\":{{\"repository_id\":4242,\"issue_number\":7}},{extra}}}");
        assert!(serde_json::from_str::<PrepareInput>(&json).is_err());
    }
}
