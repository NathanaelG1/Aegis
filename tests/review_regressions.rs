//! Regressions discovered by independent review of the first local checkpoint.
use aegis::fake::{Dispatch, Executor, FakeProvider, ProviderOutcome, RawStatus};
use aegis::{
    ApprovalMode, Control, ErrorCode, Lifecycle, ManualClock, Parameters, PrepareInput, Profile,
    ProfileId, RequestId, SyntheticSetup,
};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

fn input(name: &str) -> PrepareInput {
    PrepareInput {
        request_id: RequestId::new(name).unwrap(),
        profile_id: ProfileId::new("issue-status").unwrap(),
        parameters: Parameters {
            repository_id: 4242,
            issue_number: 7,
        },
    }
}

struct Paused {
    entered: mpsc::Sender<()>,
    released: Mutex<bool>,
    wake: Condvar,
}
impl Paused {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
impl Executor for Paused {
    fn execute(&self, dispatch: &Dispatch) -> ProviderOutcome {
        self.entered.send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
        ProviderOutcome::Status(RawStatus {
            repository_id: dispatch.parameters.repository_id,
            issue_number: dispatch.parameters.issue_number,
            state: "open".into(),
        })
    }
}
struct Release(Arc<Paused>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[test]
fn late_agent_approval_request_preserves_dispatched_state_and_clean_success() {
    let clock = Arc::new(ManualClock::default());
    let (sender, receiver) = mpsc::channel();
    let provider = Arc::new(Paused {
        entered: sender,
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let _release = Release(provider.clone());
    let (control, client) =
        Control::synthetic(SyntheticSetup::default(), clock.clone(), provider.clone()).unwrap();
    let id = client
        .prepare(input("late-agent-approval"))
        .unwrap()
        .prepared_request_id;
    client.request_approval(id).unwrap();
    control.approve(id).unwrap();
    let worker = client.clone();
    let running = thread::spawn(move || worker.invoke(id).unwrap());
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.set(15);
    assert_eq!(
        client.request_approval(id).unwrap().state,
        Lifecycle::Dispatched
    );
    assert_eq!(client.status(id).unwrap().state, Lifecycle::Dispatched);
    provider.release();
    let completed = running.join().unwrap();
    assert_eq!(completed.state, Lifecycle::Succeeded);
    assert_eq!(completed.error, None);
    assert!(completed.result.is_some());
    assert_eq!(control.remaining_uses().unwrap(), 19);
}

#[test]
fn late_control_approval_cannot_rewrite_dispatched_state() {
    let clock = Arc::new(ManualClock::default());
    let (sender, receiver) = mpsc::channel();
    let provider = Arc::new(Paused {
        entered: sender,
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let _release = Release(provider.clone());
    let (control, client) =
        Control::synthetic(SyntheticSetup::default(), clock.clone(), provider.clone()).unwrap();
    let id = client
        .prepare(input("late-control-approval"))
        .unwrap()
        .prepared_request_id;
    client.request_approval(id).unwrap();
    control.approve(id).unwrap();
    let worker = client.clone();
    let running = thread::spawn(move || worker.invoke(id).unwrap());
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.set(15);
    assert_eq!(control.approve(id), Err(ErrorCode::InvalidRequest));
    assert_eq!(client.status(id).unwrap().state, Lifecycle::Dispatched);
    provider.release();
    assert_eq!(running.join().unwrap().error, None);
}

struct FixedOutcome(Mutex<Option<ProviderOutcome>>);
impl Executor for FixedOutcome {
    fn execute(&self, _: &Dispatch) -> ProviderOutcome {
        self.0.lock().unwrap().take().expect("one dispatch")
    }
}

#[test]
fn late_control_approval_preserves_each_terminal_outcome_and_reservation() {
    for outcome in [
        ProviderOutcome::Status(RawStatus {
            repository_id: 4242,
            issue_number: 7,
            state: "open".into(),
        }),
        ProviderOutcome::Unavailable,
        ProviderOutcome::Unknown,
    ] {
        let clock = Arc::new(ManualClock::default());
        let (control, client) = Control::synthetic(
            SyntheticSetup::default(),
            clock.clone(),
            Arc::new(FixedOutcome(Mutex::new(Some(outcome)))),
        )
        .unwrap();
        let id = client
            .prepare(input("late-terminal"))
            .unwrap()
            .prepared_request_id;
        client.request_approval(id).unwrap();
        control.approve(id).unwrap();
        let terminal = client.invoke(id).unwrap();
        clock.set(15);
        assert_eq!(control.approve(id), Err(ErrorCode::InvalidRequest));
        assert_eq!(client.status(id).unwrap(), terminal);
        assert_eq!(client.invoke(id).unwrap(), terminal);
        assert_eq!(control.remaining_uses().unwrap(), 19);
    }
}

#[test]
fn canceled_request_stays_canceled_after_preparation_deadline() {
    let clock = Arc::new(ManualClock::default());
    let (control, client) = Control::synthetic(
        SyntheticSetup::default(),
        clock.clone(),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let id = client
        .prepare(input("late-canceled"))
        .unwrap()
        .prepared_request_id;
    let canceled = client.cancel(id).unwrap();
    clock.set(15);
    assert_eq!(control.approve(id), Err(ErrorCode::RequestCanceled));
    assert_eq!(client.status(id).unwrap(), canceled);
}

#[test]
fn generation_change_never_reactivates_a_frozen_bounded_grant() {
    for restore in [false, true] {
        let setup = SyntheticSetup {
            approval_mode: ApprovalMode::BoundedSession,
            ..SyntheticSetup::default()
        };
        let (control, client) = Control::synthetic(
            setup,
            Arc::new(ManualClock::default()),
            Arc::new(FakeProvider::default()),
        )
        .unwrap();
        if restore {
            let mut changed = Profile::synthetic();
            changed.revision = 2;
            control.replace_profile(changed).unwrap();
        }
        control.replace_profile(Profile::synthetic()).unwrap();
        assert_eq!(
            client.prepare(input("new-generation")),
            Err(ErrorCode::PolicyChanged)
        );
        assert_eq!(control.remaining_uses().unwrap(), 20);
    }
}

#[test]
fn duplicate_prepare_observes_expiry_without_a_prior_status_poll() {
    let clock = Arc::new(ManualClock::default());
    let (_, client) = Control::synthetic(
        SyntheticSetup::default(),
        clock.clone(),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let request = input("duplicate-expiry");
    client.prepare(request.clone()).unwrap();
    clock.set(15);
    let repeated = client.prepare(request).unwrap();
    assert_eq!(repeated.state, Lifecycle::Expired);
    assert_eq!(repeated.error, Some(ErrorCode::RequestExpired));
}

#[test]
fn canonical_review_must_match_current_budget_at_atomic_approval() {
    let (control, client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let first = client
        .prepare(input("first-budget"))
        .unwrap()
        .prepared_request_id;
    let second = client
        .prepare(input("second-budget"))
        .unwrap()
        .prepared_request_id;
    client.request_approval(first).unwrap();
    client.request_approval(second).unwrap();
    control.approve(first).unwrap();
    let reviewed = control.inspect_approval(second).unwrap();
    assert_eq!(reviewed.remaining_uses, 20);
    client.invoke(first).unwrap();
    assert_eq!(
        control.approve_reviewed(second, &reviewed),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(
        client.status(second).unwrap().state,
        Lifecycle::AwaitingApproval
    );
    let fresh = control.inspect_approval(second).unwrap();
    assert_eq!(fresh.remaining_uses, 19);
    assert_eq!(
        control.approve_reviewed(second, &fresh).unwrap().state,
        Lifecycle::Approved
    );
}

#[test]
fn canonical_review_is_bound_to_the_specific_prepared_handle() {
    let (control, client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let first = client
        .prepare(input("first-review"))
        .unwrap()
        .prepared_request_id;
    let second = client
        .prepare(input("second-review"))
        .unwrap()
        .prepared_request_id;
    client.request_approval(first).unwrap();
    client.request_approval(second).unwrap();
    let reviewed = control.inspect_approval(first).unwrap();
    assert_eq!(
        control.approve_reviewed(second, &reviewed),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(
        client.status(second).unwrap().state,
        Lifecycle::AwaitingApproval
    );
    control.approve_reviewed(first, &reviewed).unwrap();
}

#[test]
fn canonical_review_is_bound_to_its_broker_instance() {
    let (first_control, first_client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let (second_control, second_client) = Control::synthetic(
        SyntheticSetup::default(),
        Arc::new(ManualClock::default()),
        Arc::new(FakeProvider::default()),
    )
    .unwrap();
    let first = first_client
        .prepare(input("same-request"))
        .unwrap()
        .prepared_request_id;
    let second = second_client
        .prepare(input("same-request"))
        .unwrap()
        .prepared_request_id;
    assert_eq!(first, second);
    first_client.request_approval(first).unwrap();
    second_client.request_approval(second).unwrap();
    let reviewed = first_control.inspect_approval(first).unwrap();
    assert_eq!(
        second_control.approve_reviewed(second, &reviewed),
        Err(ErrorCode::ApprovalRequired)
    );
    assert_eq!(
        second_client.status(second).unwrap().state,
        Lifecycle::AwaitingApproval
    );
    first_control.approve_reviewed(first, &reviewed).unwrap();
}
