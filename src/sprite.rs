//! Owner-controlled HTTP experiment. Fake fixtures only; no deployment or TLS management.
//! Authenticated owner possession is demonstrated, not biological human presence.
use crate::{
    fake::{Dispatch, Executor, ProviderOutcome, RawStatus},
    protocol, AgentClient, ApprovalView, Control, ErrorCode, MonotonicClock, PrincipalId,
    SyntheticSetup,
};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use subtle::ConstantTimeEq;

const MAX_BODY: usize = protocol::MAX_FRAME_BYTES;
const FAKE_PREFIX: &str = "AEGIS_FAKE_ONLY_";

fn unavailable() -> ErrorCode {
    ErrorCode::BrokerUnavailable
}

fn random_hex() -> Result<String, ErrorCode> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| unavailable())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn check_path(path: &Path) -> Result<(), ErrorCode> {
    if !path.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(ErrorCode::InvalidRequest);
        }
        current.push(component);
        if fs::symlink_metadata(&current)
            .map_err(|_| unavailable())?
            .file_type()
            .is_symlink()
        {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<(), ErrorCode> {
    check_path(path)?;
    let metadata = fs::metadata(path).map_err(|_| unavailable())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}

/// Owner-side setup. Creates a new private directory; never prints any credential bytes.
/// This is not a vault and deliberately accepts no caller-provided secret material.
pub fn initialize(path: &Path) -> Result<(), ErrorCode> {
    if !path.is_absolute() {
        return Err(ErrorCode::InvalidRequest);
    }
    check_path(path.parent().ok_or(ErrorCode::InvalidRequest)?)?;
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| unavailable())?;
    check_directory(path)?;
    for (name, value) in [
        ("owner.key", random_hex()?),
        ("agent.key", random_hex()?),
        ("fake-secret.key", format!("{FAKE_PREFIX}{}", random_hex()?)),
    ] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))
            .map_err(|_| unavailable())?;
        writeln!(file, "{value}").map_err(|_| unavailable())?;
        file.sync_all().map_err(|_| unavailable())?;
    }
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| unavailable())?;
    Ok(())
}

fn private_value(path: &Path) -> Result<String, ErrorCode> {
    check_path(path)?;
    let file = File::open(path).map_err(|_| unavailable())?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > 128
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut value = String::new();
    file.take(129)
        .read_to_string(&mut value)
        .map_err(|_| unavailable())?;
    if !value.ends_with('\n') {
        return Err(ErrorCode::InvalidRequest);
    }
    value.pop();
    Ok(value)
}

fn is_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// Intentionally no Debug/Serialize and no HTTP accessor for either credential object.
struct AuthKey(String);
impl AuthKey {
    fn accepts(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        bool::from(self.0.as_bytes().ct_eq(token.as_bytes()))
    }
}

struct FakeAccount {
    expected_key: String,
}
impl FakeAccount {
    fn status(&self, key: &str, dispatch: &Dispatch) -> ProviderOutcome {
        if !bool::from(self.expected_key.as_bytes().ct_eq(key.as_bytes())) {
            return ProviderOutcome::Unavailable;
        }
        ProviderOutcome::Status(RawStatus {
            repository_id: dispatch.parameters.repository_id,
            issue_number: dispatch.parameters.issue_number,
            state: if dispatch.parameters.issue_number.is_multiple_of(2) {
                "closed"
            } else {
                "open"
            }
            .into(),
        })
    }
}

struct FixtureProvider {
    key: String,
    account: FakeAccount,
    calls: AtomicUsize,
}
impl Executor for FixtureProvider {
    fn execute(&self, dispatch: &Dispatch) -> ProviderOutcome {
        if dispatch.profile.credential.secret_id != "synthetic-fixture"
            || dispatch.profile.credential.version != 1
            || dispatch.profile.adapter_contract != 1
            || dispatch.profile.output_contract != 1
        {
            return ProviderOutcome::Unavailable;
        }
        let outcome = self.account.status(&self.key, dispatch);
        if matches!(outcome, ProviderOutcome::Status(_)) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
        outcome
    }
}

struct Audit {
    sequence: u64,
    events: VecDeque<Value>,
}
struct Service {
    owner: AuthKey,
    agent: AuthKey,
    instance: String,
    control: Control,
    client: AgentClient,
    provider: Arc<FixtureProvider>,
    reviews: Mutex<BTreeMap<String, ApprovalView>>,
    audit: Mutex<Audit>,
    slots: tokio::sync::Semaphore,
}

impl Service {
    fn load(path: &Path) -> Result<Self, ErrorCode> {
        check_directory(path)?;
        let owner = private_value(&path.join("owner.key"))?;
        let agent = private_value(&path.join("agent.key"))?;
        let key = private_value(&path.join("fake-secret.key"))?;
        if !is_token(&owner)
            || !is_token(&agent)
            || owner == agent
            || !key.strip_prefix(FAKE_PREFIX).is_some_and(is_token)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let provider = Arc::new(FixtureProvider {
            account: FakeAccount {
                expected_key: key.clone(),
            },
            key,
            calls: AtomicUsize::new(0),
        });
        let (control, client) = Control::synthetic(
            SyntheticSetup {
                principal: PrincipalId::new("sprite-demo-agent")?,
                ..SyntheticSetup::default()
            },
            Arc::new(MonotonicClock::default()),
            provider.clone(),
        )?;
        Ok(Self {
            owner: AuthKey(owner),
            agent: AuthKey(agent),
            instance: random_hex()?,
            control,
            client,
            provider,
            reviews: Mutex::new(BTreeMap::new()),
            audit: Mutex::new(Audit {
                sequence: 0,
                events: VecDeque::new(),
            }),
            slots: tokio::sync::Semaphore::new(8),
        })
    }

    fn record(&self, role: &'static str, action: &'static str, outcome: &'static str) {
        if let Ok(mut audit) = self.audit.lock() {
            audit.sequence += 1;
            let event =
                json!({"sequence":audit.sequence,"role":role,"action":action,"outcome":outcome});
            eprintln!("{event}");
            if audit.events.len() == 256 {
                audit.events.pop_front();
            }
            audit.events.push_back(event);
        }
    }

    fn owner_action(&self, action: OwnerAction) -> Result<Value, ErrorCode> {
        match action {
            OwnerAction::Pending => Ok(json!(self
                .control
                .pending_approvals()?
                .iter()
                .map(plan)
                .collect::<Vec<_>>())),
            OwnerAction::Inspect(handle) => {
                let view = self.control.inspect_approval(handle.prepared_request_id)?;
                let receipt = random_hex()?;
                let mut reviews = self.reviews.lock().map_err(|_| unavailable())?;
                reviews.retain(|_, old| old.prepared_request_id != view.prepared_request_id);
                if reviews.len() >= 128 {
                    return Err(ErrorCode::CapacityExceeded);
                }
                let result = json!({"review_id":receipt,"plan":plan(&view)});
                reviews.insert(receipt, view);
                Ok(result)
            }
            OwnerAction::Approve(receipt) => {
                let view = self
                    .reviews
                    .lock()
                    .map_err(|_| unavailable())?
                    .remove(&receipt.review_id)
                    .ok_or(ErrorCode::ApprovalRequired)?;
                Ok(json!(self
                    .control
                    .approve_reviewed(view.prepared_request_id, &view)?))
            }
            OwnerAction::Cancel(handle) => {
                Ok(json!(self.client.cancel(handle.prepared_request_id)?))
            }
            OwnerAction::Revoke => {
                self.control.revoke()?;
                Ok(json!({"revoked":true}))
            }
            OwnerAction::Evidence => {
                let audit = self.audit.lock().map_err(|_| unavailable())?;
                Ok(
                    json!({"fixture_only":true,"provider_authenticated_calls":self.provider.calls.load(Ordering::SeqCst),
                    "remaining_uses":self.control.remaining_uses()?,"audit_events":audit.events,
                    "audit_total":audit.sequence,"audit_retention":256,
                    "claim":"bounded synthetic API evidence; deployment isolation not attested"}),
                )
            }
        }
    }
}

fn plan(view: &ApprovalView) -> Value {
    json!({"prepared_request_id":view.prepared_request_id,"principal":view.principal,
        "session":view.session,"profile_id":view.profile.id,"profile_revision":view.profile.revision,
        "parameters":view.parameters,"credential_ref":view.profile.credential.secret_id,
        "credential_version":view.profile.credential.version,"output_contract":view.profile.output_contract,
        "adapter_contract":view.profile.adapter_contract,"policy_generation":view.policy_generation,
        "expires_at_monotonic_seconds":view.expires_at,"remaining_uses":view.remaining_uses,
        "effects":"synthetic read only","result_fields":["repository_id","issue_number","state"],
        "fixture_only":true})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRequest {
    instance_id: String,
    request: protocol::Envelope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRequest {
    instance_id: String,
    action: OwnerAction,
}
#[derive(Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OwnerAction {
    Pending,
    Inspect(protocol::Handle),
    Approve(ReviewReceipt),
    Cancel(protocol::Handle),
    Revoke,
    Evidence,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewReceipt {
    review_id: String,
}

fn reply(status: StatusCode, body: Value) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Json(body),
    )
        .into_response()
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    reply(status, json!({"error":code}))
}

async fn route(State(service): State<Arc<Service>>, request: Request) -> Response {
    let Ok(_slot) = service.slots.try_acquire() else {
        return failure(StatusCode::TOO_MANY_REQUESTS, "capacity_exceeded");
    };
    // No browser/cookie authentication, ambient authority, URL tokens, or forwarded identity.
    if request.headers().contains_key(header::ORIGIN) || request.uri().query().is_some() {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let path = request.uri().path();
    let role = match path {
        "/v1/owner" if service.owner.accepts(request.headers()) => "owner",
        "/v1/agent" if service.agent.accepts(request.headers()) => "agent",
        "/v1/session"
            if service.owner.accepts(request.headers())
                || service.agent.accepts(request.headers()) =>
        {
            "session"
        }
        "/v1/owner" | "/v1/agent" | "/v1/session" => {
            service.record("unauthenticated", "authenticate", "denied");
            return failure(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        _ => return failure(StatusCode::NOT_FOUND, "not_found"),
    };
    if role == "session" && request.method() == Method::GET {
        return reply(
            StatusCode::OK,
            json!({"instance_id":service.instance,"fixture_only":true,
            "request_lifetime_seconds":15,"session_maximum_seconds":1800}),
        );
    }
    if request.method() != Method::POST || role == "session" {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        != Some("application/json")
    {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_request");
    }
    let body = match tokio::time::timeout(
        Duration::from_secs(2),
        to_bytes(request.into_body(), MAX_BODY),
    )
    .await
    {
        Ok(Ok(body)) => body,
        _ => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let (action, result) = if role == "agent" {
        let input: AgentRequest = match serde_json::from_slice(&body) {
            Ok(input) => input,
            Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        if input.instance_id != service.instance {
            return failure(StatusCode::CONFLICT, "instance_changed");
        }
        let action = match &input.request.action {
            protocol::Action::DiscoverOperations => "discover_operations",
            protocol::Action::PrepareOperation(_) => "prepare_operation",
            protocol::Action::RequestApproval(_) => "request_approval",
            protocol::Action::InvokeApproved(_) => "invoke_approved",
            protocol::Action::GetRunStatus(_) => "get_run_status",
            protocol::Action::Cancel(_) => "cancel",
        };
        let response = protocol::handle_envelope(&service.client, input.request);
        (
            action,
            if let Some(error) = response.error {
                Err(error)
            } else {
                Ok(response.result.unwrap_or(Value::Null))
            },
        )
    } else {
        let input: OwnerRequest = match serde_json::from_slice(&body) {
            Ok(input) => input,
            Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        if input.instance_id != service.instance {
            return failure(StatusCode::CONFLICT, "instance_changed");
        }
        let action = match &input.action {
            OwnerAction::Pending => "pending",
            OwnerAction::Inspect(_) => "inspect",
            OwnerAction::Approve(_) => "approve",
            OwnerAction::Cancel(_) => "cancel",
            OwnerAction::Revoke => "revoke",
            OwnerAction::Evidence => "evidence",
        };
        (action, service.owner_action(input.action))
    };
    service.record(role, action, if result.is_ok() { "ok" } else { "denied" });
    match result {
        Ok(value) => reply(
            StatusCode::OK,
            json!({"instance_id":service.instance,"result":value,"error":null}),
        ),
        Err(error) => reply(
            StatusCode::OK,
            json!({"instance_id":service.instance,"result":null,"error":error}),
        ),
    }
}

/// Serve on loopback only. Remote deployments must supply an owner-managed TLS gateway
/// or private tunnel. Authentication does not provide confidentiality over plain HTTP.
pub fn serve(path: &Path, address: SocketAddr) -> Result<(), ErrorCode> {
    if !address.ip().is_loopback() {
        return Err(ErrorCode::InvalidRequest);
    }
    let service = Arc::new(Service::load(path)?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| unavailable())?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|_| unavailable())?;
        eprintln!(
            "sprite_demo_ready {}",
            listener.local_addr().map_err(|_| unavailable())?
        );
        axum::serve(listener, Router::new().fallback(route).with_state(service))
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
            .map_err(|_| unavailable())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_account_requires_the_exact_key() {
        let account = FakeAccount {
            expected_key: format!("{FAKE_PREFIX}{}", "a".repeat(64)),
        };
        let dispatch = Dispatch {
            profile: crate::Profile::synthetic(),
            parameters: crate::Parameters {
                repository_id: 4242,
                issue_number: 7,
            },
        };
        assert!(matches!(
            account.status("wrong", &dispatch),
            ProviderOutcome::Unavailable
        ));
        assert!(matches!(
            account.status(&account.expected_key, &dispatch),
            ProviderOutcome::Status(_)
        ));
    }
}
