//! Real-secret HTTP header injection on an owner-controlled Unix host.
//!
//! Services receive scoped operation authority, never a secret-export API.
//! The owner, host administrator, configured upstream and installed code are trusted.
pub(crate) mod store;
#[cfg(all(test, feature = "vault-spike"))]
mod tests;
pub(crate) mod transport;
pub mod tui;

use axum::http::{
    header::{HeaderName, HeaderValue},
    Method, Uri,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use transport::Client;
use zeroize::{Zeroize, Zeroizing};

/// Fixed errors never include keys, upstream bodies, URLs or native exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Denied,
    Storage,
    Capacity,
    OutcomeUnknown,
    ResponseDenied,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid_request",
            Self::Denied => "access_denied",
            Self::Storage => "private_storage_unavailable",
            Self::Capacity => "capacity_exceeded",
            Self::OutcomeUnknown => "upstream_outcome_unknown_do_not_retry_with_new_id",
            Self::ResponseDenied => "upstream_response_withheld",
        })
    }
}
impl std::error::Error for Error {}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn random() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Storage)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secret {
    value: String,
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Owner-defined header destination for one secret reference.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Injection {
    pub header: String,
    #[serde(default)]
    pub prefix: String,
}

/// An exact HTTPS operation, not an agent-selectable forwarding destination.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub url: String,
    pub method: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, Injection>,
    /// Named result fields mapped to JSON pointers. Empty means status only.
    #[serde(default)]
    pub response_fields: BTreeMap<String, String>,
}

/// Separate service identity, secret ACL and operation scope.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub allowed_secrets: BTreeSet<String>,
    pub operations: BTreeMap<String, Operation>,
    pub max_calls: u64,
}
impl Policy {
    fn validate(&self) -> Result<(), Error> {
        if self.max_calls == 0
            || self.operations.is_empty()
            || self.operations.len() > 32
            || self.allowed_secrets.len() > 32
        {
            return Err(Error::Invalid);
        }
        for (name, op) in &self.operations {
            let url: Uri = op.url.parse().map_err(|_| Error::Invalid)?;
            if !valid_id(name)
                || op.url.len() > 2048
                || url.scheme_str() != Some("https")
                || url.host().is_none()
                || url.authority().is_none_or(|a| a.as_str().contains('@'))
                || op.url.contains('#')
                || !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&op.method.as_str())
                || op.secrets.is_empty()
                || op.response_fields.len() > 32
                || op.headers.len() > 16
            {
                return Err(Error::Invalid);
            }
            let mut headers = BTreeSet::new();
            for (secret, injection) in &op.secrets {
                if !valid_id(secret)
                    || !self.allowed_secrets.contains(secret)
                    || injection.prefix.len() > 128
                    || HeaderValue::from_str(&injection.prefix).is_err()
                    || !safe_header(&injection.header)
                    || !headers.insert(injection.header.to_ascii_lowercase())
                {
                    return Err(Error::Invalid);
                }
            }
            for (header, value) in &op.headers {
                if !safe_header(header)
                    || header.eq_ignore_ascii_case("authorization")
                    || value.len() > 1024
                    || HeaderValue::from_str(value).is_err()
                    || !headers.insert(header.to_ascii_lowercase())
                {
                    return Err(Error::Invalid);
                }
            }
            if op.response_fields.iter().any(|(key, pointer)| {
                !valid_id(key) || !pointer.starts_with('/') || pointer.len() > 256
            }) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
fn safe_header(name: &str) -> bool {
    HeaderName::from_bytes(name.as_bytes()).is_ok()
        && ![
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "trailer",
            "expect",
        ]
        .contains(&name.to_ascii_lowercase().as_str())
}

#[derive(Serialize, Deserialize)]
struct Service {
    token_hash: String,
    enabled: bool,
    used: u64,
    policy: Policy,
}
#[derive(Serialize, Deserialize)]
struct Intent {
    fingerprint: String,
    result: Option<Value>,
}
#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u8,
    secrets: BTreeMap<String, Secret>,
    services: BTreeMap<String, Service>,
    intents: BTreeMap<String, Intent>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            version: 1,
            secrets: BTreeMap::new(),
            services: BTreeMap::new(),
            intents: BTreeMap::new(),
        }
    }
}

/// Agent/service request. No arbitrary URL, headers, environment or secret value.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub operation: String,
    pub inject: BTreeSet<String>,
    #[serde(default)]
    pub body: Option<Value>,
}

/// Private state and an HTTP client with redirects, proxies and retries disabled.
pub struct Broker {
    store: store::Store,
    client: Client,
}
impl Broker {
    /// Initialize a NEW private directory and generated age identity.
    pub fn initialize(path: &Path) -> Result<(), Error> {
        store::Store::initialize(path)
    }
    /// Open owner state. Never forwards a native HTTP client error.
    pub fn open(path: &Path) -> Result<Self, Error> {
        store::directory(path)?;
        let client = Client::new()?;
        Ok(Self {
            store: store::Store { path: path.into() },
            client,
        })
    }
    /// Provision or atomically rotate a credential. No read/export counterpart.
    pub fn put_secret(&self, name: &str, value: String) -> Result<(), Error> {
        let secret = Secret { value };
        if !valid_id(name)
            || secret.value.len() < 8
            || secret.value.len() > 4096
            || HeaderValue::from_str(&secret.value).is_err()
        {
            return Err(Error::Invalid);
        }
        let _lock = self.store.lock()?;
        let mut state = self.store.load()?;
        state.secrets.insert(name.into(), secret);
        self.store.save(&state)
    }
    /// Remove a credential; operations referencing it fail closed.
    pub fn delete_secret(&self, name: &str) -> Result<(), Error> {
        let _lock = self.store.lock()?;
        let mut state = self.store.load()?;
        state.secrets.remove(name).ok_or(Error::Invalid)?;
        self.store.save(&state)
    }
    /// Enroll a service. Its bearer credential is written only to a mode-0600 file.
    pub fn add_service(&self, name: &str, policy: Policy) -> Result<(), Error> {
        policy.validate()?;
        if !valid_id(name) {
            return Err(Error::Invalid);
        }
        let _lock = self.store.lock()?;
        let mut state = self.store.load()?;
        if state.services.contains_key(name)
            || policy
                .allowed_secrets
                .iter()
                .any(|s| !state.secrets.contains_key(s))
        {
            return Err(Error::Invalid);
        }
        let token = Zeroizing::new(random()?);
        store::atomic(
            &self.store.path.join(format!("{name}.token")),
            token.as_bytes(),
        )?;
        state.services.insert(
            name.into(),
            Service {
                token_hash: digest(token.as_bytes()),
                enabled: true,
                used: 0,
                policy,
            },
        );
        self.store.save(&state)
    }
    /// Replace policy without resetting consumed call authority or replay history.
    pub fn set_policy(&self, name: &str, policy: Policy) -> Result<(), Error> {
        policy.validate()?;
        let _lock = self.store.lock()?;
        let mut state = self.store.load()?;
        if policy
            .allowed_secrets
            .iter()
            .any(|s| !state.secrets.contains_key(s))
        {
            return Err(Error::Invalid);
        }
        let service = state.services.get_mut(name).ok_or(Error::Denied)?;
        if policy.max_calls < service.used {
            return Err(Error::Invalid);
        }
        service.policy = policy;
        self.store.save(&state)
    }
    /// Disable/re-enable a service or rotate its scoped bearer credential.
    pub fn control(&self, name: &str, enabled: Option<bool>, rotate: bool) -> Result<(), Error> {
        if !valid_id(name) {
            return Err(Error::Invalid);
        }
        let _lock = self.store.lock()?;
        let mut state = self.store.load()?;
        let service = state.services.get_mut(name).ok_or(Error::Denied)?;
        if let Some(value) = enabled {
            service.enabled = value;
        }
        if rotate {
            let token = Zeroizing::new(random()?);
            store::atomic(
                &self.store.path.join(format!("{name}.token")),
                token.as_bytes(),
            )?;
            service.token_hash = digest(token.as_bytes());
        }
        self.store.save(&state)
    }
    /// Non-secret owner inspection.
    pub fn status(&self) -> Result<Value, Error> {
        let _lock = self.store.lock()?;
        let state = self.store.load()?;
        Ok(
            json!({"services": state.services.iter().map(|(name, s)| json!({"name":name, "enabled":s.enabled, "used":s.used, "policy":s.policy})).collect::<Vec<_>>(),
            "secrets":state.secrets.keys().collect::<Vec<_>>(), "retained_requests":state.intents.len()}),
        )
    }
    /// Authenticate, durably consume one call, inject credentials, dispatch once.
    pub fn invoke(&self, token: &str, request: Request) -> Result<Value, Error> {
        if !valid_id(&request.request_id) || !valid_id(&request.operation) || token.len() != 64 {
            return Err(Error::Denied);
        }
        let encoded = serde_json::to_vec(&request).map_err(|_| Error::Invalid)?;
        if encoded.len() > 65536 {
            return Err(Error::Invalid);
        }
        let fingerprint = digest(&encoded);
        let (key, operation, secrets, headers) = {
            let _lock = self.store.lock()?;
            let mut state = self.store.load()?;
            let hash = digest(token.as_bytes());
            let (name, service) = state
                .services
                .iter()
                .find(|(_, s)| {
                    bool::from(s.token_hash.as_bytes().ct_eq(hash.as_bytes())) && s.enabled
                })
                .ok_or(Error::Denied)?;
            let name = name.clone();
            let operation = service
                .policy
                .operations
                .get(&request.operation)
                .ok_or(Error::Denied)?
                .clone();
            if request.inject != operation.secrets.keys().cloned().collect() {
                return Err(Error::Denied);
            }
            if operation.method == "GET" && request.body.is_some() {
                return Err(Error::Invalid);
            }
            let key = format!("{name}:{}", request.request_id);
            if let Some(previous) = state.intents.get(&key) {
                if previous.fingerprint != fingerprint {
                    return Err(Error::Denied);
                }
                return previous.result.clone().ok_or(Error::OutcomeUnknown);
            }
            if service.used >= service.policy.max_calls || state.intents.len() >= 10000 {
                return Err(Error::Capacity);
            }
            let mut headers = HeaderMap::new();
            for (key, value) in &operation.headers {
                headers.insert(
                    HeaderName::from_bytes(key.as_bytes()).map_err(|_| Error::Invalid)?,
                    HeaderValue::from_str(value).map_err(|_| Error::Invalid)?,
                );
            }
            let mut secrets = Vec::new();
            for (name, injection) in &operation.secrets {
                let secret = state.secrets.get(name).ok_or(Error::Denied)?;
                let value = Zeroizing::new(format!("{}{}", injection.prefix, secret.value));
                let mut header = HeaderValue::from_str(&value).map_err(|_| Error::Invalid)?;
                header.set_sensitive(true);
                headers.insert(
                    HeaderName::from_bytes(injection.header.as_bytes())
                        .map_err(|_| Error::Invalid)?,
                    header,
                );
                secrets.push(Zeroizing::new(secret.value.clone()));
            }
            state.services.get_mut(&name).ok_or(Error::Denied)?.used += 1;
            state.intents.insert(
                key.clone(),
                Intent {
                    fingerprint,
                    result: None,
                },
            );
            self.store.save(&state)?; // Commit before any external effect.
            (key, operation, secrets, headers)
        };
        let result = self.dispatch(&operation, request.body, headers, &secrets);
        let public = match result {
            Ok(value) => value,
            Err(error) => json!({"error":error.to_string()}),
        };
        let _lock = self.store.lock()?;
        let mut state = self.store.load()?;
        state.intents.get_mut(&key).ok_or(Error::Storage)?.result = Some(public.clone());
        self.store.save(&state)?;
        Ok(public)
    }
    fn dispatch(
        &self,
        op: &Operation,
        body: Option<Value>,
        mut headers: HeaderMap,
        secrets: &[Zeroizing<String>],
    ) -> Result<Value, Error> {
        let body = if let Some(value) = body {
            headers
                .entry("content-type")
                .or_insert(HeaderValue::from_static("application/json"));
            serde_json::to_vec(&value).map_err(|_| Error::Invalid)?
        } else {
            Vec::new()
        };
        let (status, bytes) = self.client.send(
            Method::from_bytes(op.method.as_bytes()).map_err(|_| Error::Invalid)?,
            op.url.parse().map_err(|_| Error::Invalid)?,
            headers,
            body,
            !op.response_fields.is_empty(),
        )?;
        // Never forward Location, Set-Cookie, authentication headers, raw error
        // bodies or an upstream redirect. Even error bodies can echo credentials.
        if !(200..300).contains(&status) || op.response_fields.is_empty() {
            return Ok(json!({"status":status}));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::ResponseDenied)?;
        let mut output = BTreeMap::new();
        for (name, pointer) in &op.response_fields {
            output.insert(name, value.pointer(pointer).ok_or(Error::ResponseDenied)?);
        }
        let result = json!({"status":status, "fields":output});
        let serialized = serde_json::to_string(&result).map_err(|_| Error::ResponseDenied)?;
        for secret in secrets {
            let escaped =
                serde_json::to_string(secret.as_str()).map_err(|_| Error::ResponseDenied)?;
            let encoded = [
                secret.to_string(),
                escaped[1..escaped.len() - 1].into(),
                STANDARD.encode(secret.as_bytes()),
                URL_SAFE_NO_PAD.encode(secret.as_bytes()),
                secret.bytes().map(|b| format!("{b:02x}")).collect(),
                secret.bytes().map(|b| format!("%{b:02X}")).collect(),
            ];
            if encoded.iter().any(|s| serialized.contains(s)) {
                return Err(Error::ResponseDenied);
            }
        }
        Ok(result)
    }
}

#[derive(Clone)]
struct HttpState {
    broker: Arc<Broker>,
    slots: Arc<tokio::sync::Semaphore>,
}
async fn handle(State(state): State<HttpState>, request: axum::extract::Request) -> Response {
    let mut response = handle_request(state, request).await.into_response();
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}
async fn handle_request(
    state: HttpState,
    request: axum::extract::Request,
) -> (StatusCode, Json<Value>) {
    let Ok(permit) = state.slots.try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":"busy"})));
    };
    let headers = request.headers();
    if headers.contains_key("origin")
        || headers.get_all("authorization").iter().count() != 1
        || request.uri().query().is_some()
        || headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"access_denied"})),
        );
    }
    let token = Zeroizing::new(
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string(),
    );
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        axum::body::to_bytes(request.into_body(), 65536),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_request"})),
            )
        }
    };
    let request: Request = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_request"})),
            )
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        state.broker.invoke(&token, request)
    })
    .await;
    match result {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)),
        Ok(Err(error)) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error":error.to_string()})),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"unavailable"})),
        ),
    }
}

/// Foreground loopback service. Use a separately managed TLS tunnel for remote use.
pub fn serve(path: &Path, address: SocketAddr) -> Result<(), Error> {
    if !address.ip().is_loopback() {
        return Err(Error::Invalid);
    }
    let broker = Arc::new(Broker::open(path)?);
    let runtime = tokio::runtime::Runtime::new().map_err(|_| Error::Storage)?;
    runtime.block_on(async {
        let state = HttpState {
            broker,
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
        };
        let app = Router::new()
            .route("/v1/proxy", post(handle))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|_| Error::Storage)?;
        println!(
            "aegis_proxy_ready {}",
            listener.local_addr().map_err(|_| Error::Storage)?
        );
        axum::serve(listener, app).await.map_err(|_| Error::Storage)
    })
}

/// CLI owner provisioning. Credential values are read only from a hidden prompt or stdin.
pub fn cli(args: &[String]) -> Result<(), Error> {
    let [flag, path, command, rest @ ..] = args else {
        return Err(Error::Invalid);
    };
    if flag != "--state-dir" {
        return Err(Error::Invalid);
    }
    let path = Path::new(path);
    if command == "init" && rest.is_empty() {
        Broker::initialize(path)?;
        println!("initialized");
        return Ok(());
    }
    let broker = Broker::open(path)?;
    match (command.as_str(), rest) {
        ("secret-put", [name]) => broker.put_secret(name, transport::prompt()?)?,
        ("secret-put", [name, flag]) if flag == "--stdin" => {
            let mut raw = Zeroizing::new(String::new());
            std::io::stdin()
                .take(4097)
                .read_to_string(&mut raw)
                .map_err(|_| Error::Invalid)?;
            if raw.len() > 4096 {
                return Err(Error::Invalid);
            }
            broker.put_secret(name, raw.trim_end_matches(['\r', '\n']).into())?;
        }
        ("secret-delete", [name]) => broker.delete_secret(name)?,
        ("service-add" | "service-set", [name, file]) => {
            let bytes = std::fs::File::open(file).map_err(|_| Error::Invalid)?;
            let policy: Policy =
                serde_json::from_reader(bytes.take(65537)).map_err(|_| Error::Invalid)?;
            if command == "service-add" {
                broker.add_service(name, policy)?;
            } else {
                broker.set_policy(name, policy)?;
            }
        }
        ("service-disable", [name]) => broker.control(name, Some(false), false)?,
        ("service-enable", [name]) => broker.control(name, Some(true), false)?,
        ("service-rotate", [name]) => broker.control(name, None, true)?,
        ("status", []) => {
            println!("{}", broker.status()?);
            return Ok(());
        }
        ("serve", [address]) => {
            drop(broker);
            return serve(path, address.parse().map_err(|_| Error::Invalid)?);
        }
        _ => return Err(Error::Invalid),
    }
    println!("ok");
    Ok(())
}
