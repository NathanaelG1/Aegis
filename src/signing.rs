//! Optional sign-only key-source experiment with disposable, unregistered RSA keys.
//!
//! No key import, file storage, network, credential export or agent tool is provided.
//! This API discipline is not protection against same-process/same-UID memory access.
//!
//! ```compile_fail
//! // Key sources and encoded credentials are not an embedding/agent API.
//! use aegis::signing::EphemeralStore;
//! ```
//!
//! ```compile_fail
//! use aegis::signing::BoundSource;
//! ```
//! ```compile_fail
//! use aegis::signing::BoundPermit;
//! ```
//! ```compile_fail
//! use aegis::signing::BoundJwt;
//! ```
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::KeyPair;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use zeroize::Zeroize;

const ISSUER: &str = "Iv1_SYNTHETIC_ONLY";
const LABEL: &str = "synthetic-github-key";
const MAX_JWT: usize = 4096;
const MAX_PART: usize = 1024;
const MAX_SIGNATURES: u32 = 32;
const HANDLE_SECONDS: u64 = 30;
const STORE_SECONDS: u64 = 600;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningError {
    UnsupportedProtectedStorage,
    ProviderUnavailable,
    InvalidBinding,
    Locked,
    Revoked,
    StaleHandle,
    LeaseExpired,
    ClockInvalid,
    CapacityExceeded,
    InvalidToken,
    CryptoUnavailable,
    Unavailable,
}
impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SigningError {}

/// Counts/booleans only. Neither a key nor a signed JWT can be serialized through this report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SigningReport {
    pub synthetic_only: bool,
    pub algorithm: &'static str,
    pub rsa_bits: u16,
    pub verified_signature_and_claims: bool,
    pub lock_denied_signing: bool,
    pub stale_handle_denied: bool,
    pub revoke_denied_signing: bool,
    pub already_issued_jwt_still_verifies: bool,
    pub protected_storage_unavailable: bool,
    pub signatures_created: u32,
    pub live_available: bool,
}

pub(crate) fn require_fixed_provider() -> Result<(), SigningError> {
    static OWNERSHIP: OnceLock<Result<(), SigningError>> = OnceLock::new();
    *OWNERSHIP.get_or_init(|| {
        jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .map_err(|_| SigningError::ProviderUnavailable)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stamp {
    utc: u64,
    elapsed: u64,
}
impl Stamp {
    fn after(self, previous: Self) -> bool {
        self.utc >= 60 && self.utc >= previous.utc && self.elapsed >= previous.elapsed
    }
}
trait Clock: Send + Sync {
    fn now(&self) -> Stamp;
}
struct FixtureClock {
    utc: AtomicU64,
    elapsed: AtomicU64,
}
impl FixtureClock {
    fn new() -> Self {
        Self {
            utc: AtomicU64::new(1_800_000_000),
            elapsed: AtomicU64::new(0),
        }
    }
}
impl Clock for FixtureClock {
    fn now(&self) -> Stamp {
        Stamp {
            utc: self.utc.load(Ordering::SeqCst),
            elapsed: self.elapsed.load(Ordering::SeqCst),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyBinding {
    label: String,
    version: u64,
    issuer: String,
    algorithm: Algorithm,
}
impl KeyBinding {
    fn fixture() -> Self {
        Self {
            label: LABEL.into(),
            version: 1,
            issuer: ISSUER.into(),
            algorithm: Algorithm::RS256,
        }
    }
    fn valid(&self) -> bool {
        self.label == LABEL
            && self.version > 0
            && self.issuer == ISSUER
            && self.algorithm == Algorithm::RS256
    }
}
/// Credential bytes intentionally lack Debug/Clone/Serialize and all public accessors.
struct AppJwt(String);
impl Drop for AppJwt {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
trait SigningLease: Send + Sync {
    fn sign_with_stamp(&self, not_before: u64) -> Result<(AppJwt, Stamp), SigningError>;
    fn sign_app_jwt(&self) -> Result<AppJwt, SigningError> {
        self.sign_with_stamp(0).map(|(jwt, _)| jwt)
    }
}
trait KeySource {
    fn resolve(&self, binding: &KeyBinding) -> Result<Box<dyn SigningLease>, SigningError>;
}
/// A future protected store must implement the same sign-only contract. No claims
/// of OS protection or an agent-provided boolean can enable this placeholder.
struct UnavailableProtectedStore;
impl KeySource for UnavailableProtectedStore {
    fn resolve(&self, _: &KeyBinding) -> Result<Box<dyn SigningLease>, SigningError> {
        Err(SigningError::UnsupportedProtectedStorage)
    }
}

struct KeyMaterial {
    encoding: EncodingKey,
    verification: DecodingKey,
}
impl KeyMaterial {
    fn generate() -> Result<Self, SigningError> {
        require_fixed_provider()?;
        let native =
            RsaKeyPair::generate(KeySize::Rsa2048).map_err(|_| SigningError::CryptoUnavailable)?;
        if native.public_modulus_len() != 256 {
            return Err(SigningError::CryptoUnavailable);
        }
        let verification = DecodingKey::from_rsa_der(native.public_key().as_ref());
        // AWS-LC emits PKCS#8; jsonwebtoken's AWS RSA signer consumes PKCS#1.
        // Borrow its embedded key with the maintained PKCS#8/DER decoder.
        let der: Pkcs8V1Der<'static> = native
            .as_der()
            .map_err(|_| SigningError::CryptoUnavailable)?;
        let parsed = pkcs8::PrivateKeyInfoRef::try_from(der.as_ref())
            .map_err(|_| SigningError::CryptoUnavailable)?;
        let rsa_oid = pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        if parsed.algorithm.oid != rsa_oid || parsed.public_key.is_some() {
            return Err(SigningError::CryptoUnavailable);
        }
        let encoding = EncodingKey::from_rsa_der(parsed.private_key.as_bytes());
        // The borrowed parser cannot outlive `der`; AWS's owned DER buffer and
        // jsonwebtoken's owned EncodingKey have zeroizing Drop implementations.
        // Native temporaries, allocator copies and host memory remain outside this claim.
        Ok(Self {
            encoding,
            verification,
        })
    }
}
struct State {
    material: Option<KeyMaterial>,
    binding: KeyBinding,
    epoch: [u8; 16],
    generation: u64,
    locked: bool,
    revoked: bool,
    clock_invalid: bool,
    created: Stamp,
    last: Stamp,
    signatures: u32,
    #[cfg(test)]
    pause: Option<Arc<SignPause>>,
}
fn advance_generation(state: &mut State) -> Result<(), SigningError> {
    if let Some(next) = state.generation.checked_add(1) {
        state.generation = next;
        Ok(())
    } else {
        state.revoked = true;
        state.locked = true;
        state.material = None;
        Err(SigningError::Unavailable)
    }
}
struct Shared {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
}
impl Shared {
    fn check_time(&self, state: &mut State) -> Result<Stamp, SigningError> {
        let now = self.clock.now();
        if state.clock_invalid || !now.after(state.last) {
            state.clock_invalid = true;
            return Err(SigningError::ClockInvalid);
        }
        state.last = now;
        if now.elapsed.saturating_sub(state.created.elapsed) >= STORE_SECONDS {
            return Err(SigningError::LeaseExpired);
        }
        Ok(now)
    }
}
struct EphemeralStore {
    shared: Arc<Shared>,
}
impl Drop for EphemeralStore {
    fn drop(&mut self) {
        // Leases retain shared state, not ownership authority. End future signing
        // when the owning store goes away, even if a lease Arc survives it.
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.revoked = true;
        state.locked = true;
        state.material = None;
    }
}
impl EphemeralStore {
    fn new(clock: Arc<dyn Clock>) -> Result<Self, SigningError> {
        let material = KeyMaterial::generate()?;
        let now = clock.now();
        if !now.after(now) {
            return Err(SigningError::ClockInvalid);
        }
        let mut epoch = [0; 16];
        getrandom::getrandom(&mut epoch).map_err(|_| SigningError::Unavailable)?;
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    material: Some(material),
                    binding: KeyBinding::fixture(),
                    epoch,
                    generation: 1,
                    locked: false,
                    revoked: false,
                    clock_invalid: false,
                    created: now,
                    last: now,
                    signatures: 0,
                    #[cfg(test)]
                    pause: None,
                }),
                clock,
            }),
        })
    }
    fn verifier(&self) -> Result<FixtureVerifier, SigningError> {
        let state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        Ok(FixtureVerifier {
            key: state
                .material
                .as_ref()
                .ok_or(SigningError::Revoked)?
                .verification
                .clone(),
            issuer: state.binding.issuer.clone(),
        })
    }
    fn lock(&self) -> Result<(), SigningError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        if state.revoked {
            return Err(SigningError::Revoked);
        }
        advance_generation(&mut state)?;
        state.locked = true;
        Ok(())
    }
    fn unlock_fixture(&self) -> Result<(), SigningError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        self.shared.check_time(&mut state)?;
        if state.revoked {
            return Err(SigningError::Revoked);
        }
        advance_generation(&mut state)?;
        state.locked = false;
        Ok(())
    }
    fn revoke(&self) -> Result<(), SigningError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        state.revoked = true;
        state.locked = true;
        state.material = None;
        advance_generation(&mut state)?;
        Ok(())
    }
    #[cfg(test)]
    fn rotate_fixture(&self) -> Result<KeyBinding, SigningError> {
        let material = KeyMaterial::generate()?;
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        self.shared.check_time(&mut state)?;
        if state.revoked {
            return Err(SigningError::Revoked);
        }
        advance_generation(&mut state)?;
        state.binding.version = state
            .binding
            .version
            .checked_add(1)
            .ok_or(SigningError::Unavailable)?;
        state.material = Some(material);
        Ok(state.binding.clone())
    }
}
impl KeySource for EphemeralStore {
    fn resolve(&self, binding: &KeyBinding) -> Result<Box<dyn SigningLease>, SigningError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        let now = self.shared.check_time(&mut state)?;
        if !binding.valid() || *binding != state.binding {
            return Err(SigningError::InvalidBinding);
        }
        if state.revoked {
            return Err(SigningError::Revoked);
        }
        if state.locked {
            return Err(SigningError::Locked);
        }
        let expires = now
            .elapsed
            .checked_add(HANDLE_SECONDS)
            .ok_or(SigningError::ClockInvalid)?;
        Ok(Box::new(EphemeralLease {
            shared: self.shared.clone(),
            epoch: state.epoch,
            generation: state.generation,
            binding: binding.clone(),
            expires,
        }))
    }
}
struct EphemeralLease {
    shared: Arc<Shared>,
    epoch: [u8; 16],
    generation: u64,
    binding: KeyBinding,
    expires: u64,
}
impl SigningLease for EphemeralLease {
    fn sign_with_stamp(&self, not_before: u64) -> Result<(AppJwt, Stamp), SigningError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| SigningError::Unavailable)?;
        let now = self.shared.check_time(&mut state)?;
        if now.elapsed < not_before {
            state.clock_invalid = true;
            return Err(SigningError::ClockInvalid);
        }
        if state.revoked {
            return Err(SigningError::Revoked);
        }
        if state.locked {
            return Err(SigningError::Locked);
        }
        if state.epoch != self.epoch
            || state.generation != self.generation
            || state.binding != self.binding
        {
            return Err(SigningError::StaleHandle);
        }
        if now.elapsed >= self.expires {
            return Err(SigningError::LeaseExpired);
        }
        if state.signatures >= MAX_SIGNATURES {
            return Err(SigningError::CapacityExceeded);
        }
        let claims = AppClaims {
            iss: state.binding.issuer.clone(),
            iat: now.utc.checked_sub(60).ok_or(SigningError::ClockInvalid)?,
            exp: now.utc.checked_add(540).ok_or(SigningError::ClockInvalid)?,
        };
        #[cfg(test)]
        if let Some(pause) = state.pause.clone() {
            pause.wait();
        }
        state.signatures += 1;
        // Signing shares the same serialization point as lock/revoke/rotation.
        let token = AppJwt(
            jsonwebtoken::encode(
                &Header::new(Algorithm::RS256),
                &claims,
                &state
                    .material
                    .as_ref()
                    .ok_or(SigningError::Revoked)?
                    .encoding,
            )
            .map_err(|_| SigningError::CryptoUnavailable)?,
        );
        if token.0.len() > MAX_JWT {
            return Err(SigningError::CryptoUnavailable);
        }
        Ok((token, now))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppClaims {
    iss: String,
    iat: u64,
    exp: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHeader {
    alg: String,
    typ: String,
}
struct FixtureVerifier {
    key: DecodingKey,
    issuer: String,
}
fn strict_parts(token: &str) -> Result<AppClaims, SigningError> {
    if token.len() > MAX_JWT || !token.is_ascii() {
        return Err(SigningError::InvalidToken);
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(SigningError::InvalidToken)?;
    let payload = parts.next().ok_or(SigningError::InvalidToken)?;
    let signature = parts.next().ok_or(SigningError::InvalidToken)?;
    if parts.next().is_some()
        || header.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || header.len() > MAX_PART
        || payload.len() > MAX_PART
    {
        return Err(SigningError::InvalidToken);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| SigningError::InvalidToken)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| SigningError::InvalidToken)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| SigningError::InvalidToken)?;
    if signature_bytes.len() != 256
        || URL_SAFE_NO_PAD.encode(&header_bytes) != header
        || URL_SAFE_NO_PAD.encode(&payload_bytes) != payload
        || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature
    {
        return Err(SigningError::InvalidToken);
    }
    let header: StrictHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| SigningError::InvalidToken)?;
    if header.alg != "RS256" || header.typ != "JWT" {
        return Err(SigningError::InvalidToken);
    }
    serde_json::from_slice(&payload_bytes).map_err(|_| SigningError::InvalidToken)
}
impl FixtureVerifier {
    fn verify(&self, token: &AppJwt, now: Stamp) -> Result<(), SigningError> {
        require_fixed_provider()?;
        let strict = strict_parts(&token.0)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 0;
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.set_issuer(&[&self.issuer]);
        // Signature/algorithm/issuer validation remains enabled. Only the library's
        // OS-wall-clock exp check is replaced by the explicit injected-clock policy below.
        validation.validate_exp = false;
        let verified = jsonwebtoken::decode::<AppClaims>(&token.0, &self.key, &validation)
            .map_err(|_| SigningError::InvalidToken)?;
        if strict != verified.claims
            || strict.iss != self.issuer
            || now.utc < 60
            || strict.iat > now.utc
            || strict.exp <= now.utc
            || !matches!(strict.exp.checked_sub(strict.iat),Some(seconds) if seconds>0 && seconds<=600)
        {
            return Err(SigningError::InvalidToken);
        }
        Ok(())
    }
}

#[cfg(test)]
struct SignPause {
    entered: Mutex<std::sync::mpsc::Sender<()>>,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}
#[cfg(test)]
impl SignPause {
    fn wait(&self) {
        self.entered.lock().unwrap().send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
/// Generate an unregistered ephemeral test key and return only safe test evidence.
/// No arguments, imports, filesystem persistence or network calls exist on this path.
pub fn run_synthetic_signing_demo() -> Result<SigningReport, SigningError> {
    let clock = Arc::new(FixtureClock::new());
    let store = EphemeralStore::new(clock.clone())?;
    let verifier = store.verifier()?;
    let lease = store.resolve(&KeyBinding::fixture())?;
    let jwt = lease.sign_app_jwt()?;
    verifier.verify(&jwt, clock.now())?;
    store.lock()?;
    let lock_denied_signing = matches!(lease.sign_app_jwt(), Err(SigningError::Locked));
    store.unlock_fixture()?;
    let stale_handle_denied = matches!(lease.sign_app_jwt(), Err(SigningError::StaleHandle));
    let fresh = store.resolve(&KeyBinding::fixture())?;
    store.revoke()?;
    let revoke_denied_signing = matches!(fresh.sign_app_jwt(), Err(SigningError::Revoked));
    let already_issued_jwt_still_verifies = verifier.verify(&jwt, clock.now()).is_ok();
    let protected_storage_unavailable = matches!(
        UnavailableProtectedStore.resolve(&KeyBinding::fixture()),
        Err(SigningError::UnsupportedProtectedStorage)
    );
    let signatures_created = store
        .shared
        .state
        .lock()
        .map_err(|_| SigningError::Unavailable)?
        .signatures;
    if !(lock_denied_signing
        && stale_handle_denied
        && revoke_denied_signing
        && already_issued_jwt_still_verifies
        && protected_storage_unavailable
        && signatures_created == 1)
    {
        return Err(SigningError::Unavailable);
    }
    Ok(SigningReport {
        synthetic_only: true,
        algorithm: "RS256",
        rsa_bits: 2048,
        verified_signature_and_claims: true,
        lock_denied_signing,
        stale_handle_denied,
        revoke_denied_signing,
        already_issued_jwt_still_verifies,
        protected_storage_unavailable,
        signatures_created,
        live_available: crate::github::live_readiness().available,
    })
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;

#[cfg(unix)]
mod composition;
#[cfg(unix)]
pub(crate) use composition::{BoundJwt, BoundPermit, BoundSource, SigningAuthorization};
