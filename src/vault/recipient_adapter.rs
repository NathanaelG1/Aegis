//! Fixed-canary recipient-adapter contract exercise, not a production transport.
//!
//! Enrollment is checked by the sink under the same lock as installation. The
//! comparison models a protected object/identity check; these fixture digests do
//! not measure an executable, attest a host or establish an OS boundary.
//!
//! Private implementation capabilities are not a recipient enrollment or secret
//! entry API. Only the zero-input fixed-canary drill and closed report are public.
//!
//! ```compile_fail
//! use aegis::vault::recipient_adapter::{Adapter, DummySink, Enrollment, Transport};
//! ```
//! ```compile_fail
//! use aegis::vault::recipient_adapter::OpaqueCapsule;
//! ```
//! ```compile_fail
//! aegis::vault::recipient_adapter::run_synthetic_recipient_adapter_drill(b"real-value");
//! ```
use super::{
    crypto::{self, Identity, PrivateBytes, Signed, SigningKey, Verifier},
    model::{DeliveryParameters, DeliveryProfile, DeliveryProjection, RecipientBinding},
    store::{CANARY_ONE, CANARY_TWO},
};
use crate::{ErrorCode, RequestId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

const MAX_CAPSULE: usize = 16 * 1024;
const MAX_RECEIPT: usize = 8 * 1024;
const MAX_CIPHERTEXT: usize = 4 * 1024;
const MAX_ATTEMPTS: usize = 32;
const FIXTURE_USES: u32 = 4;

/// Private enrollment, resolved by trusted fixture setup, never agent input.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    recipient: RecipientBinding,
    executable_digest: String,
    dependency_digest: String,
    configuration_digest: String,
    destination_digest: String,
    destination_revision: u64,
    transport_contract: u32,
    encryption_recipient: String,
    receipt_key_revision: u64,
}
impl Enrollment {
    fn fixture(identity: &Identity) -> Self {
        Self {
            recipient: RecipientBinding::fixture(),
            executable_digest: crypto::hash(b"aegis-dummy-recipient-build-v1"),
            dependency_digest: crypto::hash(b"aegis-dummy-dependency-closure-v1"),
            configuration_digest: crypto::hash(b"aegis-dummy-configuration-v1"),
            destination_digest: crypto::hash(b"aegis-dummy-memory-slot-provider-auth-v1"),
            destination_revision: 1,
            transport_contract: 1,
            encryption_recipient: identity.recipient().to_string(),
            receipt_key_revision: 1,
        }
    }
    fn digest(&self) -> Result<String, ErrorCode> {
        serde_json::to_vec(self)
            .map(|v| crypto::hash(&v))
            .map_err(|_| ErrorCode::BrokerUnavailable)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsuleDocument {
    schema: u16,
    kind: String,
    vault_id: String,
    delivery_id: RequestId,
    profile: DeliveryProfile,
    enrollment_digest: String,
    expected_generation: u64,
    ciphertext: String,
}

/// Neither Debug nor serialization nor plaintext access is implemented.
struct OpaqueCapsule(Signed);
impl OpaqueCapsule {
    fn new(signed: Signed) -> Result<Self, ErrorCode> {
        if signed.bytes().len() > MAX_CAPSULE {
            return Err(ErrorCode::CapacityExceeded);
        }
        Ok(Self(signed))
    }
    fn digest(&self) -> String {
        crypto::hash(self.0.bytes())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u16,
    kind: String,
    vault_id: String,
    delivery_id: RequestId,
    profile: DeliveryProfile,
    enrollment_digest: String,
    expected_generation: u64,
    installed_generation: u64,
    capsule_digest: String,
}

/// Rejection is evidence from this trusted in-process sink only. A network error,
/// lost connection, malformed response or missing receipt must be Unknown.
enum Handoff {
    Acknowledged(Signed),
    Rejected,
    Unknown,
}

/// No raw paths, URLs, environment, commands, caller keys or plaintext parameters.
/// A future external implementation needs protected identity and bounded I/O;
/// implementing this fixture trait alone cannot establish those properties.
trait Transport {
    fn handoff(&self, expected: &Enrollment, capsule: OpaqueCapsule) -> Handoff;
}

struct Installed {
    actual: Enrollment,
    generation: u64,
    // Retains only capsule digests and signed receipts, never a plaintext slot.
    accepted: BTreeMap<RequestId, (String, Signed)>,
}
struct DummySink {
    vault_id: String,
    identity: Identity,
    writer: Verifier,
    signer: SigningKey,
    installed: Mutex<Installed>,
}
impl Transport for DummySink {
    fn handoff(&self, expected: &Enrollment, capsule: OpaqueCapsule) -> Handoff {
        let Ok(mut installed) = self.installed.lock() else {
            return Handoff::Unknown;
        };
        // Check the object actually used, not a preflight measurement followed by
        // another lookup. Mutation and generation replacement share this lock.
        if installed.actual != *expected {
            return Handoff::Rejected;
        }
        let Ok(document) = self.writer.verify::<CapsuleDocument>(&capsule.0) else {
            return Handoff::Rejected;
        };
        if document.schema != 1
            || document.kind != "aegis.synthetic.adapter.capsule.v1"
            || document.vault_id != self.vault_id
            || document.profile.validate().is_err()
            || document.profile.recipient != expected.recipient
            || expected.digest().as_ref() != Ok(&document.enrollment_digest)
            || document.expected_generation != document.profile.secret.version - 1
        {
            return Handoff::Rejected;
        }
        let digest = capsule.digest();
        if let Some((previous, receipt)) = installed.accepted.get(&document.delivery_id) {
            return if *previous == digest {
                Signed::parse(receipt.bytes())
                    .map(Handoff::Acknowledged)
                    .unwrap_or(Handoff::Unknown)
            } else {
                Handoff::Rejected
            };
        }
        if installed.generation != document.expected_generation
            || installed.accepted.len() >= MAX_ATTEMPTS
        {
            return Handoff::Rejected;
        }
        let clear = crypto::decode(&document.ciphertext, MAX_CIPHERTEXT)
            .and_then(|ciphertext| self.identity.decrypt(&ciphertext.0));
        let Ok(clear) = clear else {
            return Handoff::Rejected;
        };
        if fixture_value(document.profile.secret.version).as_ref() != Ok(&clear.0.as_slice()) {
            return Handoff::Rejected;
        }
        let receipt = Receipt {
            schema: 1,
            kind: "aegis.synthetic.adapter.receipt.v1".into(),
            vault_id: self.vault_id.clone(),
            delivery_id: document.delivery_id.clone(),
            profile: document.profile,
            enrollment_digest: document.enrollment_digest,
            expected_generation: document.expected_generation,
            installed_generation: document.expected_generation + 1,
            capsule_digest: digest.clone(),
        };
        let Ok(signed) = self.signer.sign(&receipt) else {
            return Handoff::Rejected;
        };
        if signed.bytes().len() > MAX_RECEIPT {
            return Handoff::Rejected;
        }
        let Ok(saved) = Signed::parse(signed.bytes()) else {
            return Handoff::Rejected;
        };
        // The in-memory installation point. No disk-durability claim follows.
        installed.generation = receipt.installed_generation;
        installed
            .accepted
            .insert(document.delivery_id, (digest, saved));
        Handoff::Acknowledged(signed)
    }
}
fn fixture_value(version: u64) -> Result<&'static [u8], ErrorCode> {
    match version {
        1 => Ok(CANARY_ONE.as_bytes()),
        2 => Ok(CANARY_TWO.as_bytes()),
        _ => Err(ErrorCode::ScopeDenied),
    }
}

struct Attempt {
    parameters: DeliveryParameters,
    result: Option<Result<DeliveryProjection, ErrorCode>>,
}
struct Book {
    attempts: BTreeMap<RequestId, Attempt>,
    remaining: u32,
    revoked: bool,
    blocked: bool,
}
struct Adapter {
    vault_id: String,
    enrollment: Enrollment,
    recipient: age::x25519::Recipient,
    writer: SigningKey,
    receipt_verifier: Verifier,
    book: Mutex<Book>,
}
impl Adapter {
    fn fixture() -> Result<(Self, DummySink), ErrorCode> {
        let identity = Identity::generate();
        let writer = SigningKey::generate()?;
        let signer = SigningKey::generate()?;
        let vault_id = crypto::random_id()?;
        let enrollment = Enrollment::fixture(&identity);
        let sink = DummySink {
            vault_id: vault_id.clone(),
            writer: writer.verifier(),
            signer,
            installed: Mutex::new(Installed {
                actual: enrollment.clone(),
                generation: 0,
                accepted: BTreeMap::new(),
            }),
            identity,
        };
        let adapter = Self {
            vault_id,
            enrollment,
            recipient: sink.identity.recipient(),
            writer,
            receipt_verifier: sink.signer.verifier(),
            book: Mutex::new(Book {
                attempts: BTreeMap::new(),
                remaining: FIXTURE_USES,
                revoked: false,
                blocked: false,
            }),
        };
        Ok((adapter, sink))
    }
    fn capsule(
        &self,
        id: &RequestId,
        parameters: &DeliveryParameters,
    ) -> Result<OpaqueCapsule, ErrorCode> {
        parameters.validate()?;
        let clear = PrivateBytes(fixture_value(parameters.secret.version)?.to_vec());
        let ciphertext = crypto::encrypt(&clear.0, &self.recipient)?;
        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(ErrorCode::CapacityExceeded);
        }
        OpaqueCapsule::new(self.writer.sign(&CapsuleDocument {
            schema: 1,
            kind: "aegis.synthetic.adapter.capsule.v1".into(),
            vault_id: self.vault_id.clone(),
            delivery_id: id.clone(),
            profile: DeliveryProfile::fixture(parameters.secret.version),
            enrollment_digest: self.enrollment.digest()?,
            expected_generation: parameters.expected_generation,
            ciphertext: crypto::encode(&ciphertext),
        })?)
    }
    fn validate_receipt(
        &self,
        signed: &Signed,
        id: &RequestId,
        parameters: &DeliveryParameters,
        capsule_digest: &str,
    ) -> Result<DeliveryProjection, ErrorCode> {
        if signed.bytes().len() > MAX_RECEIPT {
            return Err(ErrorCode::InvalidProviderResult);
        }
        let receipt: Receipt = self.receipt_verifier.verify(signed)?;
        if receipt.schema != 1
            || receipt.kind != "aegis.synthetic.adapter.receipt.v1"
            || receipt.vault_id != self.vault_id
            || receipt.delivery_id != *id
            || receipt.profile != DeliveryProfile::fixture(parameters.secret.version)
            || receipt.enrollment_digest != self.enrollment.digest()?
            || receipt.expected_generation != parameters.expected_generation
            || Some(receipt.installed_generation) != parameters.expected_generation.checked_add(1)
            || receipt.capsule_digest != capsule_digest
        {
            return Err(ErrorCode::InvalidProviderResult);
        }
        Ok(DeliveryProjection {
            delivery_id: id.clone(),
            recipient_id: receipt.profile.recipient.id,
            slot: receipt.profile.recipient.slot,
            credential_version: receipt.profile.secret.version,
            recipient_generation: receipt.installed_generation,
        })
    }
    fn deliver<T: Transport>(
        &self,
        id: RequestId,
        parameters: DeliveryParameters,
        transport: &T,
    ) -> Result<DeliveryProjection, ErrorCode> {
        {
            let mut book = self.book.lock().map_err(|_| ErrorCode::OutcomeUnknown)?;
            if let Some(attempt) = book.attempts.get(&id) {
                if attempt.parameters != parameters {
                    return Err(ErrorCode::RequestIdConflict);
                }
                return attempt
                    .result
                    .clone()
                    .unwrap_or(Err(ErrorCode::OutcomeUnknown));
            }
            parameters.validate()?;
            if parameters.recipient != self.enrollment.recipient {
                return Err(ErrorCode::ScopeDenied);
            }
            if book.revoked {
                return Err(ErrorCode::GrantRevoked);
            }
            if book.blocked {
                return Err(ErrorCode::ReconciliationRequired);
            }
            if book.remaining == 0 {
                return Err(ErrorCode::BudgetExhausted);
            }
            if book.attempts.len() >= MAX_ATTEMPTS
                || book.attempts.values().any(|a| a.result.is_none())
            {
                return Err(ErrorCode::CapacityExceeded);
            }
            book.remaining -= 1;
            book.attempts.insert(
                id.clone(),
                Attempt {
                    parameters: parameters.clone(),
                    result: None,
                },
            );
        }
        // A reservation consumes a use even on pre-handoff rejection. This book
        // is fixture-only: the main Store must durably reserve before real use.
        let result = match self.capsule(&id, &parameters) {
            Err(error) => Err(error),
            Ok(capsule) => {
                let digest = capsule.digest();
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    transport.handoff(&self.enrollment, capsule)
                }))
                .unwrap_or(Handoff::Unknown)
                {
                    Handoff::Acknowledged(signed) => self
                        .validate_receipt(&signed, &id, &parameters, &digest)
                        .map_err(|_| ErrorCode::OutcomeUnknown),
                    Handoff::Rejected => Err(ErrorCode::ProviderUnavailable),
                    Handoff::Unknown => Err(ErrorCode::OutcomeUnknown),
                }
            }
        };
        let mut book = self.book.lock().map_err(|_| ErrorCode::OutcomeUnknown)?;
        if result == Err(ErrorCode::OutcomeUnknown) {
            book.blocked = true;
        }
        let attempt = book
            .attempts
            .get_mut(&id)
            .ok_or(ErrorCode::OutcomeUnknown)?;
        attempt.result = Some(result.clone());
        result
    }
    fn revoke(&self) -> Result<(), ErrorCode> {
        self.book
            .lock()
            .map_err(|_| ErrorCode::OutcomeUnknown)?
            .revoked = true;
        Ok(())
    }
}

/// Safe fixed-canary observations; no raw capsule, receipt, key or digest output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SyntheticRecipientAdapterReport {
    pub synthetic_only: bool,
    pub completed_deliveries: usize,
    pub recipient_generation: u64,
    pub consumed_uses: u32,
    pub duplicate_reused: bool,
    pub changed_request_denied: bool,
    pub future_delivery_revoked: bool,
    pub installed_value_retracted: bool,
    pub durable_state_verified: bool,
    pub protected_recipient_verified: bool,
    pub ready_for_real_keys: bool,
}

/// Runs only built-in dummy values against an in-memory sink. No caller input,
/// transport selection, configuration, filesystem destination or key import.
pub fn run_synthetic_recipient_adapter_drill() -> Result<SyntheticRecipientAdapterReport, ErrorCode>
{
    let (adapter, sink) = Adapter::fixture()?;
    let one = RequestId::new("adapter-install-one")?;
    let parameters = DeliveryParameters::fixture(1);
    let first = adapter.deliver(one.clone(), parameters.clone(), &sink)?;
    let duplicate_reused = adapter.deliver(one.clone(), parameters, &sink)? == first;
    let changed_request_denied = adapter.deliver(one, DeliveryParameters::fixture(2), &sink)
        == Err(ErrorCode::RequestIdConflict);
    adapter.deliver(
        RequestId::new("adapter-rotate-two")?,
        DeliveryParameters::fixture(2),
        &sink,
    )?;
    adapter.revoke()?;
    let future_delivery_revoked = adapter.deliver(
        RequestId::new("adapter-after-revoke")?,
        DeliveryParameters::fixture(2),
        &sink,
    ) == Err(ErrorCode::GrantRevoked);
    let book = adapter
        .book
        .lock()
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    let installed = sink
        .installed
        .lock()
        .map_err(|_| ErrorCode::BrokerUnavailable)?;
    if !duplicate_reused
        || !changed_request_denied
        || !future_delivery_revoked
        || installed.generation != 2
        || book.remaining != 2
    {
        return Err(ErrorCode::BrokerUnavailable);
    }
    Ok(SyntheticRecipientAdapterReport {
        synthetic_only: true,
        completed_deliveries: installed.accepted.len(),
        recipient_generation: installed.generation,
        consumed_uses: FIXTURE_USES - book.remaining,
        duplicate_reused,
        changed_request_denied,
        future_delivery_revoked,
        installed_value_retracted: false,
        durable_state_verified: false,
        protected_recipient_verified: false,
        ready_for_real_keys: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };

    fn id(value: &str) -> RequestId {
        RequestId::new(value).unwrap()
    }

    fn signed_clone(value: &Signed) -> Signed {
        Signed::parse(value.bytes()).unwrap()
    }

    fn original_capsule(adapter: &Adapter) -> OpaqueCapsule {
        adapter
            .capsule(&id("install"), &DeliveryParameters::fixture(1))
            .unwrap()
    }

    fn capsule_value(adapter: &Adapter) -> Value {
        adapter
            .writer
            .verifier()
            .verify(&original_capsule(adapter).0)
            .unwrap()
    }

    fn assert_uninstalled(sink: &DummySink) {
        let installed = sink.installed.lock().unwrap();
        assert_eq!(installed.generation, 0);
        assert!(installed.accepted.is_empty());
    }

    struct Counted<'a> {
        sink: &'a DummySink,
        calls: AtomicUsize,
    }
    impl Transport for Counted<'_> {
        fn handoff(&self, expected: &Enrollment, capsule: OpaqueCapsule) -> Handoff {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.sink.handoff(expected, capsule)
        }
    }

    #[test]
    fn public_drill_is_fixed_canary_only_and_cannot_enable_deployment() {
        let run: fn() -> Result<SyntheticRecipientAdapterReport, ErrorCode> =
            run_synthetic_recipient_adapter_drill;
        let report = run().unwrap();
        assert!(report.synthetic_only);
        assert_eq!(report.completed_deliveries, 2);
        assert_eq!(report.recipient_generation, 2);
        assert_eq!(report.consumed_uses, 2);
        assert!(report.duplicate_reused && report.changed_request_denied);
        assert!(report.future_delivery_revoked);
        assert!(!report.installed_value_retracted);
        assert!(!report.durable_state_verified);
        assert!(!report.protected_recipient_verified);
        assert!(!report.ready_for_real_keys);
        assert_eq!(
            super::super::require_live_deployment(),
            Err(ErrorCode::UnsupportedDeployment)
        );
        for output in [
            serde_json::to_string(&report).unwrap(),
            format!("{report:?}"),
        ] {
            assert!(!output.contains(CANARY_ONE));
            assert!(!output.contains(CANARY_TWO));
            assert!(!output.contains("AGE-SECRET-KEY"));
            assert!(!output.contains("-----BEGIN"));
            assert!(output.len() < 1024);
        }
        assert_eq!(
            serde_json::to_value(report)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            11
        );
    }

    #[test]
    fn every_enrollment_binding_is_checked_at_the_installation_point() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let baseline = serde_json::to_value(&adapter.enrollment).unwrap();
        let mutations = [
            ("/recipient/id", json!("other-recipient")),
            ("/recipient/revision", json!(2)),
            ("/recipient/configuration_revision", json!(2)),
            ("/recipient/slot", json!("other-slot")),
            ("/executable_digest", json!("changed-build")),
            ("/dependency_digest", json!("changed-dependencies")),
            ("/configuration_digest", json!("changed-configuration")),
            ("/destination_digest", json!("changed-destination")),
            ("/destination_revision", json!(2)),
            ("/transport_contract", json!(2)),
            (
                "/encryption_recipient",
                json!(Identity::generate().recipient().to_string()),
            ),
            ("/receipt_key_revision", json!(2)),
        ];
        for (path, replacement) in mutations {
            // Capture the capsule before changing the actual installation object.
            let capsule = original_capsule(&adapter);
            let mut changed = baseline.clone();
            *changed.pointer_mut(path).unwrap() = replacement;
            sink.installed.lock().unwrap().actual = serde_json::from_value(changed).unwrap();
            assert!(
                matches!(
                    sink.handoff(&adapter.enrollment, capsule),
                    Handoff::Rejected
                ),
                "{path}"
            );
            assert_uninstalled(&sink);
        }
        sink.installed.lock().unwrap().actual = adapter.enrollment.clone();
        assert!(matches!(
            sink.handoff(&adapter.enrollment, original_capsule(&adapter)),
            Handoff::Acknowledged(_)
        ));
    }

    #[test]
    fn invalid_request_bindings_never_reserve_or_handoff() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let transport = Counted {
            sink: &sink,
            calls: AtomicUsize::new(0),
        };
        let baseline = serde_json::to_value(DeliveryParameters::fixture(1)).unwrap();
        for (path, value) in [
            ("/secret/id", json!("other-secret")),
            ("/secret/version", json!(0)),
            ("/secret/version", json!(3)),
            ("/recipient/id", json!("other-recipient")),
            ("/recipient/revision", json!(2)),
            ("/recipient/configuration_revision", json!(2)),
            ("/recipient/slot", json!("other-slot")),
            ("/repository_id", json!(4243)),
            ("/expected_generation", json!(1)),
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(path).unwrap() = value;
            let parameters = serde_json::from_value(changed).unwrap();
            assert_eq!(
                adapter.deliver(id("invalid"), parameters, &transport),
                Err(ErrorCode::InvalidRequest),
                "{path}"
            );
        }
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        let book = adapter.book.lock().unwrap();
        assert!(book.attempts.is_empty());
        assert_eq!(book.remaining, FIXTURE_USES);
    }

    #[test]
    fn signed_capsule_context_mismatches_fail_before_installation() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let baseline = capsule_value(&adapter);
        for (path, value) in [
            ("/schema", json!(2)),
            ("/kind", json!("another-purpose")),
            ("/vault_id", json!("another-vault")),
            ("/profile/id", json!("another-profile")),
            ("/profile/revision", json!(2)),
            ("/profile/repository_id", json!(4243)),
            ("/profile/secret/id", json!("another-secret")),
            ("/profile/secret/version", json!(0)),
            ("/profile/recipient/id", json!("another-recipient")),
            ("/profile/recipient/revision", json!(2)),
            ("/profile/recipient/configuration_revision", json!(2)),
            ("/profile/recipient/slot", json!("another-slot")),
            ("/profile/acl_revision", json!(2)),
            ("/profile/adapter_contract", json!(2)),
            ("/profile/output_contract", json!(2)),
            ("/enrollment_digest", json!("another-enrollment")),
            ("/expected_generation", json!(1)),
            ("/ciphertext", json!("not-an-age-message")),
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(path).unwrap() = value;
            let capsule = OpaqueCapsule::new(adapter.writer.sign(&changed).unwrap()).unwrap();
            assert!(
                matches!(
                    sink.handoff(&adapter.enrollment, capsule),
                    Handoff::Rejected
                ),
                "{path}"
            );
            assert_uninstalled(&sink);
        }
    }

    #[test]
    fn wrong_signer_unknown_fields_and_wrong_encrypted_value_are_rejected() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let baseline = capsule_value(&adapter);
        let stranger = SigningKey::generate().unwrap();
        let capsule = OpaqueCapsule::new(stranger.sign(&baseline).unwrap()).unwrap();
        assert!(matches!(
            sink.handoff(&adapter.enrollment, capsule),
            Handoff::Rejected
        ));
        let mut unknown = baseline.clone();
        unknown["approved"] = json!(true);
        let capsule = OpaqueCapsule::new(adapter.writer.sign(&unknown).unwrap()).unwrap();
        assert!(matches!(
            sink.handoff(&adapter.enrollment, capsule),
            Handoff::Rejected
        ));
        for (value, recipient) in [
            (CANARY_TWO.as_bytes(), adapter.recipient.clone()),
            (CANARY_ONE.as_bytes(), Identity::generate().recipient()),
        ] {
            let mut changed = baseline.clone();
            changed["ciphertext"] =
                json!(crypto::encode(&crypto::encrypt(value, &recipient).unwrap()));
            let capsule = OpaqueCapsule::new(adapter.writer.sign(&changed).unwrap()).unwrap();
            assert!(matches!(
                sink.handoff(&adapter.enrollment, capsule),
                Handoff::Rejected
            ));
        }
        assert_uninstalled(&sink);
    }

    #[test]
    fn sink_replays_only_the_exact_accepted_capsule() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let original = original_capsule(&adapter);
        let retry = OpaqueCapsule::new(signed_clone(&original.0)).unwrap();
        let first = match sink.handoff(&adapter.enrollment, original) {
            Handoff::Acknowledged(receipt) => receipt,
            _ => panic!("fixed capsule rejected"),
        };
        let replay = match sink.handoff(&adapter.enrollment, retry) {
            Handoff::Acknowledged(receipt) => receipt,
            _ => panic!("exact replay rejected"),
        };
        assert_eq!(first.bytes(), replay.bytes());
        // Re-encrypting the same canary generates a distinct signed capsule.
        assert!(matches!(
            sink.handoff(&adapter.enrollment, original_capsule(&adapter)),
            Handoff::Rejected
        ));
        let installed = sink.installed.lock().unwrap();
        assert_eq!(installed.generation, 1);
        assert_eq!(installed.accepted.len(), 1);
    }

    #[test]
    fn every_receipt_binding_and_signer_is_verified() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let capsule = original_capsule(&adapter);
        let digest = capsule.digest();
        let signed = match sink.handoff(&adapter.enrollment, capsule) {
            Handoff::Acknowledged(value) => value,
            _ => panic!("fixed capsule rejected"),
        };
        let baseline: Value = adapter.receipt_verifier.verify(&signed).unwrap();
        let parameters = DeliveryParameters::fixture(1);
        assert!(adapter
            .validate_receipt(&signed, &id("install"), &parameters, &digest)
            .is_ok());
        for (path, value) in [
            ("/schema", json!(2)),
            ("/kind", json!("another-purpose")),
            ("/vault_id", json!("another-vault")),
            ("/delivery_id", json!("another-request")),
            ("/profile/id", json!("another-profile")),
            ("/profile/revision", json!(2)),
            ("/profile/repository_id", json!(4243)),
            ("/profile/secret/id", json!("another-secret")),
            ("/profile/secret/version", json!(2)),
            ("/profile/recipient/id", json!("another-recipient")),
            ("/profile/recipient/revision", json!(2)),
            ("/profile/recipient/configuration_revision", json!(2)),
            ("/profile/recipient/slot", json!("another-slot")),
            ("/profile/acl_revision", json!(2)),
            ("/profile/adapter_contract", json!(2)),
            ("/profile/output_contract", json!(2)),
            ("/enrollment_digest", json!("another-enrollment")),
            ("/expected_generation", json!(1)),
            ("/installed_generation", json!(2)),
            ("/capsule_digest", json!("another-capsule")),
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(path).unwrap() = value;
            let signed = sink.signer.sign(&changed).unwrap();
            assert_eq!(
                adapter.validate_receipt(&signed, &id("install"), &parameters, &digest),
                Err(ErrorCode::InvalidProviderResult),
                "{path}"
            );
        }
        let wrong_signer = SigningKey::generate().unwrap().sign(&baseline).unwrap();
        assert!(adapter
            .validate_receipt(&wrong_signer, &id("install"), &parameters, &digest)
            .is_err());
        let mut unknown = baseline;
        unknown["extra"] = json!("untrusted");
        assert!(adapter
            .validate_receipt(
                &sink.signer.sign(&unknown).unwrap(),
                &id("install"),
                &parameters,
                &digest
            )
            .is_err());
        assert!(adapter
            .validate_receipt(&signed, &id("other"), &parameters, &digest)
            .is_err());
        assert!(adapter
            .validate_receipt(
                &signed,
                &id("install"),
                &DeliveryParameters::fixture(2),
                &digest
            )
            .is_err());
        assert!(adapter
            .validate_receipt(&signed, &id("install"), &parameters, "wrong-digest")
            .is_err());
    }

    #[test]
    fn request_reuse_rotation_and_revoke_never_repeat_or_retract() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let transport = Counted {
            sink: &sink,
            calls: AtomicUsize::new(0),
        };
        let first = adapter
            .deliver(id("one"), DeliveryParameters::fixture(1), &transport)
            .unwrap();
        assert_eq!(
            adapter.deliver(id("one"), DeliveryParameters::fixture(1), &transport),
            Ok(first.clone())
        );
        assert_eq!(
            adapter.deliver(id("one"), DeliveryParameters::fixture(2), &transport),
            Err(ErrorCode::RequestIdConflict)
        );
        let second = adapter
            .deliver(id("two"), DeliveryParameters::fixture(2), &transport)
            .unwrap();
        assert_eq!(second.recipient_generation, 2);
        adapter.revoke().unwrap();
        assert_eq!(
            adapter.deliver(id("three"), DeliveryParameters::fixture(2), &transport),
            Err(ErrorCode::GrantRevoked)
        );
        assert_eq!(
            adapter.deliver(id("one"), DeliveryParameters::fixture(1), &transport),
            Ok(first)
        );
        assert_eq!(transport.calls.load(Ordering::SeqCst), 2);
        assert_eq!(adapter.book.lock().unwrap().remaining, 2);
        assert_eq!(sink.installed.lock().unwrap().generation, 2);
    }

    #[test]
    fn out_of_order_and_stale_rotations_are_consumed_known_rejections() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        assert_eq!(
            adapter.deliver(id("early"), DeliveryParameters::fixture(2), &sink),
            Err(ErrorCode::ProviderUnavailable)
        );
        assert_uninstalled(&sink);
        adapter
            .deliver(id("one"), DeliveryParameters::fixture(1), &sink)
            .unwrap();
        assert_eq!(
            adapter.deliver(id("stale"), DeliveryParameters::fixture(1), &sink),
            Err(ErrorCode::ProviderUnavailable)
        );
        adapter
            .deliver(id("two"), DeliveryParameters::fixture(2), &sink)
            .unwrap();
        assert_eq!(adapter.book.lock().unwrap().remaining, 0);
        assert_eq!(sink.installed.lock().unwrap().generation, 2);
    }

    enum Fault {
        LostReceipt,
        MalformedReceipt,
        MismatchedReceipt,
        PanicAfterInstall,
    }
    struct Faulty<'a> {
        sink: &'a DummySink,
        fault: Fault,
        calls: AtomicUsize,
    }
    impl Transport for Faulty<'_> {
        fn handoff(&self, expected: &Enrollment, capsule: OpaqueCapsule) -> Handoff {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let receipt = match self.sink.handoff(expected, capsule) {
                Handoff::Acknowledged(value) => value,
                other => return other,
            };
            match self.fault {
                Fault::LostReceipt => Handoff::Unknown,
                Fault::MalformedReceipt => {
                    Handoff::Acknowledged(Signed::parse(b"malformed").unwrap())
                }
                Fault::MismatchedReceipt => {
                    let mut value: Receipt = self.sink.signer.verifier().verify(&receipt).unwrap();
                    value.delivery_id = id("wrong-request");
                    Handoff::Acknowledged(self.sink.signer.sign(&value).unwrap())
                }
                Fault::PanicAfterInstall => panic!("synthetic post-install failure"),
            }
        }
    }

    #[test]
    fn post_install_faults_keep_consumed_uncertainty_and_block_new_attempts() {
        for fault in [
            Fault::LostReceipt,
            Fault::MalformedReceipt,
            Fault::MismatchedReceipt,
            Fault::PanicAfterInstall,
        ] {
            let (adapter, sink) = Adapter::fixture().unwrap();
            let transport = Faulty {
                sink: &sink,
                fault,
                calls: AtomicUsize::new(0),
            };
            let parameters = DeliveryParameters::fixture(1);
            assert_eq!(
                adapter.deliver(id("unknown"), parameters.clone(), &transport),
                Err(ErrorCode::OutcomeUnknown)
            );
            assert_eq!(sink.installed.lock().unwrap().generation, 1);
            assert_eq!(
                adapter.deliver(id("unknown"), parameters, &transport),
                Err(ErrorCode::OutcomeUnknown)
            );
            assert_eq!(
                adapter.deliver(id("unknown"), DeliveryParameters::fixture(2), &transport),
                Err(ErrorCode::RequestIdConflict)
            );
            assert_eq!(
                adapter.deliver(id("new"), DeliveryParameters::fixture(2), &transport),
                Err(ErrorCode::ReconciliationRequired)
            );
            assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
            let book = adapter.book.lock().unwrap();
            assert_eq!(book.remaining, FIXTURE_USES - 1);
            assert_eq!(book.attempts.len(), 1);
            assert!(book.blocked);
        }
    }

    struct Rejecting(AtomicUsize);
    impl Transport for Rejecting {
        fn handoff(&self, _: &Enrollment, _: OpaqueCapsule) -> Handoff {
            self.0.fetch_add(1, Ordering::SeqCst);
            Handoff::Rejected
        }
    }

    #[test]
    fn known_rejection_is_not_refunded_or_automatically_retried() {
        let (adapter, _) = Adapter::fixture().unwrap();
        let transport = Rejecting(AtomicUsize::new(0));
        for number in 0..FIXTURE_USES {
            let request = id(&format!("attempt-{number}"));
            for _ in 0..2 {
                assert_eq!(
                    adapter.deliver(request.clone(), DeliveryParameters::fixture(1), &transport),
                    Err(ErrorCode::ProviderUnavailable)
                );
            }
        }
        assert_eq!(
            adapter.deliver(id("exhausted"), DeliveryParameters::fixture(1), &transport),
            Err(ErrorCode::BudgetExhausted)
        );
        assert_eq!(transport.0.load(Ordering::SeqCst), FIXTURE_USES as usize);
        assert_eq!(adapter.book.lock().unwrap().remaining, 0);
    }

    struct Paused<'a> {
        sink: &'a DummySink,
        entered: Barrier,
        release: Barrier,
        calls: AtomicUsize,
    }
    impl Transport for Paused<'_> {
        fn handoff(&self, expected: &Enrollment, capsule: OpaqueCapsule) -> Handoff {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.wait();
            self.release.wait();
            self.sink.handoff(expected, capsule)
        }
    }

    #[test]
    fn in_flight_duplicate_and_capacity_do_not_dispatch_twice_and_revoke_does_not_retract() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        let transport = Paused {
            sink: &sink,
            entered: Barrier::new(2),
            release: Barrier::new(2),
            calls: AtomicUsize::new(0),
        };
        std::thread::scope(|scope| {
            let work = scope
                .spawn(|| adapter.deliver(id("one"), DeliveryParameters::fixture(1), &transport));
            transport.entered.wait();
            let duplicate = adapter.deliver(id("one"), DeliveryParameters::fixture(1), &transport);
            let changed = adapter.deliver(id("one"), DeliveryParameters::fixture(2), &transport);
            let concurrent = adapter.deliver(id("two"), DeliveryParameters::fixture(1), &transport);
            let revoke = adapter.revoke();
            let after_revoke =
                adapter.deliver(id("three"), DeliveryParameters::fixture(1), &transport);
            // Release before assertions so a failure cannot strand the scoped thread.
            transport.release.wait();
            let completed = work.join().unwrap();
            assert_eq!(duplicate, Err(ErrorCode::OutcomeUnknown));
            assert_eq!(changed, Err(ErrorCode::RequestIdConflict));
            assert_eq!(concurrent, Err(ErrorCode::CapacityExceeded));
            assert!(revoke.is_ok());
            assert_eq!(after_revoke, Err(ErrorCode::GrantRevoked));
            assert!(completed.is_ok());
            assert_eq!(
                adapter.deliver(id("one"), DeliveryParameters::fixture(1), &transport),
                completed
            );
        });
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.book.lock().unwrap().remaining, FIXTURE_USES - 1);
        assert_eq!(sink.installed.lock().unwrap().generation, 1);
    }

    #[test]
    fn revoke_before_reservation_prevents_any_handoff() {
        let (adapter, _) = Adapter::fixture().unwrap();
        let transport = Rejecting(AtomicUsize::new(0));
        adapter.revoke().unwrap();
        assert_eq!(
            adapter.deliver(id("revoked"), DeliveryParameters::fixture(1), &transport),
            Err(ErrorCode::GrantRevoked)
        );
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        assert_eq!(adapter.book.lock().unwrap().remaining, FIXTURE_USES);
    }

    #[test]
    fn byte_bounds_are_checked_before_acceptance() {
        assert!(OpaqueCapsule::new(Signed::parse(&vec![b'a'; MAX_CAPSULE]).unwrap()).is_ok());
        assert!(matches!(
            OpaqueCapsule::new(Signed::parse(&vec![b'a'; MAX_CAPSULE + 1]).unwrap()),
            Err(ErrorCode::CapacityExceeded)
        ));
        let (adapter, sink) = Adapter::fixture().unwrap();
        let oversized = Signed::parse(&vec![b'a'; MAX_RECEIPT + 1]).unwrap();
        assert_eq!(
            adapter.validate_receipt(
                &oversized,
                &id("install"),
                &DeliveryParameters::fixture(1),
                "digest"
            ),
            Err(ErrorCode::InvalidProviderResult)
        );
        let mut value = capsule_value(&adapter);
        value["ciphertext"] = json!(crypto::encode(&vec![0; MAX_CIPHERTEXT + 1]));
        let capsule = OpaqueCapsule::new(adapter.writer.sign(&value).unwrap()).unwrap();
        assert!(matches!(
            sink.handoff(&adapter.enrollment, capsule),
            Handoff::Rejected
        ));
        assert_uninstalled(&sink);
        assert!(RequestId::new("x".repeat(64)).is_ok());
        assert!(RequestId::new("x".repeat(65)).is_err());
    }

    #[test]
    fn retention_caps_fail_closed_without_an_extra_reservation_or_install() {
        let (adapter, sink) = Adapter::fixture().unwrap();
        // Production fixture uses exhaust at four. Seed only test-local state to
        // independently exercise the defense-in-depth 32-entry retention caps.
        {
            let mut book = adapter.book.lock().unwrap();
            for number in 0..MAX_ATTEMPTS {
                book.attempts.insert(
                    id(&format!("retained-{number}")),
                    Attempt {
                        parameters: DeliveryParameters::fixture(1),
                        result: Some(Err(ErrorCode::ProviderUnavailable)),
                    },
                );
            }
        }
        let transport = Rejecting(AtomicUsize::new(0));
        assert_eq!(
            adapter.deliver(id("overflow"), DeliveryParameters::fixture(1), &transport),
            Err(ErrorCode::CapacityExceeded)
        );
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        assert_eq!(adapter.book.lock().unwrap().remaining, FIXTURE_USES);
        {
            let mut installed = sink.installed.lock().unwrap();
            for number in 0..MAX_ATTEMPTS {
                installed.accepted.insert(
                    id(&format!("retained-{number}")),
                    (String::new(), Signed::parse(b"test-receipt").unwrap()),
                );
            }
        }
        assert!(matches!(
            sink.handoff(&adapter.enrollment, original_capsule(&adapter)),
            Handoff::Rejected
        ));
        let installed = sink.installed.lock().unwrap();
        assert_eq!(installed.generation, 0);
        assert_eq!(installed.accepted.len(), MAX_ATTEMPTS);
    }
}
