//! Signed bounded fixture metadata, age-encrypted records and durable synthetic handoff.
//! The separate fixture kit/anchor assumes trusted storage. It is NOT an OS-protected
//! key store or a rollback anchor against an attacker who controls that kit as well.
use super::{
    auth::{Actors, Receipt, Review, AGENT},
    crypto::{self, Identity, PrivateBytes, Signed, SigningKey, Verifier},
    model::*,
};
use crate::{ErrorCode, PrincipalId, RequestId};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroize;
const MAX_LOG: usize = 1024 * 1024;
const MAX_EVENTS: u64 = 128;
pub(super) const BUDGET: u32 = 4;
pub(super) const CANARY_ONE: &str = "AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_ONE_NOT_VALID";
pub(super) const CANARY_TWO: &str = "AEGIS_SYNTHETIC_DELIVERY_CANARY_VERSION_TWO_NOT_VALID";
fn canary(version: u64) -> Result<&'static str, ErrorCode> {
    match version {
        1 => Ok(CANARY_ONE),
        2 => Ok(CANARY_TWO),
        _ => Err(ErrorCode::ScopeDenied),
    }
}

pub(super) struct Kit {
    pub vault_id: String,
    pub storage: Arc<Identity>,
    pub writer: Arc<SigningKey>,
    pub recipient: Arc<Identity>,
    pub receipt: Arc<SigningKey>,
    pub actors: Actors,
    pub directory: PathBuf,
}
/// Role-limited runtime material. No agent/admin signer or recipient private key.
pub(super) struct BrokerMaterial {
    pub(super) vault_id: String,
    pub(super) storage: Arc<Identity>,
    pub(super) writer: Arc<SigningKey>,
    pub(super) recipient: age::x25519::Recipient,
    pub(super) receipt: Verifier,
    pub(super) directory: PathBuf,
}
/// Recipient owns only its decryption/receipt keys and the broker public verifier.
pub(super) struct RecipientMaterial {
    pub(super) vault_id: String,
    pub(super) recipient: Arc<Identity>,
    pub(super) receipt: Arc<SigningKey>,
    pub(super) writer: Verifier,
}
impl BrokerMaterial {
    pub(super) fn check_recipient_material(
        &self,
        recipient: &RecipientMaterial,
    ) -> Result<(), ErrorCode> {
        // Empty histories cannot establish enrollment when custody is loaded separately.
        if self.vault_id != recipient.vault_id
            || self.recipient != recipient.recipient.recipient()
            || !self.receipt.same_key(&recipient.receipt.verifier())
            || !self.writer.verifier().same_key(&recipient.writer)
        {
            return Err(ErrorCode::ScopeDenied);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDocument {
    schema: u16,
    kind: String,
    vault_id: String,
    storage: String,
    writer: String,
    recipient: String,
    receipt: String,
    agent: String,
    admin: String,
}
impl Drop for KeyDocument {
    fn drop(&mut self) {
        self.storage.zeroize();
        self.writer.zeroize();
        self.recipient.zeroize();
        self.receipt.zeroize();
        self.agent.zeroize();
        self.admin.zeroize();
    }
}
impl Kit {
    pub fn broker_material(&self) -> Arc<BrokerMaterial> {
        Arc::new(BrokerMaterial {
            vault_id: self.vault_id.clone(),
            storage: self.storage.clone(),
            writer: self.writer.clone(),
            recipient: self.recipient.recipient(),
            receipt: self.receipt.verifier(),
            directory: self.directory.clone(),
        })
    }
    pub fn recipient_material(&self) -> Arc<RecipientMaterial> {
        Arc::new(RecipientMaterial {
            vault_id: self.vault_id.clone(),
            recipient: self.recipient.clone(),
            receipt: self.receipt.clone(),
            writer: self.writer.verifier(),
        })
    }
    pub fn create(path: &Path) -> Result<Arc<Self>, ErrorCode> {
        new_directory(path)?;
        let kit = Arc::new(Self {
            vault_id: crypto::random_id()?,
            storage: Arc::new(Identity::generate()),
            writer: Arc::new(SigningKey::generate()?),
            recipient: Arc::new(Identity::generate()),
            receipt: Arc::new(SigningKey::generate()?),
            actors: Actors::generate()?,
            directory: path.into(),
        });
        let document = KeyDocument {
            schema: 1,
            kind: "aegis.synthetic.vault.fixture-kit.v1".into(),
            vault_id: kit.vault_id.clone(),
            storage: crypto::encode(&kit.storage.fixture_encode().0),
            writer: crypto::encode(kit.writer.fixture_der()),
            recipient: crypto::encode(&kit.recipient.fixture_encode().0),
            receipt: crypto::encode(kit.receipt.fixture_der()),
            agent: crypto::encode(kit.actors.agent.fixture_der()),
            admin: crypto::encode(kit.actors.admin.fixture_der()),
        };
        let encoded = PrivateBytes(
            serde_json::to_vec(&document).map_err(|_| ErrorCode::PersistenceUnavailable)?,
        );
        write_new(&path.join("fixture-keys.json"), &encoded.0)?;
        sync_directory(path)?;
        Ok(kit)
    }
    pub fn open(path: &Path) -> Result<Arc<Self>, ErrorCode> {
        safe_directory(path)?;
        let bytes = PrivateBytes(read_file(&path.join("fixture-keys.json"), 16 * 1024)?);
        let document: KeyDocument =
            serde_json::from_slice(&bytes.0).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if document.schema != 1
            || document.kind != "aegis.synthetic.vault.fixture-kit.v1"
            || document.vault_id.len() != 43
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let key = |s: &str| -> Result<Arc<SigningKey>, ErrorCode> {
            Ok(Arc::new(SigningKey::from_fixture_der(
                &crypto::decode(s, 4096)?.0,
            )?))
        };
        Ok(Arc::new(Self {
            vault_id: document.vault_id.clone(),
            storage: Arc::new(Identity::fixture_parse(
                &crypto::decode(&document.storage, 256)?.0,
            )?),
            writer: key(&document.writer)?,
            recipient: Arc::new(Identity::fixture_parse(
                &crypto::decode(&document.recipient, 256)?.0,
            )?),
            receipt: key(&document.receipt)?,
            actors: Actors {
                agent: key(&document.agent)?,
                admin: key(&document.admin)?,
            },
            directory: path.into(),
        }))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AclEntry {
    pub principal: PrincipalId,
    pub profile: DeliveryProfile,
    pub max_uses: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    reference: SecretReference,
    ciphertext_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    import_metadata_digest: Option<String>,
}
/// Persisted purpose binding. Legacy fixtures remain byte-compatible when absent.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReceiptContract {
    #[default]
    Acceptance,
    #[cfg(feature = "application-slot")]
    Installation,
}
impl ReceiptContract {
    fn is_acceptance(&self) -> bool {
        *self == Self::Acceptance
    }
    pub(super) fn profile(self, version: u64) -> DeliveryProfile {
        match self {
            Self::Acceptance => DeliveryProfile::fixture(version),
            #[cfg(feature = "application-slot")]
            Self::Installation => DeliveryProfile::installation(version),
        }
    }
    pub(super) fn capsule_kind(self) -> &'static str {
        match self {
            Self::Acceptance => "aegis.synthetic.recipient.capsule.v1",
            #[cfg(feature = "application-slot")]
            Self::Installation => "aegis.synthetic.application-slot.capsule.v1",
        }
    }
    pub(super) fn verify_ack(
        self,
        signed: &Signed,
        verifier: &Verifier,
        vault: &str,
        id: &RequestId,
        profile: &DeliveryProfile,
        digest: &str,
    ) -> Result<Ack, ErrorCode> {
        match self {
            Self::Acceptance => {
                let ack: Ack = verifier.verify(signed)?;
                validate_ack(&ack, vault, id, profile, digest)?;
                Ok(ack)
            }
            #[cfg(feature = "application-slot")]
            Self::Installation => super::application_slot::verify_installation_receipt(
                signed, verifier, vault, id, profile, digest,
            ),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u16,
    kind: String,
    vault_id: String,
    acl_revision: u64,
    acl: Vec<AclEntry>,
    records: Vec<Record>,
    recipient_key: String,
    #[serde(default, skip_serializing_if = "ReceiptContract::is_acceptance")]
    receipt_contract: ReceiptContract,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    schema: u16,
    kind: String,
    vault_id: String,
    reference: SecretReference,
    pub(super) value: String,
    value_digest: String,
}
impl Drop for Payload {
    fn drop(&mut self) {
        self.value.zeroize();
        self.value_digest.zeroize();
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ack {
    pub schema: u16,
    pub kind: String,
    pub vault_id: String,
    pub delivery_id: RequestId,
    pub recipient: RecipientBinding,
    pub version: u64,
    pub generation: u64,
    pub capsule_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capsule {
    schema: u16,
    kind: String,
    vault_id: String,
    pub(super) delivery_id: RequestId,
    pub(super) profile: DeliveryProfile,
    pub(super) expected_generation: u64,
    ciphertext: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Delivered,
    Rejected,
    Unknown,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "event", deny_unknown_fields)]
enum Event {
    Genesis {
        manifest_digest: String,
        budget: u32,
    },
    Approval {
        review: Review,
        proof: Receipt,
    },
    Reservation {
        review: Review,
        agent: Receipt,
        admin_challenge: String,
        remaining_before: u32,
        reserved_at: u64,
    },
    Handoff {
        request_id: RequestId,
        capsule_digest: String,
    },
    Complete {
        request_id: RequestId,
        outcome: Outcome,
        ack: Option<String>,
    },
    Revoke {
        proof: Receipt,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    schema: u16,
    kind: String,
    vault_id: String,
    sequence: u64,
    previous: String,
    at: u64,
    event: Event,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    schema: u16,
    kind: String,
    vault_id: String,
    sequence: u64,
    head: String,
}
#[derive(Clone)]
struct Operation {
    review: Review,
    phase: Phase,
    outcome: Option<Outcome>,
    capsule: Option<String>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Reserved,
    Handing,
}
#[derive(Clone)]
struct History {
    sequence: u64,
    head: String,
    last_time: u64,
    remaining: u32,
    revoked: bool,
    blocked: bool,
    approvals: BTreeMap<RequestId, (Review, Receipt)>,
    operations: BTreeMap<RequestId, Operation>,
}
impl History {
    fn empty() -> Self {
        Self {
            sequence: 0,
            head: String::new(),
            last_time: 0,
            remaining: 0,
            revoked: false,
            blocked: false,
            approvals: BTreeMap::new(),
            operations: BTreeMap::new(),
        }
    }
    fn apply(
        &mut self,
        frame: &Frame,
        manifest_digest: &str,
        kit: &BrokerMaterial,
        contract: ReceiptContract,
    ) -> Result<(), ErrorCode> {
        let bad = || ErrorCode::PersistenceUnavailable;
        if frame.schema != 1
            || frame.kind != "aegis.synthetic.vault.journal.v1"
            || frame.vault_id != kit.vault_id
            || frame.sequence != self.sequence + 1
            || frame.previous != self.head
            || frame.at < self.last_time
            || frame.sequence > MAX_EVENTS
        {
            return Err(bad());
        }
        if self.sequence == 0 && !matches!(frame.event, Event::Genesis { .. }) {
            return Err(bad());
        }
        match &frame.event {
            Event::Genesis {
                manifest_digest: actual,
                budget,
            } => {
                if self.sequence != 0 || actual != manifest_digest || *budget != BUDGET {
                    return Err(bad());
                }
                self.remaining = *budget;
            }
            Event::Approval { review, proof } => {
                validate_review(review)?;
                if self.revoked
                    || self.blocked
                    || self.operations.contains_key(&review.request_id)
                    || proof.purpose != super::auth::Purpose::Approve
                    || proof.subject != super::auth::ADMIN
                    || proof.digest != review.digest()?
                    || proof.epoch != crypto::encode(&review.instance)
                    || proof.enrollment_revision != 1
                    || proof.acl_revision != review.profile.acl_revision
                    || proof.challenge.len() != 43
                {
                    return Err(bad());
                }
                if self.approvals.len() >= 32 && !self.approvals.contains_key(&review.request_id) {
                    return Err(bad());
                }
                self.approvals
                    .insert(review.request_id.clone(), (review.clone(), proof.clone()));
            }
            Event::Reservation {
                review,
                agent,
                admin_challenge,
                remaining_before,
                reserved_at,
            } => {
                validate_review(review)?;
                let Some((approved, proof)) = self.approvals.get(&review.request_id) else {
                    return Err(bad());
                };
                let expected =
                    super::auth::digest(&("aegis.vault.invoke.v1", review, *remaining_before))?;
                if self.revoked
                    || self.blocked
                    || self.operations.contains_key(&review.request_id)
                    || self.operations.values().any(|o| o.outcome.is_none())
                    || approved != review
                    || proof.challenge != *admin_challenge
                    || *remaining_before != self.remaining
                    || self.remaining == 0
                    || self.remaining > review.remaining
                    || *reserved_at >= review.expires
                    || agent.subject != AGENT
                    || agent.purpose != super::auth::Purpose::Invoke
                    || agent.digest != expected
                    || agent.epoch != crypto::encode(&review.instance)
                    || agent.enrollment_revision != 1
                    || agent.acl_revision != review.profile.acl_revision
                    || agent.challenge.len() != 43
                {
                    return Err(bad());
                }
                self.remaining -= 1;
                self.operations.insert(
                    review.request_id.clone(),
                    Operation {
                        review: review.clone(),
                        phase: Phase::Reserved,
                        outcome: None,
                        capsule: None,
                    },
                );
            }
            Event::Handoff {
                request_id,
                capsule_digest,
            } => {
                let op = self.operations.get_mut(request_id).ok_or_else(bad)?;
                if op.outcome.is_some() || op.phase != Phase::Reserved || capsule_digest.len() != 43
                {
                    return Err(bad());
                }
                op.phase = Phase::Handing;
                op.capsule = Some(capsule_digest.clone());
            }
            Event::Complete {
                request_id,
                outcome,
                ack,
            } => {
                let op = self.operations.get_mut(request_id).ok_or_else(bad)?;
                if op.outcome.is_some() {
                    return Err(bad());
                }
                match outcome {
                    Outcome::Delivered => {
                        if op.phase != Phase::Handing {
                            return Err(bad());
                        }
                        let signed = Signed::parse(ack.as_ref().ok_or_else(bad)?.as_bytes())?;
                        contract.verify_ack(
                            &signed,
                            &kit.receipt,
                            &kit.vault_id,
                            &op.review.request_id,
                            &op.review.profile,
                            op.capsule.as_ref().ok_or_else(bad)?,
                        )?;
                    }
                    Outcome::Rejected | Outcome::Unknown => {
                        if ack.is_some() {
                            return Err(bad());
                        }
                    }
                }
                op.outcome = Some(*outcome);
                self.blocked |= *outcome == Outcome::Unknown;
            }
            Event::Revoke { proof } => {
                if self.revoked
                    || proof.purpose != super::auth::Purpose::Revoke
                    || proof.subject != super::auth::ADMIN
                    || proof.enrollment_revision != 1
                    || proof.acl_revision != 1
                    || proof.challenge.len() != 43
                    || proof.digest.len() != 43
                    || proof.epoch.len() != 22
                {
                    return Err(bad());
                }
                self.revoked = true;
            }
        }
        self.sequence = frame.sequence;
        self.last_time = frame.at;
        Ok(())
    }
}
fn validate_review(r: &Review) -> Result<(), ErrorCode> {
    if r.profile.validate().is_err()
        || !r.profile.permits(&r.operation)
        || r.principal.as_str() != AGENT
        || r.session != 1
        || r.generation != 1
        || r.prepared == 0
        || r.remaining == 0
        || r.remaining > BUDGET
        || r.limits[0] > BUDGET as u64
        || r.limits[5] != 1
        || r.limits[4] > 32
        || r.limits[3] > 15
        || r.expires == 0
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(())
}
pub(super) fn validate_ack(
    a: &Ack,
    vault: &str,
    id: &RequestId,
    p: &DeliveryProfile,
    capsule: &str,
) -> Result<(), ErrorCode> {
    if a.schema != 1
        || a.kind != "aegis.synthetic.recipient.ack.v1"
        || a.vault_id != vault
        || a.delivery_id != *id
        || a.recipient != p.recipient
        || a.version != p.secret.version
        || a.generation != p.secret.version
        || a.capsule_digest != capsule
    {
        return Err(ErrorCode::InvalidProviderResult);
    }
    Ok(())
}
struct Writer {
    file: File,
    history: History,
    bytes: usize,
    failed: bool,
    reservation_guard: Option<String>,
    revocation_guard: Option<String>,
    #[cfg(test)]
    fault: Option<(u64, Fault)>,
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum Fault {
    BeforeWrite,
    PartialWrite,
    AfterWrite,
    AfterSync,
    BeforeAnchor,
    AfterAnchor,
    ExitAfterSync,
    ExitAfterAnchor,
}
pub(super) struct Store {
    directory: PathBuf,
    kit: Arc<BrokerMaterial>,
    manifest: Manifest,
    manifest_digest: String,
    writer: Mutex<Writer>,
}
impl Store {
    pub fn create(path: &Path, kit: Arc<BrokerMaterial>) -> Result<Arc<Self>, ErrorCode> {
        Self::create_with_acl(
            path,
            kit,
            [1, 2]
                .into_iter()
                .map(|v| AclEntry {
                    principal: PrincipalId::new(AGENT).expect("constant"),
                    profile: DeliveryProfile::fixture(v),
                    max_uses: BUDGET,
                })
                .collect(),
        )
    }
    pub(super) fn create_with_acl(
        path: &Path,
        kit: Arc<BrokerMaterial>,
        acl: Vec<AclEntry>,
    ) -> Result<Arc<Self>, ErrorCode> {
        Self::create_with_acl_contract(path, kit, acl, ReceiptContract::Acceptance)
    }
    #[cfg(all(test, feature = "application-slot"))]
    pub(super) fn create_installation(
        path: &Path,
        kit: Arc<BrokerMaterial>,
    ) -> Result<Arc<Self>, ErrorCode> {
        let contract = ReceiptContract::Installation;
        let acl = [1, 2]
            .into_iter()
            .map(|v| AclEntry {
                principal: PrincipalId::new(AGENT).expect("constant"),
                profile: contract.profile(v),
                max_uses: BUDGET,
            })
            .collect();
        Self::create_with_acl_contract(path, kit, acl, contract)
    }
    fn create_with_acl_contract(
        path: &Path,
        kit: Arc<BrokerMaterial>,
        acl: Vec<AclEntry>,
        contract: ReceiptContract,
    ) -> Result<Arc<Self>, ErrorCode> {
        if kit.directory.join("anchor.jws").exists() || kit.directory.join("anchor.next").exists() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        new_directory(path)?;
        let mut records = Vec::new();
        for version in [1, 2] {
            let value = canary(version)?;
            let payload = Payload {
                schema: 1,
                kind: "aegis.synthetic.secret.v1".into(),
                vault_id: kit.vault_id.clone(),
                reference: DeliveryParameters::fixture(version).secret,
                value: value.into(),
                value_digest: crypto::hash(value.as_bytes()),
            };
            let clear = PrivateBytes(
                serde_json::to_vec(&payload).map_err(|_| ErrorCode::PersistenceUnavailable)?,
            );
            let ciphertext = crypto::encrypt(&clear.0, &kit.storage.recipient())?;
            write_new(&path.join(format!("secret-{version}.age")), &ciphertext)?;
            records.push(Record {
                reference: payload.reference.clone(),
                ciphertext_digest: crypto::hash(&ciphertext),
                import_metadata_digest: None,
            });
        }
        Self::initialize(path, kit, acl, records, contract)
    }
    /// The sole composed constructor consumes one committed, bounded import.
    /// It never calls `canary` or the standalone record synthesizer.
    pub(super) fn create_imported(
        path: &Path,
        kit: Arc<BrokerMaterial>,
        imported: super::entry::protected_entry::ImportedCanary,
    ) -> Result<Arc<Self>, ErrorCode> {
        Self::create_imported_contract(path, kit, imported, ReceiptContract::Acceptance)
    }
    pub(super) fn create_imported_contract(
        path: &Path,
        kit: Arc<BrokerMaterial>,
        imported: super::entry::protected_entry::ImportedCanary,
        contract: ReceiptContract,
    ) -> Result<Arc<Self>, ErrorCode> {
        if kit.directory.join("anchor.jws").exists() || kit.directory.join("anchor.next").exists() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let (ciphertext, metadata_digest) = imported.consume_contract(&kit, contract)?;
        new_directory(path)?;
        write_new(&path.join("secret-1.age"), &ciphertext)?;
        let records = vec![Record {
            reference: DeliveryParameters::fixture(1).secret,
            ciphertext_digest: crypto::hash(&ciphertext),
            import_metadata_digest: Some(metadata_digest),
        }];
        let acl = vec![AclEntry {
            principal: PrincipalId::new(AGENT).expect("constant"),
            profile: contract.profile(1),
            max_uses: BUDGET,
        }];
        Self::initialize(path, kit, acl, records, contract)
    }
    fn initialize(
        path: &Path,
        kit: Arc<BrokerMaterial>,
        acl: Vec<AclEntry>,
        records: Vec<Record>,
        receipt_contract: ReceiptContract,
    ) -> Result<Arc<Self>, ErrorCode> {
        let manifest = Manifest {
            schema: 1,
            kind: "aegis.synthetic.vault.manifest.v1".into(),
            vault_id: kit.vault_id.clone(),
            acl_revision: 1,
            acl,
            records,
            recipient_key: crypto::hash(kit.recipient.to_string().as_bytes()),
            receipt_contract,
        };
        validate_manifest(&manifest, &kit)?;
        let signed = kit.writer.sign(&manifest)?;
        write_new(&path.join("manifest.jws"), signed.bytes())?;
        let file = create_file(&path.join("journal.jws"))?;
        file.try_lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let store = Arc::new(Self {
            directory: path.into(),
            manifest_digest: crypto::hash(signed.bytes()),
            manifest,
            kit,
            writer: Mutex::new(Writer {
                file,
                history: History::empty(),
                bytes: 0,
                failed: false,
                reservation_guard: None,
                revocation_guard: None,
                #[cfg(test)]
                fault: None,
            }),
        });
        store.append(
            Event::Genesis {
                manifest_digest: store.manifest_digest.clone(),
                budget: BUDGET,
            },
            0,
        )?;
        sync_directory(path)?;
        Ok(store)
    }
    pub fn open(path: &Path, kit: Arc<BrokerMaterial>) -> Result<Arc<Self>, ErrorCode> {
        safe_directory(path)?;
        for name in ["reservation.guard", "revocation.guard"] {
            match fs::symlink_metadata(path.join(name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(ErrorCode::ReconciliationRequired),
            }
        }
        let signed = Signed::parse(&read_file(
            &path.join("manifest.jws"),
            crypto::MAX_DOCUMENT,
        )?)?;
        let manifest: Manifest = kit.writer.verifier().verify(&signed)?;
        validate_manifest(&manifest, &kit)?;
        for record in &manifest.records {
            let ciphertext = read_file(
                &path.join(format!("secret-{}.age", record.reference.version)),
                crypto::MAX_DOCUMENT,
            )?;
            if crypto::hash(&ciphertext) != record.ciphertext_digest {
                return Err(ErrorCode::PersistenceUnavailable);
            }
        }
        let file = open_existing(&path.join("journal.jws"), true)?;
        file.try_lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let mut data = Vec::new();
        (&file)
            .take((MAX_LOG + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let manifest_digest = crypto::hash(signed.bytes());
        let history = replay(&data, &manifest_digest, &kit, manifest.receipt_contract)?;
        check_anchor(&kit, &history)?;
        let store = Arc::new(Self {
            directory: path.into(),
            kit,
            manifest,
            manifest_digest,
            writer: Mutex::new(Writer {
                file,
                history,
                bytes: data.len(),
                failed: false,
                reservation_guard: None,
                revocation_guard: None,
                #[cfg(test)]
                fault: None,
            }),
        });
        Ok(store)
    }
    pub(super) fn receipt_contract(&self) -> ReceiptContract {
        self.manifest.receipt_contract
    }
    pub(super) fn check_imported_record(&self, input: &Path) -> Result<(), ErrorCode> {
        let [record] = self.manifest.records.as_slice() else {
            return Err(ErrorCode::PolicyChanged);
        };
        let metadata_digest = record
            .import_metadata_digest
            .as_ref()
            .ok_or(ErrorCode::PolicyChanged)?;
        let original = super::entry::protected_entry::committed_ciphertext(input)?;
        let stored = read_file(&self.directory.join("secret-1.age"), crypto::MAX_DOCUMENT)?;
        if original != stored || crypto::hash(&stored) != record.ciphertext_digest {
            return Err(ErrorCode::PolicyChanged);
        }
        let clear = self.kit.storage.decrypt(&stored)?;
        super::entry::protected_entry::decode_imported_for(
            &clear.0,
            metadata_digest,
            &record.reference,
            &self.kit,
            self.manifest.receipt_contract,
        )?;
        Ok(())
    }
    fn check_storage_view(&self, w: &mut Writer) -> Result<(), ErrorCode> {
        safe_directory(&self.directory)?;
        safe_directory(&self.kit.directory)?;
        for (name, expected) in [
            ("reservation.guard", &w.reservation_guard),
            ("revocation.guard", &w.revocation_guard),
        ] {
            let guard = self.directory.join(name);
            match expected {
                Some(expected) => {
                    if crypto::hash(&read_file(&guard, crypto::MAX_DOCUMENT)?) != *expected {
                        return Err(ErrorCode::PersistenceUnavailable);
                    }
                }
                None => match fs::symlink_metadata(guard) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(ErrorCode::PersistenceUnavailable),
                },
            }
        }
        let named = fs::symlink_metadata(self.directory.join("journal.jws"))
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let opened = w
            .file
            .metadata()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if !named.is_file()
            || named.file_type().is_symlink()
            || named.dev() != opened.dev()
            || named.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.len() != w.bytes as u64
            || opened.mode() & 0o777 != 0o600
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        if crypto::hash(&read_file(
            &self.directory.join("manifest.jws"),
            crypto::MAX_DOCUMENT,
        )?) != self.manifest_digest
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        for r in &self.manifest.records {
            let bytes = read_file(
                &self
                    .directory
                    .join(format!("secret-{}.age", r.reference.version)),
                crypto::MAX_DOCUMENT,
            )?;
            if crypto::hash(&bytes) != r.ciphertext_digest {
                return Err(ErrorCode::PersistenceUnavailable);
            }
        }
        if w.history.sequence > 0 {
            let mut reader = w
                .file
                .try_clone()
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            reader
                .seek(SeekFrom::Start(0))
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            let mut bytes = Vec::new();
            reader
                .take((MAX_LOG + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            let current = replay(
                &bytes,
                &self.manifest_digest,
                &self.kit,
                self.manifest.receipt_contract,
            )?;
            if current.sequence != w.history.sequence || current.head != w.history.head {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            check_anchor(&self.kit, &current)?;
        }
        Ok(())
    }
    fn append_locked(&self, w: &mut Writer, event: Event, at: u64) -> Result<(), ErrorCode> {
        if w.failed {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        if self.check_storage_view(w).is_err() {
            w.failed = true;
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let frame = Frame {
            schema: 1,
            kind: "aegis.synthetic.vault.journal.v1".into(),
            vault_id: self.kit.vault_id.clone(),
            sequence: w.history.sequence + 1,
            previous: w.history.head.clone(),
            at,
            event,
        };
        let mut next = w.history.clone();
        next.apply(
            &frame,
            &self.manifest_digest,
            &self.kit,
            self.manifest.receipt_contract,
        )?;
        let signed = self.kit.writer.sign(&frame)?;
        let mut bytes = signed.bytes().to_vec();
        bytes.push(b'\n');
        if w.bytes.saturating_add(bytes.len()) > MAX_LOG {
            return Err(ErrorCode::CapacityExceeded);
        }
        next.head = crypto::hash(signed.bytes());
        w.failed = true;
        #[cfg(test)]
        let fault = w
            .fault
            .filter(|(seq, _)| *seq == next.sequence)
            .map(|(_, f)| f);
        #[cfg(test)]
        if matches!(fault, Some(Fault::BeforeWrite)) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        #[cfg(test)]
        if matches!(fault, Some(Fault::PartialWrite)) {
            w.file
                .write_all(&bytes[..bytes.len() / 2])
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            w.file
                .sync_all()
                .map_err(|_| ErrorCode::PersistenceUnavailable)?;
            return Err(ErrorCode::PersistenceUnavailable);
        }
        w.file
            .write_all(&bytes)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        #[cfg(test)]
        if matches!(fault, Some(Fault::AfterWrite)) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        w.file
            .sync_all()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        #[cfg(test)]
        if matches!(fault, Some(Fault::ExitAfterSync)) {
            std::process::exit(93);
        }
        #[cfg(test)]
        if matches!(fault, Some(Fault::AfterSync | Fault::BeforeAnchor)) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        write_anchor(&self.kit, &next)?;
        #[cfg(test)]
        if matches!(fault, Some(Fault::ExitAfterAnchor)) {
            std::process::exit(93);
        }
        #[cfg(test)]
        if matches!(fault, Some(Fault::AfterAnchor)) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        w.bytes += bytes.len();
        w.history = next;
        w.failed = false;
        Ok(())
    }
    fn append(&self, event: Event, at: u64) -> Result<(), ErrorCode> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        self.append_locked(&mut w, event, at)
    }
    pub fn remaining(&self) -> Result<u32, ErrorCode> {
        Ok(self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?
            .history
            .remaining)
    }
    pub fn ready(&self) -> Result<(), ErrorCode> {
        let w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.failed {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        if w.history.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if w.history.blocked || w.history.operations.values().any(|o| o.outcome.is_none()) {
            return Err(ErrorCode::ReconciliationRequired);
        }
        Ok(())
    }
    pub fn permits(&self, principal: &PrincipalId, profile: &DeliveryProfile) -> bool {
        self.manifest
            .acl
            .iter()
            .any(|a| a.principal == *principal && a.profile == *profile && a.max_uses == BUDGET)
            && profile.acl_revision == self.manifest.acl_revision
    }
    pub fn ensure_new(&self, id: &RequestId) -> Result<(), ErrorCode> {
        let w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.failed {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        if w.history.revoked {
            return Err(ErrorCode::GrantRevoked);
        }
        if w.history.blocked {
            return Err(ErrorCode::ReconciliationRequired);
        }
        if w.history.operations.contains_key(id) {
            Err(ErrorCode::RequestIdConflict)
        } else {
            Ok(())
        }
    }
    pub fn approve(&self, review: Review, proof: Receipt, at: u64) -> Result<(), ErrorCode> {
        self.append(Event::Approval { review, proof }, at)
    }
    /// Persist a fail-closed marker before the core reports a consumed reservation.
    /// Even a subsequent failure before the first journal byte must not look like
    /// untouched authority after restart. No automatic marker repair is supported.
    pub fn begin_reservation(
        &self,
        review: &Review,
        remaining_before: u32,
    ) -> Result<(), ErrorCode> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.failed || w.reservation_guard.is_some() || w.revocation_guard.is_some() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        self.check_storage_view(&mut w)?;
        let marker = self.kit.writer.sign(&(
            "aegis.synthetic.vault.reservation-guard.v1",
            &self.kit.vault_id,
            review,
            remaining_before,
        ))?;
        w.failed = true;
        write_new(&self.directory.join("reservation.guard"), marker.bytes())?;
        sync_directory(&self.directory)?;
        w.reservation_guard = Some(crypto::hash(marker.bytes()));
        w.failed = false;
        Ok(())
    }
    pub fn reserve(
        &self,
        review: Review,
        agent: Receipt,
        remaining_before: u32,
        reserved_at: u64,
    ) -> Result<(), ErrorCode> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.reservation_guard.is_none() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let admin_challenge = w
            .history
            .approvals
            .get(&review.request_id)
            .ok_or(ErrorCode::ApprovalRequired)?
            .1
            .challenge
            .clone();
        self.append_locked(
            &mut w,
            Event::Reservation {
                review,
                agent,
                admin_challenge,
                remaining_before,
                reserved_at,
            },
            reserved_at,
        )?;
        w.failed = true;
        fs::remove_file(self.directory.join("reservation.guard"))
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        sync_directory(&self.directory)?;
        w.reservation_guard = None;
        w.failed = false;
        Ok(())
    }
    pub fn revoke(&self, proof: Receipt, at: u64) -> Result<(), ErrorCode> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.revocation_guard.is_none() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        self.append_locked(&mut w, Event::Revoke { proof }, at)?;
        w.failed = true;
        fs::remove_file(self.directory.join("revocation.guard"))
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        sync_directory(&self.directory)?;
        w.revocation_guard = None;
        w.failed = false;
        Ok(())
    }
    pub fn begin_revocation(&self, proof: &Receipt) -> Result<(), ErrorCode> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.failed || w.reservation_guard.is_some() || w.revocation_guard.is_some() {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        self.check_storage_view(&mut w)?;
        let marker = self.kit.writer.sign(&(
            "aegis.synthetic.vault.revocation-guard.v1",
            &self.kit.vault_id,
            proof,
        ))?;
        w.failed = true;
        write_new(&self.directory.join("revocation.guard"), marker.bytes())?;
        sync_directory(&self.directory)?;
        w.revocation_guard = Some(crypto::hash(marker.bytes()));
        w.failed = false;
        Ok(())
    }
    pub fn blocked(&self) -> bool {
        self.writer
            .lock()
            .map(|w| w.failed || w.history.blocked)
            .unwrap_or(true)
    }
    pub fn history_counts(&self) -> Result<(usize, usize, usize, u32, bool), ErrorCode> {
        let w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        Ok((
            w.history.operations.len(),
            w.history
                .operations
                .values()
                .filter(|o| o.outcome.is_none())
                .count(),
            w.history
                .operations
                .values()
                .filter(|o| o.outcome == Some(Outcome::Unknown))
                .count(),
            w.history.remaining,
            w.history.revoked,
        ))
    }
    #[cfg(test)]
    pub fn fault(&self, sequence: u64, fault: Fault) {
        self.writer.lock().unwrap().fault = Some((sequence, fault));
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let w = self
            .writer
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = w.file.unlock();
    }
}
fn validate_manifest(m: &Manifest, kit: &BrokerMaterial) -> Result<(), ErrorCode> {
    if m.schema != 1
        || m.kind != "aegis.synthetic.vault.manifest.v1"
        || m.vault_id != kit.vault_id
        || m.acl_revision != 1
        || m.acl.len() > 2
        || m.recipient_key != crypto::hash(kit.recipient.to_string().as_bytes())
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    // Existing standalone records remain exactly the two original versions.
    // A single record is accepted only with authenticated import provenance and
    // the exact one-version ACL; deleting a standalone record cannot opt in.
    let imported = matches!(m.records.as_slice(), [r] if r.import_metadata_digest.as_ref().is_some_and(|d| d.len() == 43));
    if imported {
        if m.acl.len() != 1 || m.acl[0].profile != m.receipt_contract.profile(1) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
    } else if m.records.len() != 2 || m.records.iter().any(|r| r.import_metadata_digest.is_some()) {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    for (version, r) in [1, 2].into_iter().zip(&m.records) {
        if r.reference != DeliveryParameters::fixture(version).secret
            || r.ciphertext_digest.len() != 43
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
    }
    for a in &m.acl {
        if a.principal.as_str() != AGENT
            || a.profile.validate().is_err()
            || a.profile != m.receipt_contract.profile(a.profile.secret.version)
            || a.max_uses != BUDGET
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
    }
    Ok(())
}
fn replay(
    bytes: &[u8],
    manifest: &str,
    kit: &BrokerMaterial,
    contract: ReceiptContract,
) -> Result<History, ErrorCode> {
    if bytes.is_empty() || bytes.len() > MAX_LOG || bytes.last() != Some(&b'\n') {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    let mut h = History::empty();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        let signed = Signed::parse(&line[..line.len() - 1])?;
        let frame: Frame = kit.writer.verifier().verify(&signed)?;
        h.apply(&frame, manifest, kit, contract)?;
        h.head = crypto::hash(signed.bytes());
    }
    Ok(h)
}
fn write_anchor(kit: &BrokerMaterial, h: &History) -> Result<(), ErrorCode> {
    // Separate fixture file is an anchor INTERFACE, not protection against coherent
    // rollback of both directories. A real adapter must supply independent custody.
    let a = Anchor {
        schema: 1,
        kind: "aegis.synthetic.vault.anchor.v1".into(),
        vault_id: kit.vault_id.clone(),
        sequence: h.sequence,
        head: h.head.clone(),
    };
    let signed = kit.writer.sign(&a)?;
    let staging = kit.directory.join("anchor.next");
    write_new(&staging, signed.bytes())?;
    fs::rename(&staging, kit.directory.join("anchor.jws"))
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    sync_directory(&kit.directory)
}
fn check_anchor(kit: &BrokerMaterial, h: &History) -> Result<(), ErrorCode> {
    let signed = Signed::parse(&read_file(
        &kit.directory.join("anchor.jws"),
        crypto::MAX_DOCUMENT,
    )?)?;
    let a: Anchor = kit.writer.verifier().verify(&signed)?;
    if a.schema != 1
        || a.kind != "aegis.synthetic.vault.anchor.v1"
        || a.vault_id != kit.vault_id
        || a.sequence != h.sequence
        || a.head != h.head
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(())
}
fn path_components(path: &Path) -> Result<(), ErrorCode> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut p = PathBuf::new();
    for c in path.components() {
        p.push(c);
        if let Ok(m) = fs::symlink_metadata(&p) {
            if m.file_type().is_symlink() {
                return Err(ErrorCode::InvalidRequest);
            }
        }
    }
    Ok(())
}
pub(super) fn new_directory(path: &Path) -> Result<(), ErrorCode> {
    path_components(path)?;
    let parent = path.parent().ok_or(ErrorCode::InvalidRequest)?;
    if !parent.is_dir() {
        return Err(ErrorCode::InvalidRequest);
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    sync_directory(parent)
}
pub(super) fn safe_directory(path: &Path) -> Result<(), ErrorCode> {
    path_components(path)?;
    let m = fs::symlink_metadata(path).map_err(|_| ErrorCode::PersistenceUnavailable)?;
    if !m.is_dir() || m.mode() & 0o777 != 0o700 || m.uid() != nix::unistd::geteuid().as_raw() {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(())
}
fn create_file(path: &Path) -> Result<File, ErrorCode> {
    path_components(path)?;
    OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ErrorCode::PersistenceUnavailable)
}
fn open_existing(path: &Path, append: bool) -> Result<File, ErrorCode> {
    path_components(path)?;
    let f = OpenOptions::new()
        .read(true)
        .append(append)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    let m = f
        .metadata()
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != nix::unistd::geteuid().as_raw()
        || m.mode() & 0o777 != 0o600
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(f)
}
pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ErrorCode> {
    let mut f = create_file(path)?;
    f.write_all(bytes)
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    f.sync_all().map_err(|_| ErrorCode::PersistenceUnavailable)
}
pub(super) fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, ErrorCode> {
    let f = open_existing(path, false)?;
    if f.metadata()
        .map_err(|_| ErrorCode::PersistenceUnavailable)?
        .len()
        > limit as u64
    {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    let mut bytes = Vec::new();
    f.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::PersistenceUnavailable)?;
    if bytes.len() > limit {
        return Err(ErrorCode::PersistenceUnavailable);
    }
    Ok(bytes)
}
pub(super) fn sync_directory(path: &Path) -> Result<(), ErrorCode> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| ErrorCode::PersistenceUnavailable)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    schema: u16,
    kind: String,
    vault_id: String,
    sequence: u64,
    previous: String,
    capsule: String,
    ack: String,
}
struct RecipientState {
    file: File,
    head: String,
    generation: u64,
    received: BTreeMap<RequestId, (String, String)>,
    slot: Option<Payload>,
    failed: bool,
    #[cfg(test)]
    fault: Option<RecipientFault>,
    #[cfg(test)]
    pause: Option<Arc<RecipientPause>>,
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum RecipientFault {
    Reject,
    BeforeWrite,
    PartialWrite,
    AfterSync,
    PanicAfterInstall,
    BadAck,
    ExitBeforeWrite,
    ExitAfterSync,
}
pub(super) struct Recipient {
    kit: Arc<RecipientMaterial>,
    directory: PathBuf,
    state: Mutex<RecipientState>,
}
pub(super) enum RecipientOutcome {
    Acknowledged(Signed),
    Rejected,
    Unknown,
}
impl Recipient {
    pub fn create(path: &Path, kit: Arc<RecipientMaterial>) -> Result<Arc<Self>, ErrorCode> {
        new_directory(path)?;
        let file = create_file(&path.join("accepted.jws"))?;
        file.try_lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        file.sync_all()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        sync_directory(path)?;
        Ok(Arc::new(Self {
            kit,
            directory: path.into(),
            state: Mutex::new(RecipientState {
                file,
                head: String::new(),
                generation: 0,
                received: BTreeMap::new(),
                slot: None,
                failed: false,
                #[cfg(test)]
                fault: None,
                #[cfg(test)]
                pause: None,
            }),
        }))
    }
    pub fn open(path: &Path, kit: Arc<RecipientMaterial>) -> Result<Arc<Self>, ErrorCode> {
        safe_directory(path)?;
        let file = open_existing(&path.join("accepted.jws"), true)?;
        file.try_lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let mut bytes = Vec::new();
        (&file)
            .take((MAX_LOG + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if bytes.len() > MAX_LOG || (!bytes.is_empty() && bytes.last() != Some(&b'\n')) {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let mut state = RecipientState {
            file,
            head: String::new(),
            generation: 0,
            received: BTreeMap::new(),
            slot: None,
            failed: false,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            pause: None,
        };
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            let signed = Signed::parse(&line[..line.len() - 1])?;
            let record: Accepted = kit.receipt.verifier().verify(&signed)?;
            if record.schema != 1
                || record.kind != "aegis.synthetic.recipient.record.v1"
                || record.vault_id != kit.vault_id
                || record.sequence != state.generation + 1
                || record.previous != state.head
            {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            let capsule = Signed::parse(record.capsule.as_bytes())?;
            let (content, payload) = decode_capsule(&kit, &capsule)?;
            if content.expected_generation != state.generation
                || state.received.contains_key(&content.delivery_id)
            {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            let ack: Ack = kit
                .receipt
                .verifier()
                .verify(&Signed::parse(record.ack.as_bytes())?)?;
            let hash = crypto::hash(capsule.bytes());
            validate_ack(
                &ack,
                &kit.vault_id,
                &content.delivery_id,
                &content.profile,
                &hash,
            )?;
            state.generation = ack.generation;
            state.head = crypto::hash(signed.bytes());
            state
                .received
                .insert(content.delivery_id, (hash, record.ack));
            state.slot = Some(payload);
        }
        Ok(Arc::new(Self {
            kit,
            directory: path.into(),
            state: Mutex::new(state),
        }))
    }
    fn check_storage_view(&self, state: &RecipientState) -> Result<(), ErrorCode> {
        safe_directory(&self.directory)?;
        let path = self.directory.join("accepted.jws");
        let named = fs::symlink_metadata(&path).map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let opened = state
            .file
            .metadata()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if !named.is_file()
            || named.file_type().is_symlink()
            || named.dev() != opened.dev()
            || named.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.uid() != nix::unistd::geteuid().as_raw()
            || opened.mode() & 0o777 != 0o600
        {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let bytes = read_file(&path, MAX_LOG)?;
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let mut head = String::new();
        let mut generation = 0;
        let mut received = BTreeMap::new();
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            let signed = Signed::parse(&line[..line.len() - 1])?;
            let record: Accepted = self.kit.receipt.verifier().verify(&signed)?;
            if record.schema != 1
                || record.kind != "aegis.synthetic.recipient.record.v1"
                || record.vault_id != self.kit.vault_id
                || record.sequence != generation + 1
                || record.previous != head
            {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            let capsule = Signed::parse(record.capsule.as_bytes())?;
            let (content, _) = decode_capsule(&self.kit, &capsule)?;
            let hash = crypto::hash(capsule.bytes());
            let ack: Ack = self
                .kit
                .receipt
                .verifier()
                .verify(&Signed::parse(record.ack.as_bytes())?)?;
            validate_ack(
                &ack,
                &self.kit.vault_id,
                &content.delivery_id,
                &content.profile,
                &hash,
            )?;
            if content.expected_generation != generation
                || received
                    .insert(content.delivery_id, (hash, record.ack))
                    .is_some()
            {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            generation = ack.generation;
            head = crypto::hash(signed.bytes());
        }
        if head != state.head || generation != state.generation || received != state.received {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        Ok(())
    }
    /// Public-only receipts for a signed process status. No capsule or slot value.
    pub(super) fn process_receipts(&self) -> Result<(u64, Vec<String>), ErrorCode> {
        let state = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        if state.failed {
            return Err(ErrorCode::ReconciliationRequired);
        }
        self.check_storage_view(&state)?;
        Ok((
            state.generation,
            state
                .received
                .values()
                .map(|(_, ack)| ack.clone())
                .collect(),
        ))
    }
    pub fn generation(&self) -> Result<u64, ErrorCode> {
        let s = self
            .state
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        if s.failed {
            return Err(ErrorCode::ReconciliationRequired);
        }
        Ok(s.generation)
    }
    pub(super) fn accept(&self, signed: Signed) -> RecipientOutcome {
        let Ok(mut s) = self.state.lock() else {
            return RecipientOutcome::Unknown;
        };
        if s.failed {
            return RecipientOutcome::Unknown;
        }
        if self.check_storage_view(&s).is_err() {
            s.failed = true;
            return RecipientOutcome::Unknown;
        }
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::Reject)) {
            return RecipientOutcome::Rejected;
        }
        let Ok((content, payload)) = decode_capsule(&self.kit, &signed) else {
            return RecipientOutcome::Rejected;
        };
        let hash = crypto::hash(signed.bytes());
        if let Some((previous, ack)) = s.received.get(&content.delivery_id) {
            return if *previous == hash {
                Signed::parse(ack.as_bytes())
                    .map(RecipientOutcome::Acknowledged)
                    .unwrap_or(RecipientOutcome::Unknown)
            } else {
                RecipientOutcome::Rejected
            };
        }
        if content.expected_generation != s.generation || s.received.len() >= 32 {
            return RecipientOutcome::Rejected;
        }
        let receipt = Ack {
            schema: 1,
            kind: "aegis.synthetic.recipient.ack.v1".into(),
            vault_id: self.kit.vault_id.clone(),
            delivery_id: content.delivery_id.clone(),
            recipient: content.profile.recipient.clone(),
            version: content.profile.secret.version,
            generation: content.profile.secret.version,
            capsule_digest: hash.clone(),
        };
        let Ok(ack) = self.kit.receipt.sign(&receipt) else {
            return RecipientOutcome::Rejected;
        };
        let record = Accepted {
            schema: 1,
            kind: "aegis.synthetic.recipient.record.v1".into(),
            vault_id: self.kit.vault_id.clone(),
            sequence: s.generation + 1,
            previous: s.head.clone(),
            capsule: std::str::from_utf8(signed.bytes())
                .expect("ASCII JWS")
                .into(),
            ack: std::str::from_utf8(ack.bytes()).expect("ASCII JWS").into(),
        };
        let Ok(encoded) = self.kit.receipt.sign(&record) else {
            return RecipientOutcome::Rejected;
        };
        let mut bytes = encoded.bytes().to_vec();
        bytes.push(b'\n');
        #[cfg(test)]
        if let Some(pause) = s.pause.clone() {
            pause.wait();
        }
        s.failed = true;
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::ExitBeforeWrite)) {
            std::process::exit(93);
        }
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::BeforeWrite)) {
            return RecipientOutcome::Unknown;
        }
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::PartialWrite)) {
            let _ = s.file.write_all(&bytes[..bytes.len() / 2]);
            let _ = s.file.sync_all();
            return RecipientOutcome::Unknown;
        }
        if s.file
            .write_all(&bytes)
            .and_then(|_| s.file.sync_all())
            .is_err()
        {
            return RecipientOutcome::Unknown;
        }
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::ExitAfterSync)) {
            std::process::exit(93);
        }
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::AfterSync)) {
            return RecipientOutcome::Unknown;
        }
        s.generation = receipt.generation;
        s.head = crypto::hash(encoded.bytes());
        s.received.insert(content.delivery_id, (hash, record.ack));
        s.slot = Some(payload);
        s.failed = false;
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::PanicAfterInstall)) {
            panic!("synthetic recipient panic after installation");
        }
        #[cfg(test)]
        if matches!(s.fault, Some(RecipientFault::BadAck)) {
            return SigningKey::generate()
                .and_then(|wrong| wrong.sign(&receipt))
                .map(RecipientOutcome::Acknowledged)
                .unwrap_or(RecipientOutcome::Unknown);
        }
        RecipientOutcome::Acknowledged(ack)
    }
    #[cfg(test)]
    pub fn pause(&self) -> (std::sync::mpsc::Receiver<()>, Arc<RecipientPause>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let p = Arc::new(RecipientPause {
            entered: Mutex::new(tx),
            released: Mutex::new(false),
            wake: std::sync::Condvar::new(),
        });
        self.state.lock().unwrap().pause = Some(p.clone());
        (rx, p)
    }
    #[cfg(test)]
    pub fn fault(&self, fault: RecipientFault) {
        self.state.lock().unwrap().fault = Some(fault);
    }
    #[cfg(test)]
    pub fn contains_canary(&self, version: u64) -> bool {
        self.state
            .lock()
            .map(|s| {
                s.slot
                    .as_ref()
                    .is_some_and(|p| p.value == canary(version).unwrap())
            })
            .unwrap_or(false)
    }
}
impl Drop for Recipient {
    fn drop(&mut self) {
        let s = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = s.file.unlock();
    }
}
fn decode_capsule(
    kit: &RecipientMaterial,
    signed: &Signed,
) -> Result<(Capsule, Payload), ErrorCode> {
    decode_capsule_for(kit, signed, ReceiptContract::Acceptance)
}
pub(super) fn decode_capsule_for(
    kit: &RecipientMaterial,
    signed: &Signed,
    contract: ReceiptContract,
) -> Result<(Capsule, Payload), ErrorCode> {
    let content: Capsule = kit.writer.verify(signed)?;
    if content.schema != 1
        || content.kind != contract.capsule_kind()
        || content.vault_id != kit.vault_id
        || content.profile.validate().is_err()
        || content.profile != contract.profile(content.profile.secret.version)
        || content.expected_generation != content.profile.secret.version - 1
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let ciphertext = crypto::decode(&content.ciphertext, crypto::MAX_DOCUMENT)?;
    let plaintext = kit.recipient.decrypt(&ciphertext.0)?;
    let payload: Payload =
        serde_json::from_slice(&plaintext.0).map_err(|_| ErrorCode::InvalidProviderResult)?;
    validate_payload(&payload, &kit.vault_id, &content.profile.secret)?;
    Ok((content, payload))
}
fn validate_payload(
    p: &Payload,
    vault: &str,
    reference: &SecretReference,
) -> Result<(), ErrorCode> {
    if p.schema != 1
        || p.kind != "aegis.synthetic.secret.v1"
        || p.vault_id != vault
        || p.reference != *reference
        || p.value.len() > 4096
        || p.value != canary(reference.version)?
        || p.value_digest != crypto::hash(p.value.as_bytes())
    {
        return Err(ErrorCode::InvalidProviderResult);
    }
    Ok(())
}
impl Store {
    pub fn check_recipient(&self, recipient: &Recipient) -> Result<(), ErrorCode> {
        self.kit.check_recipient_material(&recipient.kit)?;
        let w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        let r = recipient
            .state
            .lock()
            .map_err(|_| ErrorCode::ReconciliationRequired)?;
        if r.failed {
            return Err(ErrorCode::ReconciliationRequired);
        }
        // Incomplete/unknown operations may already exist at the recipient. Inspection
        // preserves that uncertainty, but completed history must never lose its receipt.
        for (id, op) in &w.history.operations {
            if op.outcome == Some(Outcome::Delivered)
                && r.received
                    .get(id)
                    .is_none_or(|(digest, _)| op.capsule.as_ref() != Some(digest))
            {
                return Err(ErrorCode::ReconciliationRequired);
            }
        }
        for (id, (digest, _)) in &r.received {
            let Some(op) = w.history.operations.get(id) else {
                return Err(ErrorCode::ReconciliationRequired);
            };
            if op.phase != Phase::Handing
                || op.capsule.as_ref() != Some(digest)
                || op.outcome == Some(Outcome::Rejected)
            {
                return Err(ErrorCode::ReconciliationRequired);
            }
        }
        Ok(())
    }
    /// Compare an authenticated process snapshot against broker history. This
    /// never opens a recipient role, capsule, plaintext slot or recipient file.
    pub(super) fn check_process_receipts(
        &self,
        received: &BTreeMap<RequestId, String>,
    ) -> Result<(), ErrorCode> {
        let w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        for (id, op) in &w.history.operations {
            if op.outcome == Some(Outcome::Delivered) && received.get(id) != op.capsule.as_ref() {
                return Err(ErrorCode::ReconciliationRequired);
            }
        }
        for (id, digest) in received {
            let op = w
                .history
                .operations
                .get(id)
                .ok_or(ErrorCode::ReconciliationRequired)?;
            if op.phase != Phase::Handing
                || op.capsule.as_ref() != Some(digest)
                || op.outcome == Some(Outcome::Rejected)
            {
                return Err(ErrorCode::ReconciliationRequired);
            }
        }
        Ok(())
    }
    pub fn deliver(
        &self,
        id: &RequestId,
        recipient: &Recipient,
        at: u64,
    ) -> Result<DeliveryProjection, ErrorCode> {
        self.deliver_via(id, at, |capsule| recipient.accept(capsule))
    }
    /// The reservation, handoff and terminal receipt checks stay in the durable
    /// broker. A transport only exchanges the already-built encrypted capsule.
    pub(super) fn deliver_via(
        &self,
        id: &RequestId,
        at: u64,
        handoff: impl FnOnce(Signed) -> RecipientOutcome,
    ) -> Result<DeliveryProjection, ErrorCode> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| ErrorCode::PersistenceUnavailable)?;
        if w.failed {
            return Err(ErrorCode::PersistenceUnavailable);
        }
        let operation = w
            .history
            .operations
            .get(id)
            .cloned()
            .ok_or(ErrorCode::NotFound)?;
        if operation.outcome.is_some() || operation.phase != Phase::Reserved {
            return Err(ErrorCode::OutcomeUnknown);
        }
        let profile = &operation.review.profile;
        let build_capsule = || -> Result<Signed, ErrorCode> {
            let record = self
                .manifest
                .records
                .iter()
                .find(|r| r.reference == profile.secret)
                .ok_or(ErrorCode::ScopeDenied)?;
            let ciphertext = read_file(
                &self
                    .directory
                    .join(format!("secret-{}.age", profile.secret.version)),
                crypto::MAX_DOCUMENT,
            )?;
            if crypto::hash(&ciphertext) != record.ciphertext_digest {
                return Err(ErrorCode::PersistenceUnavailable);
            }
            let mut clear = self.kit.storage.decrypt(&ciphertext)?;
            if let Some(metadata_digest) = &record.import_metadata_digest {
                let imported = super::entry::protected_entry::decode_imported_for(
                    &clear.0,
                    metadata_digest,
                    &profile.secret,
                    &self.kit,
                    self.manifest.receipt_contract,
                )?;
                let payload = Payload {
                    schema: 1,
                    kind: "aegis.synthetic.secret.v1".into(),
                    vault_id: self.kit.vault_id.clone(),
                    reference: profile.secret.clone(),
                    value: std::str::from_utf8(&imported.0)
                        .map_err(|_| ErrorCode::InvalidProviderResult)?
                        .to_owned(),
                    value_digest: crypto::hash(&imported.0),
                };
                clear = PrivateBytes(
                    serde_json::to_vec(&payload).map_err(|_| ErrorCode::InvalidProviderResult)?,
                );
            }
            let payload: Payload =
                serde_json::from_slice(&clear.0).map_err(|_| ErrorCode::InvalidProviderResult)?;
            validate_payload(&payload, &self.kit.vault_id, &profile.secret)?;
            let encrypted = crypto::encrypt(&clear.0, &self.kit.recipient)?;
            self.kit.writer.sign(&Capsule {
                schema: 1,
                kind: self.manifest.receipt_contract.capsule_kind().into(),
                vault_id: self.kit.vault_id.clone(),
                delivery_id: id.clone(),
                profile: profile.clone(),
                expected_generation: operation.review.operation.expected_generation,
                ciphertext: crypto::encode(&encrypted),
            })
        };
        let capsule = match build_capsule() {
            Ok(value) => value,
            Err(error) => {
                self.append_locked(
                    &mut w,
                    Event::Complete {
                        request_id: id.clone(),
                        outcome: Outcome::Rejected,
                        ack: None,
                    },
                    at,
                )?;
                return Err(error);
            }
        };
        let capsule_digest = crypto::hash(capsule.bytes());
        self.append_locked(
            &mut w,
            Event::Handoff {
                request_id: id.clone(),
                capsule_digest: capsule_digest.clone(),
            },
            at,
        )?;
        // After this point the recipient may have installed a credential. Panic/invalid
        // acknowledgement or failed terminal persistence must retain consumed uncertainty.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handoff(capsule)))
            .unwrap_or(RecipientOutcome::Unknown);
        let (terminal, ack, result) = match outcome {
            RecipientOutcome::Acknowledged(signed) => {
                let valid = self.manifest.receipt_contract.verify_ack(
                    &signed,
                    &self.kit.receipt,
                    &self.kit.vault_id,
                    id,
                    profile,
                    &capsule_digest,
                );
                match valid {
                    Ok(a) => (
                        Outcome::Delivered,
                        Some(
                            std::str::from_utf8(signed.bytes())
                                .expect("ASCII JWS")
                                .to_owned(),
                        ),
                        Ok(DeliveryProjection {
                            delivery_id: id.clone(),
                            recipient_id: a.recipient.id,
                            slot: a.recipient.slot,
                            credential_version: a.version,
                            recipient_generation: a.generation,
                        }),
                    ),
                    Err(_) => (Outcome::Unknown, None, Err(ErrorCode::OutcomeUnknown)),
                }
            }
            RecipientOutcome::Rejected => {
                (Outcome::Rejected, None, Err(ErrorCode::ProviderUnavailable))
            }
            RecipientOutcome::Unknown => (Outcome::Unknown, None, Err(ErrorCode::OutcomeUnknown)),
        };
        if self
            .append_locked(
                &mut w,
                Event::Complete {
                    request_id: id.clone(),
                    outcome: terminal,
                    ack,
                },
                at,
            )
            .is_err()
        {
            return Err(ErrorCode::OutcomeUnknown);
        }
        result
    }
}

#[cfg(test)]
pub(super) struct RecipientPause {
    entered: Mutex<std::sync::mpsc::Sender<()>>,
    released: Mutex<bool>,
    wake: std::sync::Condvar,
}
#[cfg(test)]
impl RecipientPause {
    fn wait(&self) {
        self.entered.lock().unwrap().send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
    pub fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
