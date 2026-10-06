//! Optional synthetic-only age recovery feasibility experiment.
//!
//! This module deliberately cannot accept credential values. It only encrypts and validates
//! one fixed synthetic fixture. It has no operational vault, commit, rekey, or unlock API.
//! File drills are supported only on Unix; their same-user workflow is not containment.

use age::secrecy::zeroize::Zeroize;
#[cfg(unix)]
use age::secrecy::ExposeSecret;
use serde::Deserialize;
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;

/// Deliberately small experimental bounds, not production vault limits.
pub const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;
pub const MAX_PLAINTEXT_BYTES: usize = 4 * 1024;
pub const MAX_RECOVERY_KEY_BYTES: usize = 256;

const CANARY: &str = "AEGIS_SYNTHETIC_RECOVERY_CANARY_NO_REAL_CREDENTIAL";
const VAULT_ID: &str = "aegis-synthetic-vault-v1";
const ORIGINAL: &str = r#"{
  "schema_version": 1,
  "kind": "aegis.synthetic.recovery.v1",
  "vault_id": "aegis-synthetic-vault-v1",
  "generation": 1,
  "credentials": [{"id":"synthetic-status","version":1,"canary":"AEGIS_SYNTHETIC_RECOVERY_CANARY_NO_REAL_CREDENTIAL"}],
  "profiles": [{"id":"synthetic-issue-status","revision":1,"credential_id":"synthetic-status","credential_version":1,"operation":"fake.issue-status.v1","resource":"synthetic/project-a","output_contract":"issue-status.v1"}],
  "grants": [{"id":"synthetic-grant","profile_id":"synthetic-issue-status","profile_revision":1,"enabled":true,"remaining_uses":1}],
  "sessions": ["synthetic-session"]
}"#;
#[cfg(unix)]
const RESTORED: &str = r#"{
  "schema_version": 1,
  "kind": "aegis.synthetic.recovery.v1",
  "vault_id": "aegis-synthetic-vault-v1",
  "generation": 1,
  "credentials": [{"id":"synthetic-status","version":1,"canary":"AEGIS_SYNTHETIC_RECOVERY_CANARY_NO_REAL_CREDENTIAL"}],
  "profiles": [{"id":"synthetic-issue-status","revision":1,"credential_id":"synthetic-status","credential_version":1,"operation":"fake.issue-status.v1","resource":"synthetic/project-a","output_contract":"issue-status.v1"}],
  "grants": [{"id":"synthetic-grant","profile_id":"synthetic-issue-status","profile_revision":1,"enabled":false,"remaining_uses":1}],
  "sessions": []
}"#;

/// Private generated identity. No `Debug`, `Clone`, serialization, or value accessor.
pub struct SyntheticKey(age::x25519::Identity);

impl SyntheticKey {
    /// Generate a fresh key solely for the synthetic experiment.
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }
}

/// Fixed non-sensitive failures. Native parser/crypto/IO errors are never forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpikeError {
    CiphertextTooLarge,
    PlaintextTooLarge,
    InvalidCiphertext,
    UnsupportedEncryption,
    DecryptionFailed,
    InvalidSnapshot,
    UnsupportedSchema,
    FixtureMismatch,
    InvalidRecoveryKey,
    InvalidPath,
    DestinationExists,
    UnsafeFile,
    Io,
    UnsupportedPlatform,
}

impl fmt::Display for SpikeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::PlaintextTooLarge => "plaintext_too_large",
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::UnsupportedEncryption => "unsupported_encryption",
            Self::DecryptionFailed => "decryption_failed",
            Self::InvalidSnapshot => "invalid_snapshot",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::FixtureMismatch => "synthetic_fixture_mismatch",
            Self::InvalidRecoveryKey => "invalid_recovery_key",
            Self::InvalidPath => "invalid_path",
            Self::DestinationExists => "destination_exists",
            Self::UnsafeFile => "unsafe_file",
            Self::Io => "storage_spike_io_error",
            Self::UnsupportedPlatform => "unsupported_platform",
        };
        f.write_str(code)
    }
}

impl std::error::Error for SpikeError {}

/// Non-sensitive evidence. No credential record or authorization object is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySummary {
    pub schema_version: u16,
    pub validated_credentials: usize,
    pub validated_profiles: usize,
    pub disabled_grants: usize,
    pub enabled_grants: usize,
    pub restored_sessions: usize,
}

// Secret-bearing deserialized records deliberately have neither Debug nor Serialize.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u16,
    kind: String,
    vault_id: String,
    generation: u64,
    credentials: Vec<Credential>,
    profiles: Vec<Profile>,
    grants: Vec<Grant>,
    sessions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    id: String,
    version: u64,
    canary: String,
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.canary.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    id: String,
    revision: u64,
    credential_id: String,
    credential_version: u64,
    operation: String,
    resource: String,
    output_contract: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: String,
    profile_id: String,
    profile_revision: u64,
    enabled: bool,
    remaining_uses: u64,
}

struct PrivateBytes(Vec<u8>);

impl Drop for PrivateBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypt only the built-in fixture to two independent standard X25519 recipients.
pub fn encrypt_synthetic_fixture(
    local: &SyntheticKey,
    recovery: &SyntheticKey,
) -> Result<Vec<u8>, SpikeError> {
    encrypt_fixed(ORIGINAL.as_bytes(), local, recovery)
}

fn encrypt_fixed(
    fixture: &[u8],
    local: &SyntheticKey,
    recovery: &SyntheticKey,
) -> Result<Vec<u8>, SpikeError> {
    let local_recipient = local.0.to_public();
    let recovery_recipient = recovery.0.to_public();
    if local_recipient == recovery_recipient {
        return Err(SpikeError::FixtureMismatch);
    }
    let recipients: [&dyn age::Recipient; 2] = [&local_recipient, &recovery_recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|_| SpikeError::InvalidCiphertext)?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| SpikeError::Io)?;
    writer.write_all(fixture).map_err(|_| SpikeError::Io)?;
    writer.finish().map_err(|_| SpikeError::Io)?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(SpikeError::CiphertextTooLarge);
    }
    Ok(ciphertext)
}

/// Authenticate the entire age payload, validate every fixed fixture binding, then
/// report the restore projection with all grants disabled and no sessions retained.
/// Does not return plaintext and does not attach authority to a running broker.
pub fn validate_synthetic_restore(
    ciphertext: &[u8],
    key: &SyntheticKey,
) -> Result<RecoverySummary, SpikeError> {
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(SpikeError::CiphertextTooLarge);
    }
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| SpikeError::InvalidCiphertext)?;
    if decryptor.is_scrypt() {
        return Err(SpikeError::UnsupportedEncryption);
    }
    let reader = decryptor
        .decrypt(std::iter::once(&key.0 as &dyn age::Identity))
        .map_err(|_| SpikeError::DecryptionFailed)?;
    let mut plaintext = PrivateBytes(Vec::with_capacity(MAX_PLAINTEXT_BYTES + 1));
    reader
        .take((MAX_PLAINTEXT_BYTES + 1) as u64)
        .read_to_end(&mut plaintext.0)
        .map_err(|_| SpikeError::DecryptionFailed)?;
    if plaintext.0.len() > MAX_PLAINTEXT_BYTES {
        return Err(SpikeError::PlaintextTooLarge);
    }
    // Reading to EOF above is required: age verifies the final authenticated chunk.
    let snapshot: Snapshot =
        serde_json::from_slice(&plaintext.0).map_err(|_| SpikeError::InvalidSnapshot)?;
    validate_snapshot(&snapshot)?;
    Ok(RecoverySummary {
        schema_version: 1,
        validated_credentials: 1,
        validated_profiles: 1,
        disabled_grants: snapshot.grants.len(),
        enabled_grants: 0,
        restored_sessions: 0,
    })
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), SpikeError> {
    if snapshot.schema_version != 1 {
        return Err(SpikeError::UnsupportedSchema);
    }
    if snapshot.kind != "aegis.synthetic.recovery.v1"
        || snapshot.vault_id != VAULT_ID
        || snapshot.generation != 1
        || snapshot.credentials.len() != 1
        || snapshot.profiles.len() != 1
        || snapshot.grants.len() != 1
        || !(snapshot.sessions.is_empty() || snapshot.sessions == ["synthetic-session".to_owned()])
    {
        return Err(SpikeError::FixtureMismatch);
    }
    let credential = &snapshot.credentials[0];
    let profile = &snapshot.profiles[0];
    let grant = &snapshot.grants[0];
    if credential.id != "synthetic-status"
        || credential.version != 1
        || credential.canary != CANARY
        || profile.id != "synthetic-issue-status"
        || profile.revision != 1
        || profile.credential_id != credential.id
        || profile.credential_version != credential.version
        || profile.operation != "fake.issue-status.v1"
        || profile.resource != "synthetic/project-a"
        || profile.output_contract != "issue-status.v1"
        || grant.id != "synthetic-grant"
        || grant.profile_id != profile.id
        || grant.profile_revision != profile.revision
        || grant.remaining_uses != 1
        || (grant.enabled && snapshot.sessions.is_empty())
        || (!grant.enabled && !snapshot.sessions.is_empty())
    {
        return Err(SpikeError::FixtureMismatch);
    }
    Ok(())
}

/// Create two NEW sibling-independent directories containing a fixed encrypted
/// snapshot and an independently saved recovery kit. No local key is persisted.
/// Never verifies recovery in this setup process; the caller must exit first.
pub fn create_saved_synthetic_drill(
    snapshot_directory: &Path,
    recovery_directory: &Path,
) -> Result<(), SpikeError> {
    #[cfg(unix)]
    {
        files::create_drill(snapshot_directory, recovery_directory)
    }
    #[cfg(not(unix))]
    {
        let _ = (snapshot_directory, recovery_directory);
        Err(SpikeError::UnsupportedPlatform)
    }
}

/// Recover with ONLY the independently saved kit and saved snapshot in a new
/// destination. A fixed disabled snapshot is encrypted to a fresh transient local
/// recipient plus the saved recovery recipient. No old session/grant is activated.
pub fn recover_saved_synthetic_drill(
    snapshot_directory: &Path,
    recovery_directory: &Path,
    new_destination: &Path,
) -> Result<RecoverySummary, SpikeError> {
    #[cfg(unix)]
    {
        files::recover_drill(snapshot_directory, recovery_directory, new_destination)
    }
    #[cfg(not(unix))]
    {
        let _ = (snapshot_directory, recovery_directory, new_destination);
        Err(SpikeError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
mod files {
    use super::*;
    use std::fs::{self, DirBuilder, File, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    use std::path::{Component, PathBuf};

    fn absolute_without_symlinks(path: &Path) -> Result<(), SpikeError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(SpikeError::InvalidPath);
        }
        let mut prefix = PathBuf::new();
        for part in path.components() {
            prefix.push(part);
            match fs::symlink_metadata(&prefix) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(SpikeError::UnsafeFile)
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(_) => return Err(SpikeError::Io),
            }
        }
        Ok(())
    }

    fn require_new(path: &Path) -> Result<(), SpikeError> {
        absolute_without_symlinks(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => Err(SpikeError::DestinationExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(SpikeError::InvalidPath)?;
                if !fs::metadata(parent).map_err(|_| SpikeError::Io)?.is_dir() {
                    return Err(SpikeError::InvalidPath);
                }
                Ok(())
            }
            Err(_) => Err(SpikeError::Io),
        }
    }

    fn create_directory(path: &Path) -> Result<(), SpikeError> {
        DirBuilder::new().mode(0o700).create(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                SpikeError::DestinationExists
            } else {
                SpikeError::Io
            }
        })
    }

    fn write_new(path: &Path, bytes: &[u8]) -> Result<(), SpikeError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| SpikeError::Io)?;
        file.write_all(bytes).map_err(|_| SpikeError::Io)?;
        file.sync_all().map_err(|_| SpikeError::Io)
    }

    fn sync_directory(path: &Path) -> Result<(), SpikeError> {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| SpikeError::Io)
    }

    fn read_bounded(path: &Path, bound: usize) -> Result<PrivateBytes, SpikeError> {
        absolute_without_symlinks(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| SpikeError::Io)?;
        let metadata = file.metadata().map_err(|_| SpikeError::Io)?;
        if !metadata.is_file() {
            return Err(SpikeError::UnsafeFile);
        }
        if metadata.len() > bound as u64 {
            return Err(if bound == MAX_RECOVERY_KEY_BYTES {
                SpikeError::InvalidRecoveryKey
            } else {
                SpikeError::CiphertextTooLarge
            });
        }
        let mut bytes = PrivateBytes(Vec::with_capacity(bound + 1));
        file.take((bound + 1) as u64)
            .read_to_end(&mut bytes.0)
            .map_err(|_| SpikeError::Io)?;
        if bytes.0.len() > bound {
            return Err(SpikeError::Io);
        }
        Ok(bytes)
    }

    pub(super) fn create_drill(
        snapshot_directory: &Path,
        recovery_directory: &Path,
    ) -> Result<(), SpikeError> {
        require_new(snapshot_directory)?;
        require_new(recovery_directory)?;
        if snapshot_directory == recovery_directory
            || snapshot_directory.starts_with(recovery_directory)
            || recovery_directory.starts_with(snapshot_directory)
        {
            return Err(SpikeError::InvalidPath);
        }
        let local = SyntheticKey::generate();
        let recovery = SyntheticKey::generate();
        let ciphertext = encrypt_synthetic_fixture(&local, &recovery)?;
        let serialized_key = recovery.0.to_string();
        create_directory(snapshot_directory)?;
        create_directory(recovery_directory)?;
        write_new(
            &recovery_directory.join("recovery-key.txt"),
            serialized_key.expose_secret().as_bytes(),
        )?;
        write_new(&snapshot_directory.join("snapshot.age"), &ciphertext)?;
        sync_directory(recovery_directory)?;
        sync_directory(snapshot_directory)?;
        // Both identities and serialized private key drop here. No validation in this process.
        Ok(())
    }

    pub(super) fn recover_drill(
        snapshot_directory: &Path,
        recovery_directory: &Path,
        new_destination: &Path,
    ) -> Result<RecoverySummary, SpikeError> {
        require_new(new_destination)?;
        if new_destination.starts_with(snapshot_directory)
            || new_destination.starts_with(recovery_directory)
        {
            return Err(SpikeError::InvalidPath);
        }
        let saved_key = read_bounded(
            &recovery_directory.join("recovery-key.txt"),
            MAX_RECOVERY_KEY_BYTES,
        )?;
        let key_text =
            std::str::from_utf8(&saved_key.0).map_err(|_| SpikeError::InvalidRecoveryKey)?;
        if !key_text.starts_with("AGE-SECRET-KEY-") || key_text.contains(['\r', '\n']) {
            return Err(SpikeError::InvalidRecoveryKey);
        }
        let recovery = SyntheticKey(
            key_text
                .parse()
                .map_err(|_| SpikeError::InvalidRecoveryKey)?,
        );
        let ciphertext = read_bounded(
            &snapshot_directory.join("snapshot.age"),
            MAX_CIPHERTEXT_BYTES,
        )?;
        let summary = validate_synthetic_restore(&ciphertext.0, &recovery)?;
        let local = SyntheticKey::generate();
        let restored = encrypt_fixed(RESTORED.as_bytes(), &local, &recovery)?;
        create_directory(new_destination)?;
        write_new(&new_destination.join("snapshot.age"), &restored)?;
        sync_directory(new_destination)?;
        // New local key is transient; only the saved recovery kit can open this drill output.
        Ok(summary)
    }
}
