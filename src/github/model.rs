use super::{GithubError, RepositoryProjection};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const OWNER: &str = "NathanaelG1";
pub(super) const MAX_REPOSITORIES: usize = 500;
pub(super) const MAX_RECORDS: usize = 32;
pub(super) const MAX_BODY: usize = 16 * 1024;
pub(super) const MAX_TOKEN: usize = 4096;
pub(super) const TOKEN_SECONDS: u64 = 3600;
pub(super) const REFRESH_MARGIN: u64 = 60;
pub(super) const SYNTHETIC_TOKEN: &str =
    "AEGIS_SYNTHETIC_GITHUB_INSTALLATION_TOKEN_NEVER_VALID_7e3f6a";
pub(super) const SYNTHETIC_JWT: &str = "AEGIS_SYNTHETIC_JWT_NOT_A_SIGNATURE";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AccountKind {
    User,
    #[cfg_attr(not(test), allow(dead_code))] // Rejected enrollment exercised by adversarial tests.
    Organization,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Selection {
    Selected,
    #[cfg_attr(not(test), allow(dead_code))] // Never emitted by the fixed fixture.
    All,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Permission {
    Read,
    Write,
}

/// Immutable validated administrative enrollment; no public deserializer/constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Binding {
    pub app_id: u64,
    pub client_id: String,
    pub installation_id: u64,
    pub account_id: u64,
    pub login: String,
    pub account_kind: AccountKind,
    pub selection: Selection,
    pub repositories: Vec<Repository>,
    pub permissions: BTreeMap<String, Permission>,
    pub signer_id: String,
    pub signer_version: u64,
    pub revision: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Repository {
    pub id: u64,
    pub owner_id: u64,
    pub name: String,
}
impl Binding {
    pub fn validate(&self) -> Result<(), GithubError> {
        let valid_id = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        if self.app_id == 0
            || self.installation_id == 0
            || self.account_id == 0
            || self.login != OWNER
            || self.account_kind != AccountKind::User
            || self.selection != Selection::Selected
            || !valid_id(&self.client_id)
            || !valid_id(&self.signer_id)
            || self.signer_version == 0
            || self.revision == 0
            || self.repositories.is_empty()
            || self.repositories.len() > MAX_REPOSITORIES
            || self.permissions.get("metadata") != Some(&Permission::Read)
            || self
                .permissions
                .iter()
                .any(|(key, _)| key != "contents" && key != "metadata")
        {
            return Err(GithubError::InvalidBinding);
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for repo in &self.repositories {
            if repo.id == 0
                || repo.owner_id != self.account_id
                || repo.name.is_empty()
                || repo.name.len() > 100
                || repo.name == "."
                || repo.name == ".."
                || !repo
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                || !ids.insert(repo.id)
                || !names.insert(repo.name.to_ascii_lowercase())
            {
                return Err(GithubError::InvalidBinding);
            }
        }
        Ok(())
    }
    pub fn fixture() -> Self {
        Self {
            app_id: 101,
            client_id: "Iv1_SYNTHETIC_ONLY".into(),
            installation_id: 202,
            account_id: 303,
            login: OWNER.into(),
            account_kind: AccountKind::User,
            selection: Selection::Selected,
            repositories: vec![Repository {
                id: 4242,
                owner_id: 303,
                name: "Aegis".into(),
            }],
            permissions: BTreeMap::from([
                ("contents".into(), Permission::Write),
                ("metadata".into(), Permission::Read),
            ]),
            signer_id: "synthetic-github-key".into(),
            signer_version: 1,
            revision: 1,
        }
    }
}

/// UTC claims need a trusted wall clock; elapsed time bounds cached use independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Moment {
    pub unix: u64,
    pub elapsed: u64,
}
impl Moment {
    pub fn validate_after(self, before: Self) -> Result<(), GithubError> {
        if self.unix < 60 || self.unix < before.unix || self.elapsed < before.elapsed {
            Err(GithubError::ClockInvalid)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct JwtClaims {
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
}
impl JwtClaims {
    pub fn new(binding: &Binding, time: Moment) -> Result<Self, GithubError> {
        Ok(Self {
            iss: binding.client_id.clone(),
            iat: time.unix.checked_sub(60).ok_or(GithubError::ClockInvalid)?,
            exp: time
                .unix
                .checked_add(540)
                .ok_or(GithubError::ClockInvalid)?,
        })
    }
}

/// These bytes never implement Debug/Clone/Serialize and never leave this private module tree.
pub(super) struct Token(pub String);
impl Token {
    pub fn valid_shape(&self) -> bool {
        !self.0.is_empty()
            && self.0.len() <= MAX_TOKEN
            && self.0.bytes().all(|b| (33..=126).contains(&b))
    }
}
pub(super) enum SignedJwt {
    Mock(String),
    #[cfg(all(unix, feature = "signing-spike"))]
    Bound(Box<crate::signing::BoundJwt>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct TokenScope {
    pub repository_ids: Vec<u64>,
    pub permissions: BTreeMap<String, Permission>,
}
impl TokenScope {
    pub fn metadata(repo: &Repository) -> Self {
        Self {
            repository_ids: vec![repo.id],
            permissions: BTreeMap::from([("metadata".into(), Permission::Read)]),
        }
    }
}
/// Mock's already-decoded token response, not a live GitHub HTTP parser.
pub(super) struct TokenEnvelope {
    /// Broker-assigned reference; never derived from token bytes.
    pub mint_request: Option<crate::types::RequestId>,
    pub token: Token,
    pub expires_at: u64,
    pub scope: TokenScope,
}
pub(super) struct Lease {
    pub envelope: TokenEnvelope,
    pub elapsed_deadline: u64,
}
impl Lease {
    pub fn validate(
        envelope: TokenEnvelope,
        scope: &TokenScope,
        started: Moment,
        observed: Moment,
    ) -> Result<Self, (GithubError, TokenEnvelope)> {
        if observed.validate_after(started).is_err() {
            return Err((GithubError::ClockInvalid, envelope));
        }
        let lifetime = envelope.expires_at.checked_sub(started.unix);
        if !envelope.token.valid_shape()
            || envelope.scope != *scope
            || !matches!(lifetime, Some(ttl) if ttl > REFRESH_MARGIN && ttl <= TOKEN_SECONDS)
        {
            return Err((GithubError::InvalidProviderResult, envelope));
        }
        // Anchor to exchange start, not its receipt: a stalled UTC clock or slow
        // exchange must not create another hour of local token authority.
        let Some(elapsed_deadline) = started.elapsed.checked_add(lifetime.expect("checked")) else {
            return Err((GithubError::ClockInvalid, envelope));
        };
        let lease = Self {
            envelope,
            elapsed_deadline,
        };
        if !lease.usable(observed) {
            return Err((GithubError::InvalidProviderResult, lease.envelope));
        }
        Ok(lease)
    }
    pub fn usable(&self, now: Moment) -> bool {
        self.envelope.expires_at.saturating_sub(now.unix) > REFRESH_MARGIN
            && self.elapsed_deadline.saturating_sub(now.elapsed) > REFRESH_MARGIN
    }
    pub fn expired(&self, now: Moment) -> bool {
        now.unix >= self.envelope.expires_at && now.elapsed >= self.elapsed_deadline
    }
}

#[derive(Deserialize)]
struct RawOwner {
    id: u64,
    login: String,
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
struct RawMetadata {
    id: u64,
    owner: RawOwner,
    name: String,
    private: bool,
    archived: bool,
}
pub(super) fn project(
    body: &[u8],
    binding: &Binding,
    repo: &Repository,
) -> Result<RepositoryProjection, GithubError> {
    if body.len() > MAX_BODY {
        return Err(GithubError::InvalidProviderResult);
    }
    let raw: RawMetadata =
        serde_json::from_slice(body).map_err(|_| GithubError::InvalidProviderResult)?;
    if raw.id != repo.id
        || raw.owner.id != binding.account_id
        || raw.owner.login != binding.login
        || raw.owner.kind != "User"
        || raw.name != repo.name
    {
        return Err(GithubError::InvalidProviderResult);
    }
    Ok(RepositoryProjection {
        repository_id: raw.id,
        private: raw.private,
        archived: raw.archived,
    })
}
