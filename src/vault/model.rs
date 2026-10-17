use crate::{ErrorCode, ProfileId, RequestId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    pub id: String,
    pub version: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientBinding {
    pub id: String,
    pub revision: u64,
    pub configuration_revision: u64,
    pub slot: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryParameters {
    pub secret: SecretReference,
    pub recipient: RecipientBinding,
    pub repository_id: u64,
    pub expected_generation: u64,
}
impl DeliveryParameters {
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        if self.secret.id != "synthetic-provider-key"
            || !matches!(self.secret.version, 1 | 2)
            || self.recipient != RecipientBinding::fixture()
            || self.repository_id != 4242
            || self.expected_generation != self.secret.version - 1
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
    pub(crate) fn fixture(version: u64) -> Self {
        Self {
            secret: SecretReference {
                id: "synthetic-provider-key".into(),
                version,
            },
            recipient: RecipientBinding::fixture(),
            repository_id: 4242,
            expected_generation: version - 1,
        }
    }
}
impl RecipientBinding {
    pub(crate) fn fixture() -> Self {
        Self {
            id: "synthetic-recipient".into(),
            revision: 1,
            configuration_revision: 1,
            slot: "provider-auth".into(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProfile {
    pub id: ProfileId,
    pub revision: u64,
    pub repository_id: u64,
    pub secret: SecretReference,
    pub recipient: RecipientBinding,
    pub acl_revision: u64,
    pub adapter_contract: u32,
    pub output_contract: u32,
}
impl DeliveryProfile {
    pub(crate) fn fixture(version: u64) -> Self {
        Self {
            id: ProfileId::new("vault-delivery").expect("constant"),
            revision: version,
            repository_id: 4242,
            secret: DeliveryParameters::fixture(version).secret,
            recipient: RecipientBinding::fixture(),
            acl_revision: 1,
            adapter_contract: 1,
            output_contract: 1,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ErrorCode> {
        if !matches!(self.secret.version, 1 | 2) || *self != Self::fixture(self.secret.version) {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
    pub(crate) fn permits(&self, p: &DeliveryParameters) -> bool {
        p.validate().is_ok()
            && p.secret == self.secret
            && p.recipient == self.recipient
            && p.repository_id == self.repository_id
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryProjection {
    pub delivery_id: RequestId,
    pub recipient_id: String,
    pub slot: String,
    pub credential_version: u64,
    pub recipient_generation: u64,
}
impl DeliveryProjection {
    pub(crate) fn matches(&self, id: &RequestId, p: &DeliveryParameters) -> bool {
        self.delivery_id == *id
            && self.recipient_id == p.recipient.id
            && self.slot == p.recipient.slot
            && self.credential_version == p.secret.version
            && self.recipient_generation == p.secret.version
    }
}
