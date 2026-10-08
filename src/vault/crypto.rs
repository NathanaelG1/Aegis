//! Maintained age and JWS primitives. This module exports no plaintext/key accessor
//! outside the private vault implementation. It does not provide host-memory isolation.
use crate::ErrorCode;
use age::secrecy::ExposeSecret;
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::KeyPair,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::Zeroize;

pub(super) const MAX_DOCUMENT: usize = 64 * 1024;
pub(super) const MAX_CLEAR: usize = 16 * 1024;
pub(super) struct PrivateBytes(pub(super) Vec<u8>);
impl Drop for PrivateBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
pub(super) struct Signed(String);
impl Signed {
    pub(super) fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT || !bytes.is_ascii() {
            return Err(ErrorCode::AuthenticationRequired);
        }
        Ok(Self(
            std::str::from_utf8(bytes)
                .map_err(|_| ErrorCode::AuthenticationRequired)?
                .into(),
        ))
    }
}
impl Drop for Signed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
#[derive(Clone)]
pub(super) struct Verifier {
    key: DecodingKey,
}
pub(super) struct SigningKey {
    der: PrivateBytes,
    key: EncodingKey,
    verify: Verifier,
}
impl SigningKey {
    pub(super) fn generate() -> Result<Self, ErrorCode> {
        crate::signing::require_fixed_provider().map_err(|_| ErrorCode::ProviderUnavailable)?;
        let native =
            RsaKeyPair::generate(KeySize::Rsa2048).map_err(|_| ErrorCode::ProviderUnavailable)?;
        let der: Pkcs8V1Der<'static> = native
            .as_der()
            .map_err(|_| ErrorCode::ProviderUnavailable)?;
        Self::from_fixture_der(der.as_ref())
    }
    pub(super) fn from_fixture_der(der: &[u8]) -> Result<Self, ErrorCode> {
        if der.len() > 4096 {
            return Err(ErrorCode::InvalidRequest);
        }
        crate::signing::require_fixed_provider().map_err(|_| ErrorCode::ProviderUnavailable)?;
        let native = RsaKeyPair::from_pkcs8(der).map_err(|_| ErrorCode::InvalidRequest)?;
        if native.public_modulus_len() != 256 {
            return Err(ErrorCode::InvalidRequest);
        }
        let parsed =
            pkcs8::PrivateKeyInfoRef::try_from(der).map_err(|_| ErrorCode::InvalidRequest)?;
        if parsed.algorithm.oid != pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
            || parsed.public_key.is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            der: PrivateBytes(der.to_vec()),
            key: EncodingKey::from_rsa_der(parsed.private_key.as_bytes()),
            verify: Verifier {
                key: DecodingKey::from_rsa_der(native.public_key().as_ref()),
            },
        })
    }
    pub(super) fn fixture_der(&self) -> &[u8] {
        &self.der.0
    }
    pub(super) fn verifier(&self) -> Verifier {
        self.verify.clone()
    }
    #[cfg(test)]
    pub(super) fn sign_raw(&self, header: &str, payload: &str) -> Signed {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = jsonwebtoken::crypto::sign(message.as_bytes(), &self.key, Algorithm::RS256)
            .expect("synthetic signature");
        Signed(format!("{message}.{signature}"))
    }

    pub(super) fn sign<T: Serialize>(&self, value: &T) -> Result<Signed, ErrorCode> {
        crate::signing::require_fixed_provider().map_err(|_| ErrorCode::ProviderUnavailable)?;
        let value = Signed(
            jsonwebtoken::encode(&Header::new(Algorithm::RS256), value, &self.key)
                .map_err(|_| ErrorCode::ProviderUnavailable)?,
        );
        if value.0.len() > MAX_DOCUMENT {
            return Err(ErrorCode::CapacityExceeded);
        }
        Ok(value)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHeader {
    alg: String,
    typ: String,
}
impl Verifier {
    pub(super) fn verify<T: DeserializeOwned>(&self, value: &Signed) -> Result<T, ErrorCode> {
        crate::signing::require_fixed_provider().map_err(|_| ErrorCode::ProviderUnavailable)?;
        let invalid = || ErrorCode::AuthenticationRequired;
        let parts: Vec<_> = value.0.split('.').collect();
        if parts.len() != 3
            || parts.iter().any(|v| v.is_empty())
            || parts[0].len() > 512
            || value.0.len() > MAX_DOCUMENT
        {
            return Err(invalid());
        }
        let header = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| invalid())?;
        let payload = PrivateBytes(URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid())?);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| invalid())?;
        if payload.0.len() > MAX_CLEAR
            || signature.len() != 256
            || URL_SAFE_NO_PAD.encode(&header) != parts[0]
            || URL_SAFE_NO_PAD.encode(&payload.0) != parts[1]
            || URL_SAFE_NO_PAD.encode(&signature) != parts[2]
        {
            return Err(invalid());
        }
        let h: StrictHeader = serde_json::from_slice(&header).map_err(|_| invalid())?;
        if h.alg != "RS256" || h.typ != "JWT" {
            return Err(invalid());
        }
        let mut policy = Validation::new(Algorithm::RS256);
        policy.set_required_spec_claims(&[] as &[&str]);
        policy.validate_exp = false;
        policy.validate_nbf = false;
        policy.validate_aud = false;
        policy.leeway = 0;
        // These are purpose-specific signed documents. Authentication expiry/audience
        // checks are mandatory in auth.rs; durable ledger records intentionally do not expire.
        jsonwebtoken::decode::<T>(&value.0, &self.key, &policy)
            .map(|v| v.claims)
            .map_err(|_| invalid())
    }
}
pub(super) fn hash(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes).as_ref())
}
pub(super) fn random_id() -> Result<String, ErrorCode> {
    let mut bytes = [0; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ErrorCode::BrokerUnavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub(super) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(super) fn decode(value: &str, limit: usize) -> Result<PrivateBytes, ErrorCode> {
    if value.len() > limit.saturating_mul(2) {
        return Err(ErrorCode::CapacityExceeded);
    }
    let bytes = PrivateBytes(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| ErrorCode::InvalidRequest)?,
    );
    if bytes.0.len() > limit || URL_SAFE_NO_PAD.encode(&bytes.0) != value {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(bytes)
}
pub(super) struct Identity(age::x25519::Identity);
impl Identity {
    pub(super) fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }
    pub(super) fn recipient(&self) -> age::x25519::Recipient {
        self.0.to_public()
    }
    pub(super) fn fixture_encode(&self) -> PrivateBytes {
        PrivateBytes(self.0.to_string().expose_secret().as_bytes().to_vec())
    }
    pub(super) fn fixture_parse(bytes: &[u8]) -> Result<Self, ErrorCode> {
        if bytes.len() > 256 {
            return Err(ErrorCode::InvalidRequest);
        }
        let s = std::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
        Ok(Self(s.parse().map_err(|_| ErrorCode::InvalidRequest)?))
    }
    pub(super) fn decrypt(&self, ciphertext: &[u8]) -> Result<PrivateBytes, ErrorCode> {
        if ciphertext.len() > MAX_DOCUMENT {
            return Err(ErrorCode::CapacityExceeded);
        }
        let decryptor = age::Decryptor::new(ciphertext).map_err(|_| ErrorCode::InvalidRequest)?;
        if decryptor.is_scrypt() {
            return Err(ErrorCode::InvalidRequest);
        }
        let reader = decryptor
            .decrypt(std::iter::once(&self.0 as &dyn age::Identity))
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let mut bytes = PrivateBytes(Vec::with_capacity(MAX_CLEAR + 1));
        reader
            .take((MAX_CLEAR + 1) as u64)
            .read_to_end(&mut bytes.0)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        if bytes.0.len() > MAX_CLEAR {
            return Err(ErrorCode::CapacityExceeded);
        }
        Ok(bytes)
    }
}
pub(super) fn encrypt(
    bytes: &[u8],
    recipient: &age::x25519::Recipient,
) -> Result<Vec<u8>, ErrorCode> {
    if bytes.len() > MAX_CLEAR {
        return Err(ErrorCode::CapacityExceeded);
    }
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(|_| ErrorCode::ProviderUnavailable)?;
    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|_| ErrorCode::ProviderUnavailable)?;
    writer
        .write_all(bytes)
        .map_err(|_| ErrorCode::ProviderUnavailable)?;
    writer
        .finish()
        .map_err(|_| ErrorCode::ProviderUnavailable)?;
    if output.len() > MAX_DOCUMENT {
        return Err(ErrorCode::CapacityExceeded);
    }
    Ok(output)
}
