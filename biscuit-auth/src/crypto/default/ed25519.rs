/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! cryptographic operations
//!
//! Biscuit tokens are based on a chain of Ed25519 signatures.
//! This provides the fundamental operation for offline delegation: from a message
//! and a valid signature, it is possible to add a new message and produce a valid
//! signature for the whole.
//!
//! The implementation is based on [ed25519_dalek](https://github.com/dalek-cryptography/ed25519-dalek).
#![allow(non_snake_case)]

use crate::{error, error::Format};
use std::convert::TryInto;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

use crate::crypto::{KeyPairImpl, KeySerialization, PrivateKeyImpl, PublicKeyImpl, Signature};
use crate::format::schema::public_key::Algorithm;
use ed25519_dalek::*;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

#[cfg(feature = "pem")]
impl crate::crypto::KeyPemSerialization for PublicKey {
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        let pubkey = VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| Format::InvalidKey(e.to_string()))?;
        Ok(Self(pubkey))
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        let pubkey = VerifyingKey::from_public_key_pem(str)
            .map_err(|e| Format::InvalidKey(e.to_string()))?;
        Ok(Self(pubkey))
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        self.0
            .to_public_key_der()
            .map(|b| b.to_vec())
            .map_err(|e| Format::PKCS8(e.to_string()))
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::EncodePublicKey;
        self.0
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Format::PKCS8(e.to_string()))
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.algorithm() as i32).hash(state);
        self.0.as_bytes().hash(state);
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ed25519/{}", self.to_bytes_hex())
    }
}

impl KeySerialization for PublicKey {
    type Bytes = Vec<u8>;
    type String = String;

    fn to_bytes(&self) -> Self::Bytes {
        self.0.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)
    }
}

impl PublicKeyImpl for PublicKey {
    fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<(), Format> {
        let signature_bytes: [u8; 64] = signature.0.as_slice().try_into().map_err(|e| {
            Format::BlockDeserializationError(format!(
                "block signature deserialization error: {:?}",
                e
            ))
        })?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        self.0
            .verify_strict(data, &sig)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignature)
            .map_err(Format::Signature)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(SecretKey);

#[cfg(feature = "pem")]
impl crate::crypto::KeyPemSerialization for PrivateKey {
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_der(bytes)
            .map(|kp| Self(kp.to_bytes()))
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(str)
            .map(|kp| Self(kp.to_bytes()))
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let kp = SigningKey::from_bytes(&self.0);
        kp.to_pkcs8_der()
            .map(|d| d.to_bytes())
            .map_err(|e| Format::PKCS8(e.to_string()))
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let kp = SigningKey::from_bytes(&self.0);
        kp.to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Format::PKCS8(e.to_string()))
    }
}

impl KeySerialization for PrivateKey {
    type Bytes = Zeroizing<Vec<u8>>;
    type String = Zeroizing<String>;

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_vec().into()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl PrivateKeyImpl for PrivateKey {
    type PublicKey = PublicKey;

    fn public(&self) -> Self::PublicKey {
        let kp = SigningKey::from_bytes(&self.0);
        PublicKey(kp.verifying_key())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
}

#[derive(Debug, PartialEq)]
pub struct KeyPair(SigningKey);

impl KeyPairImpl for KeyPair {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    fn sign(&self, data: &[u8]) -> Result<Signature, Format> {
        Ok(Signature(
            self.0
                .try_sign(data)
                .map_err(|s| s.to_string())
                .map_err(error::Signature::InvalidSignatureGeneration)
                .map_err(Format::Signature)?
                .to_bytes()
                .to_vec(),
        ))
    }

    fn from_private(key: &Self::PrivateKey) -> Self {
        Self(SigningKey::from(key.0))
    }

    fn public(&self) -> Self::PublicKey {
        PublicKey(self.0.verifying_key())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn private(&self) -> Self::PrivateKey {
        PrivateKey(self.0.to_bytes())
    }

    fn generate() -> Self {
        Self::generate_with_rng(&mut rand::rngs::OsRng)
    }

    fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let kp = SigningKey::generate(rng);
        Self(kp)
    }
}
