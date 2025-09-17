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
use crate::{error::Format, format::schema};

use super::error;
use super::Signature;
#[cfg(feature = "pem")]
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::Signer;
use ed25519_dalek::*;
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryInto, hash::Hash, ops::Drop};
use zeroize::Zeroize;

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug, PartialEq)]
pub struct KeyPair {
    pub(super) kp: ed25519_dalek::SigningKey,
}

impl KeyPair {
    pub fn new() -> Self {
        Self::new_with_rng(&mut rand::rng())
    }

    pub fn new_with_rng<T: RngCore + CryptoRng + ?Sized>(rng: &mut T) -> Self {
        let kp = ed25519_dalek::SigningKey::generate(rng);
        KeyPair { kp }
    }

    pub fn from(key: &PrivateKey) -> Self {
        KeyPair {
            kp: ed25519_dalek::SigningKey::from_bytes(&key.0),
        }
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;

        Ok(KeyPair {
            kp: ed25519_dalek::SigningKey::from_bytes(&bytes),
        })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        Ok(Signature(
            self.kp
                .try_sign(&data)
                .map_err(|s| s.to_string())
                .map_err(error::Signature::InvalidSignatureGeneration)
                .map_err(error::Format::Signature)?
                .to_bytes()
                .to_vec(),
        ))
    }

    pub fn private(&self) -> PrivateKey {
        PrivateKey(self.kp.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.kp.verifying_key())
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        crate::format::schema::public_key::Algorithm::Ed25519
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        let kp = SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        let kp = SigningKey::from_pkcs8_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let kp = self
            .kp
            .to_pkcs8_der()
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp.to_bytes())
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use p256::pkcs8::LineEnding;
        let kp = self
            .kp
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp)
    }
}

impl std::default::Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// the private part of a [KeyPair]
#[derive(Debug, PartialEq)]
pub struct PrivateKey(pub(crate) ed25519_dalek::SecretKey);

impl PrivateKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;
        Ok(PrivateKey(bytes))
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        let kp = SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PrivateKey(kp.to_bytes()))
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        let kp = SigningKey::from_pkcs8_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PrivateKey(kp.to_bytes()))
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let kp = ed25519_dalek::SigningKey::from_bytes(&self.0)
            .to_pkcs8_der()
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp.to_bytes())
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use p256::pkcs8::LineEnding;
        let kp = ed25519_dalek::SigningKey::from_bytes(&self.0)
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp)
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        PublicKey(SigningKey::from_bytes(&self.0).verifying_key())
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        crate::format::schema::public_key::Algorithm::Ed25519
    }
}

impl std::clone::Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey::from_bytes(&self.to_bytes()).unwrap()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, Eq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;

        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map(PublicKey)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_proto(key: &schema::PublicKey) -> Result<Self, error::Format> {
        if key.algorithm != schema::public_key::Algorithm::Ed25519 as i32 {
            return Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                key.algorithm
            )));
        }

        PublicKey::from_bytes(&key.key)
    }

    pub fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: schema::public_key::Algorithm::Ed25519 as i32,
            key: self.to_bytes().to_vec(),
        }
    }

    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format> {
        let signature_bytes: [u8; 64] = signature.0.clone().try_into().map_err(|e| {
            error::Format::BlockSignatureDeserializationError(format!(
                "block signature deserialization error: {:?}",
                e
            ))
        })?;
        let sig = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        self.0
            .verify_strict(&data, &sig)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignature)
            .map_err(error::Format::Signature)
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        crate::format::schema::public_key::Algorithm::Ed25519
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let pubkey = ed25519_dalek::VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PublicKey(pubkey))
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let pubkey = ed25519_dalek::VerifyingKey::from_public_key_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PublicKey(pubkey))
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<Vec<u8>, error::Format> {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        let kp = self
            .0
            .to_public_key_der()
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp.to_vec())
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String, error::Format> {
        use ed25519_dalek::pkcs8::EncodePublicKey;
        use p256::pkcs8::LineEnding;
        let kp = self
            .0
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp)
    }

    pub(crate) fn write(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ed25519/{}", hex::encode(&self.to_bytes()))
    }

    pub fn print(&self) -> String {
        format!("ed25519/{}", hex::encode(&self.to_bytes()))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (crate::format::schema::public_key::Algorithm::Ed25519 as i32).hash(state);
        self.0.to_bytes().hash(state);
    }
}
