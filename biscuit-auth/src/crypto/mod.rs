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
use crate::builder::Algorithm;
use crate::format::schema;
use crate::format::ThirdPartyVerificationMode;

use super::error;
mod ed25519;
mod p256;

use nom::Finish;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug, PartialEq)]
pub enum KeyPair {
    Ed25519(ed25519::KeyPair),
    P256(p256::KeyPair),
}

impl KeyPair {
    /// Create a new ed25519 keypair with the default OS RNG
    pub fn new() -> Self {
        Self::new_with_rng(Algorithm::Ed25519, &mut rand::rngs::OsRng)
    }

    /// Create a new keypair with a chosen algorithm and the default OS RNG
    pub fn new_with_algorithm(algorithm: Algorithm) -> Self {
        Self::new_with_rng(algorithm, &mut rand::rngs::OsRng)
    }

    pub fn new_with_rng<T: RngCore + CryptoRng>(algorithm: Algorithm, rng: &mut T) -> Self {
        match algorithm {
            Algorithm::Ed25519 => KeyPair::Ed25519(ed25519::KeyPair::new_with_rng(rng)),
            Algorithm::Secp256r1 => KeyPair::P256(p256::KeyPair::new_with_rng(rng)),
        }
    }

    pub fn from(key: &PrivateKey) -> Self {
        match key {
            PrivateKey::Ed25519(key) => KeyPair::Ed25519(ed25519::KeyPair::from(key)),
            PrivateKey::P256(key) => KeyPair::P256(p256::KeyPair::from(key)),
        }
    }

    /// deserializes from a byte array
    pub fn from_bytes(
        bytes: &[u8],
        algorithm: schema::public_key::Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            schema::public_key::Algorithm::Ed25519 => {
                Ok(KeyPair::Ed25519(ed25519::KeyPair::from_bytes(bytes)?))
            }
            schema::public_key::Algorithm::Secp256r1 => {
                Ok(KeyPair::P256(p256::KeyPair::from_bytes(bytes)?))
            }
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.sign(data),
            KeyPair::P256(key) => key.sign(data),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der_with_algorithm(
        bytes: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(KeyPair::Ed25519(ed25519::KeyPair::from_private_key_der(
                bytes,
            )?)),
            Algorithm::Secp256r1 => Ok(KeyPair::P256(p256::KeyPair::from_private_key_der(bytes)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        parse_any_algorithm(bytes, Self::from_private_key_der_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem_with_algorithm(
        str: &str,
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(KeyPair::Ed25519(ed25519::KeyPair::from_private_key_pem(
                str,
            )?)),
            Algorithm::Secp256r1 => Ok(KeyPair::P256(p256::KeyPair::from_private_key_pem(str)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        parse_any_algorithm(str, Self::from_private_key_pem_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.to_private_key_der(),
            KeyPair::P256(key) => key.to_private_key_der(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        match self {
            KeyPair::Ed25519(key) => key.to_private_key_pem(),
            KeyPair::P256(key) => key.to_private_key_pem(),
        }
    }

    pub fn private(&self) -> PrivateKey {
        match self {
            KeyPair::Ed25519(key) => PrivateKey::Ed25519(key.private()),
            KeyPair::P256(key) => PrivateKey::P256(key.private()),
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            KeyPair::Ed25519(key) => PublicKey::Ed25519(key.public()),
            KeyPair::P256(key) => PublicKey::P256(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            KeyPair::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            KeyPair::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

impl std::default::Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// the private part of a [KeyPair]
#[derive(Debug, Clone, PartialEq)]
pub enum PrivateKey {
    Ed25519(ed25519::PrivateKey),
    P256(p256::PrivateKey),
}

impl FromStr for PrivateKey {
    type Err = error::Format;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some(("ed25519-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Ed25519),
            Some(("secp256r1-private", bytes)) => Self::from_bytes_hex(bytes, Algorithm::Secp256r1),
            Some((alg, _)) => Err(error::Format::InvalidKey(format!(
                "Unsupported key algorithm {alg}"
            ))),
            None => Err(error::Format::InvalidKey(
                "Missing key algorithm".to_string(),
            )),
        }
    }
}

impl PrivateKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        match self {
            PrivateKey::Ed25519(key) => zeroize::Zeroizing::new(key.to_bytes()),
            PrivateKey::P256(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// serializes to an hex-encoded string, prefixed with the key algorithm
    pub fn to_prefixed_string(&self) -> String {
        let algorithm = match self.algorithm() {
            schema::public_key::Algorithm::Ed25519 => "ed25519-private",
            schema::public_key::Algorithm::Secp256r1 => "secp256r1-private",
        };
        format!("{algorithm}/{}", self.to_bytes_hex())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_bytes(bytes)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_bytes(bytes)?)),
        }
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes, algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_der_with_algorithm(
        bytes: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_der(bytes)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_der(bytes)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        parse_any_algorithm(bytes, Self::from_der_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem_with_algorithm(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PrivateKey::Ed25519(ed25519::PrivateKey::from_pem(str)?)),
            Algorithm::Secp256r1 => Ok(PrivateKey::P256(p256::PrivateKey::from_pem(str)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        parse_any_algorithm(str, Self::from_pem_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        match self {
            PrivateKey::Ed25519(key) => key.to_der(),
            PrivateKey::P256(key) => key.to_der(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        match self {
            PrivateKey::Ed25519(key) => key.to_pem(),
            PrivateKey::P256(key) => key.to_pem(),
        }
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(key.public()),
            PrivateKey::P256(key) => PublicKey::P256(key.public()),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PrivateKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            PrivateKey::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }
}

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
    P256(p256::PublicKey),
}

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(key) => key.to_bytes().into(),
            PublicKey::P256(key) => key.to_bytes(),
        }
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8], algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(bytes)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_bytes(bytes)?)),
        }
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes, algorithm)
    }

    pub fn from_proto(key: &schema::PublicKey) -> Result<Self, error::Format> {
        if key.algorithm == schema::public_key::Algorithm::Ed25519 as i32 {
            Ok(PublicKey::Ed25519(ed25519::PublicKey::from_bytes(
                &key.key,
            )?))
        } else if key.algorithm == schema::public_key::Algorithm::Secp256r1 as i32 {
            Ok(PublicKey::P256(p256::PublicKey::from_bytes(&key.key)?))
        } else {
            Err(error::Format::DeserializationError(format!(
                "deserialization error: unexpected key algorithm {}",
                key.algorithm
            )))
        }
    }

    pub fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: self.algorithm() as i32,
            key: self.to_bytes(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_der_with_algorithm(
        bytes: &[u8],
        algorithm: Algorithm,
    ) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_der(bytes)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_der(bytes)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        parse_any_algorithm(bytes, Self::from_der_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem_with_algorithm(str: &str, algorithm: Algorithm) -> Result<Self, error::Format> {
        match algorithm {
            Algorithm::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::from_pem(str)?)),
            Algorithm::Secp256r1 => Ok(PublicKey::P256(p256::PublicKey::from_pem(str)?)),
        }
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        parse_any_algorithm(str, Self::from_pem_with_algorithm)
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<Vec<u8>, error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.to_der(),
            PublicKey::P256(key) => key.to_der(),
        }
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String, error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.to_pem(),
            PublicKey::P256(key) => key.to_pem(),
        }
    }

    pub fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format> {
        match self {
            PublicKey::Ed25519(key) => key.verify_signature(data, signature),
            PublicKey::P256(key) => key.verify_signature(data, signature),
        }
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        match self {
            PublicKey::Ed25519(_) => crate::format::schema::public_key::Algorithm::Ed25519,
            PublicKey::P256(_) => crate::format::schema::public_key::Algorithm::Secp256r1,
        }
    }

    pub fn algorithm_string(&self) -> &str {
        match self {
            PublicKey::Ed25519(_) => "ed25519",
            PublicKey::P256(_) => "secp256r1",
        }
    }

    pub(crate) fn write(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicKey::Ed25519(key) => key.write(f),
            PublicKey::P256(key) => key.write(f),
        }
    }

    pub fn print(&self) -> String {
        match self {
            PublicKey::Ed25519(key) => key.print(),
            PublicKey::P256(key) => key.print(),
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f)
    }
}

#[derive(Clone, Debug)]
pub struct Signature(pub(crate) Vec<u8>);

impl Signature {
    pub fn from_bytes(data: &[u8]) -> Result<Self, error::Format> {
        Ok(Signature(data.to_owned()))
    }

    pub(crate) fn from_vec(data: Vec<u8>) -> Self {
        Signature(data)
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for PublicKey {
    type Err = error::Format;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, public_key) = biscuit_parser::parser::public_key(s)
            .finish()
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        PublicKey::from_bytes(
            &public_key.key,
            match public_key.algorithm {
                biscuit_parser::builder::Algorithm::Ed25519 => Algorithm::Ed25519,
                biscuit_parser::builder::Algorithm::Secp256r1 => Algorithm::Secp256r1,
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct Block {
    pub(crate) data: Vec<u8>,
    pub(crate) next_key: PublicKey,
    pub signature: Signature,
    pub external_signature: Option<ExternalSignature>,
    pub version: u32,
}

#[derive(Clone, Debug)]
pub struct ExternalSignature {
    pub(crate) public_key: PublicKey,
    pub(crate) signature: Signature,
}

#[derive(Clone, Debug)]
pub enum TokenNext {
    Secret(PrivateKey),
    Seal(Signature),
}

pub fn sign_authority_block(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    version: u32,
) -> Result<Signature, error::Token> {
    let to_sign = match version {
        0 => generate_authority_block_signature_payload_v0(&message, &next_key.public()),
        1 => generate_authority_block_signature_payload_v1(&message, &next_key.public(), version),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                version
            ))
            .into())
        }
    };

    let signature = keypair.sign(&to_sign)?;

    Ok(Signature(signature.to_bytes().to_vec()))
}

pub fn sign_block(
    keypair: &KeyPair,
    next_key: &KeyPair,
    message: &[u8],
    external_signature: Option<&ExternalSignature>,
    previous_signature: &Signature,
    version: u32,
) -> Result<Signature, error::Token> {
    let to_sign = match version {
        0 => generate_block_signature_payload_v0(&message, &next_key.public(), external_signature),
        1 => generate_block_signature_payload_v1(
            &message,
            &next_key.public(),
            external_signature,
            previous_signature,
            version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                version
            ))
            .into())
        }
    };

    Ok(keypair.sign(&to_sign)?)
}

pub fn verify_authority_block_signature(
    block: &Block,
    public_key: &PublicKey,
) -> Result<(), error::Format> {
    let to_verify = match block.version {
        0 => generate_block_signature_payload_v0(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
        ),
        1 => generate_authority_block_signature_payload_v1(
            &block.data,
            &block.next_key,
            block.version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                block.version
            )))
        }
    };

    public_key.verify_signature(&to_verify, &block.signature)
}

pub fn verify_block_signature(
    block: &Block,
    public_key: &PublicKey,
    previous_signature: &Signature,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match block.version {
        0 => generate_block_signature_payload_v0(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
        ),
        1 => generate_block_signature_payload_v1(
            &block.data,
            &block.next_key,
            block.external_signature.as_ref(),
            previous_signature,
            block.version,
        ),
        _ => {
            return Err(error::Format::DeserializationError(format!(
                "unsupported block version: {}",
                block.version
            )))
        }
    };

    public_key.verify_signature(&to_verify, &block.signature)?;

    if let Some(external_signature) = block.external_signature.as_ref() {
        verify_external_signature(
            &block.data,
            public_key,
            previous_signature,
            external_signature,
            block.version,
            verification_mode,
        )?;
    }

    Ok(())
}

pub fn verify_external_signature(
    payload: &[u8],
    public_key: &PublicKey,
    previous_signature: &Signature,
    external_signature: &ExternalSignature,
    version: u32,
    verification_mode: ThirdPartyVerificationMode,
) -> Result<(), error::Format> {
    let to_verify = match verification_mode {
        ThirdPartyVerificationMode::UnsafeLegacy => {
            generate_external_signature_payload_v0(payload, public_key)
        }
        ThirdPartyVerificationMode::PreviousSignatureHashing => {
            generate_external_signature_payload_v1(payload, previous_signature.to_bytes(), version)
        }
    };

    external_signature
        .public_key
        .verify_signature(&to_verify, &external_signature.signature)
}

pub(crate) fn generate_authority_block_signature_payload_v0(
    payload: &[u8],
    next_key: &PublicKey,
) -> Vec<u8> {
    let mut to_verify = payload.to_vec();

    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
}

pub(crate) fn generate_block_signature_payload_v0(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
) -> Vec<u8> {
    let mut to_verify = payload.to_vec();

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(next_key.to_bytes());
    to_verify
}

pub(crate) fn generate_authority_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    to_verify
}

pub(crate) fn generate_block_signature_payload_v1(
    payload: &[u8],
    next_key: &PublicKey,
    external_signature: Option<&ExternalSignature>,
    previous_signature: &Signature,
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0BLOCK\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0ALGORITHM\0".to_vec());
    to_verify.extend(&(next_key.algorithm() as i32).to_le_bytes());

    to_verify.extend(b"\0NEXTKEY\0".to_vec());
    to_verify.extend(&next_key.to_bytes());

    to_verify.extend(b"\0PREVSIG\0".to_vec());
    to_verify.extend(previous_signature.to_bytes());

    if let Some(signature) = external_signature.as_ref() {
        to_verify.extend(b"\0EXTERNALSIG\0".to_vec());
        to_verify.extend_from_slice(&signature.signature.to_bytes());
    }

    to_verify
}

fn generate_external_signature_payload_v0(payload: &[u8], previous_key: &PublicKey) -> Vec<u8> {
    let mut to_verify = payload.to_vec();
    to_verify.extend(&(previous_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(&previous_key.to_bytes());

    to_verify
}

pub(crate) fn generate_external_signature_payload_v1(
    payload: &[u8],
    previous_signature: &[u8],
    version: u32,
) -> Vec<u8> {
    let mut to_verify = b"\0EXTERNAL\0\0VERSION\0".to_vec();
    to_verify.extend(version.to_le_bytes());

    to_verify.extend(b"\0PAYLOAD\0".to_vec());
    to_verify.extend(payload.to_vec());

    to_verify.extend(b"\0PREVSIG\0".to_vec());
    to_verify.extend(previous_signature);
    to_verify
}

pub(crate) fn generate_seal_signature_payload_v0(block: &Block) -> Vec<u8> {
    let mut to_verify = block.data.to_vec();
    to_verify.extend(&(block.next_key.algorithm() as i32).to_le_bytes());
    to_verify.extend(&block.next_key.to_bytes());
    to_verify.extend(block.signature.to_bytes());
    to_verify
}

impl TokenNext {
    pub fn keypair(&self) -> Result<KeyPair, error::Token> {
        match &self {
            TokenNext::Seal(_) => Err(error::Token::AlreadySealed),
            TokenNext::Secret(private) => Ok(KeyPair::from(private)),
        }
    }

    pub fn is_sealed(&self) -> bool {
        match &self {
            TokenNext::Seal(_) => true,
            TokenNext::Secret(_) => false,
        }
    }
}

fn parse_any_algorithm<I: Copy, O>(
    i: I,
    parse: fn(i: I, alg: Algorithm) -> Result<O, error::Format>,
) -> Result<O, error::Format> {
    for algorithm in Algorithm::values() {
        let res = parse(i, *algorithm);
        if res.is_ok() {
            return res;
        }
    }

    Err(error::Format::InvalidKey(
        "The key could not be parsed with any algorithm".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_from_string() {
        let ed_root = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        assert_eq!(
            ed_root.public(),
            ed_root.public().to_string().parse().unwrap()
        );
        assert_eq!(
            ed_root.private().to_bytes(),
            ed_root
                .private()
                .to_prefixed_string()
                .parse::<PrivateKey>()
                .unwrap()
                .to_bytes()
        );
        let p256_root = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        assert_eq!(
            p256_root.public(),
            p256_root.public().to_string().parse().unwrap()
        );
        assert_eq!(
            p256_root.private().to_bytes(),
            p256_root
                .private()
                .to_prefixed_string()
                .parse::<PrivateKey>()
                .unwrap()
                .to_bytes()
        )
    }

    #[test]
    fn parsing_ed25519() {
        let private_ed = PrivateKey::from_bytes_hex(
            "bf6065d753c4a2c679dcd28828ac625c6c713efee2d4dd4b9c9ff3c9a2b2f966",
            Algorithm::Ed25519,
        )
        .unwrap();

        assert_eq!(
            private_ed.to_prefixed_string(),
            "ed25519-private/bf6065d753c4a2c679dcd28828ac625c6c713efee2d4dd4b9c9ff3c9a2b2f966"
                .to_string()
        );

        let public_ed = PublicKey::from_bytes_hex(
            "eb396fa7a681c614fefc5bd8d1fa0383f30a8c562a99d8e8a830286e844be074",
            Algorithm::Ed25519,
        )
        .unwrap();

        assert_eq!(
            public_ed.to_string(),
            "ed25519/eb396fa7a681c614fefc5bd8d1fa0383f30a8c562a99d8e8a830286e844be074".to_string()
        );
    }

    #[test]
    fn parsing_secp256r1() {
        let private_p256 = PrivateKey::from_bytes_hex(
            "4e85237ab258ca7d53051073dd6c1e501ea4699f2fed6b0f5d399dc2a5f7d38f",
            Algorithm::Secp256r1,
        )
        .unwrap();

        assert_eq!(
            private_p256.to_prefixed_string(),
            "secp256r1-private/4e85237ab258ca7d53051073dd6c1e501ea4699f2fed6b0f5d399dc2a5f7d38f"
                .to_string()
        );

        let public_p256 = PublicKey::from_bytes_hex(
            "03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29",
            Algorithm::Secp256r1,
        )
        .unwrap();

        assert_eq!(
            public_p256.to_string(),
            "secp256r1/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
                .to_string()
        );

        assert_eq!(
            public_p256,
            "secp256r1/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
                .parse()
                .unwrap()
        );
    }
    #[test]
    fn parsing_errors() {
        "xx/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PublicKey>()
            .unwrap_err();
        "03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PublicKey>()
            .unwrap_err();

        "xx/03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PrivateKey>()
            .unwrap_err();
        "03b6d94743381d3452f11a1aec8d73b0a899827d48be2e4387112e4d2faacfcc29"
            .parse::<PrivateKey>()
            .unwrap_err();
    }

    #[cfg(feature = "pem")]
    #[test]
    fn ed25519_der() {
        let ed25519_kp = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        let der_kp = ed25519_kp.to_private_key_der().unwrap();

        let deser =
            KeyPair::from_private_key_der_with_algorithm(&der_kp, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_kp, deser);
        let deser = KeyPair::from_private_key_der(&der_kp).unwrap();
        assert_eq!(ed25519_kp, deser);

        let ed25519_priv = ed25519_kp.private();
        let der_priv = ed25519_priv.to_der().unwrap();
        let deser_priv =
            PrivateKey::from_der_with_algorithm(&der_priv, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_priv, deser_priv);
        let deser_priv = PrivateKey::from_der(&der_priv).unwrap();
        assert_eq!(ed25519_priv, deser_priv);

        let ed25519_pub = ed25519_kp.public();
        let der_pub = ed25519_pub.to_der().unwrap();
        let deser_pub = PublicKey::from_der_with_algorithm(&der_pub, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
        let deser_pub = PublicKey::from_der(&der_pub).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn ed25519_pem() {
        let ed25519_kp = KeyPair::new_with_algorithm(Algorithm::Ed25519);
        let pem_kp = ed25519_kp.to_private_key_pem().unwrap();
        let deser =
            KeyPair::from_private_key_pem_with_algorithm(&pem_kp, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_kp, deser);
        let deser = KeyPair::from_private_key_pem(&pem_kp).unwrap();
        assert_eq!(ed25519_kp, deser);

        let ed25519_priv = ed25519_kp.private();
        let pem_priv = ed25519_priv.to_pem().unwrap();
        let deser_priv =
            PrivateKey::from_pem_with_algorithm(&pem_priv, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_priv, deser_priv);
        let deser_priv = PrivateKey::from_pem(&pem_priv).unwrap();
        assert_eq!(ed25519_priv, deser_priv);

        let ed25519_pub = ed25519_kp.public();
        let pem_pub = ed25519_pub.to_pem().unwrap();
        let deser_pub = PublicKey::from_pem_with_algorithm(&pem_pub, Algorithm::Ed25519).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
        let deser_pub = PublicKey::from_pem(&pem_pub).unwrap();
        assert_eq!(ed25519_pub, deser_pub);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn p256_der() {
        let p256_kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let der_kp = p256_kp.to_private_key_der().unwrap();
        let deser =
            KeyPair::from_private_key_der_with_algorithm(&der_kp, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_kp, deser);
        let deser = KeyPair::from_private_key_der(&der_kp).unwrap();
        assert_eq!(p256_kp, deser);

        let p256_priv = p256_kp.private();
        let der_priv = p256_priv.to_der().unwrap();
        let deser_priv =
            PrivateKey::from_der_with_algorithm(&der_priv, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_priv, deser_priv);
        let deser_priv = PrivateKey::from_der(&der_priv).unwrap();
        assert_eq!(p256_priv, deser_priv);

        let p256_pub = p256_kp.public();
        let der_pub = p256_pub.to_der().unwrap();
        let deser_pub = PublicKey::from_der_with_algorithm(&der_pub, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_pub, deser_pub);
        let deser_pub = PublicKey::from_der(&der_pub).unwrap();
        assert_eq!(p256_pub, deser_pub);
    }

    #[cfg(feature = "pem")]
    #[test]
    fn p256_pem() {
        let p256_kp = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
        let pem_kp = p256_kp.to_private_key_pem().unwrap();
        let deser =
            KeyPair::from_private_key_pem_with_algorithm(&pem_kp, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_kp, deser);
        let deser = KeyPair::from_private_key_pem(&pem_kp).unwrap();
        assert_eq!(p256_kp, deser);

        let p256_priv = p256_kp.private();
        let pem_priv = p256_priv.to_pem().unwrap();
        let deser_priv =
            PrivateKey::from_pem_with_algorithm(&pem_priv, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_priv, deser_priv);
        let deser_priv = PrivateKey::from_pem(&pem_priv).unwrap();
        assert_eq!(p256_priv, deser_priv);

        let p256_pub = p256_kp.public();
        let pem_pub = p256_pub.to_pem().unwrap();
        let deser_pub = PublicKey::from_pem_with_algorithm(&pem_pub, Algorithm::Secp256r1).unwrap();
        assert_eq!(p256_pub, deser_pub);
        let deser_pub = PublicKey::from_pem(&pem_pub).unwrap();
        assert_eq!(p256_pub, deser_pub);
    }

    #[test]
    fn prehashed_signature() {
        use ::p256::NistP256;
        use ecdsa::hazmat::DigestPrimitive;
        use ed25519_dalek::DigestSigner;

        fn generate_authority_block_signature_payload_v1_prehashed<
            H: ecdsa::signature::digest::Update,
        >(
            payload: &[u8],
            version: u32,
            hasher: &mut H,
        ) {
            hasher.update(b"\0BLOCK\0\0VERSION\0");
            hasher.update(&version.to_le_bytes());

            hasher.update(&b"\0PAYLOAD\0"[..]);
            hasher.update(payload);
        }

        let mut prehashed: ed25519_dalek::Sha512 = ed25519_dalek::Sha512::default();
        generate_authority_block_signature_payload_v1_prehashed(b"payload", 1, &mut prehashed);
        let kp = ed25519::KeyPair::new();
        //let hash = ed25519_dalek::Digest::finalize(prehashed);
        let sig = kp.kp.try_sign_digest(prehashed).unwrap();
        println!("{:?}", sig);

        let mut prehashed2 = <NistP256 as DigestPrimitive>::Digest::default();
        generate_authority_block_signature_payload_v1_prehashed(b"payload", 1, &mut prehashed2);
        let kp = p256::KeyPair::new();
        let sig: ecdsa::Signature<NistP256> = kp.kp.try_sign_digest(prehashed2).unwrap();
        println!("{:?}", sig);
    }
}
