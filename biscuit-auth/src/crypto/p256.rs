/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#![allow(non_snake_case)]
use crate::{error::Format, format::schema};

use super::error;
use super::Signature;

use p256::ecdsa::{signature::Signer, signature::Verifier, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{CryptoRng, OsRng, RngCore};
use p256::NistP256;
use std::hash::Hash;

/// pair of cryptographic keys used to sign a token's block
#[derive(Debug, PartialEq)]
pub struct KeyPair {
    pub(super) kp: SigningKey,
}

impl KeyPair {
    pub fn new() -> Self {
        Self::new_with_rng(&mut OsRng)
    }

    pub fn new_with_rng<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        let kp = SigningKey::random(rng);

        KeyPair { kp }
    }

    pub fn from(key: &PrivateKey) -> Self {
        KeyPair { kp: key.0.clone() }
    }

    /// deserializes from a big endian byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        // the version of generic-array used by p256 panics if the input length
        // is incorrect (including when using `.try_into()`)
        if bytes.len() != 32 {
            return Err(Format::InvalidKeySize(bytes.len()));
        }
        let kp = SigningKey::from_bytes(bytes.into())
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)?;

        Ok(KeyPair { kp })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        let signature: ecdsa::Signature<NistP256> = self
            .kp
            .try_sign(&data)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignatureGeneration)
            .map_err(error::Format::Signature)?;
        Ok(Signature(signature.to_der().as_bytes().to_owned()))
    }

    pub fn private(&self) -> PrivateKey {
        PrivateKey(self.kp.clone())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(*self.kp.verifying_key())
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        crate::format::schema::public_key::Algorithm::Secp256r1
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_der(bytes: &[u8]) -> Result<Self, error::Format> {
        use p256::pkcs8::DecodePrivateKey;

        let kp = SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    #[cfg(feature = "pem")]
    pub fn from_private_key_pem(str: &str) -> Result<Self, error::Format> {
        use p256::pkcs8::DecodePrivateKey;

        let kp = SigningKey::from_pkcs8_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(KeyPair { kp })
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        use p256::pkcs8::EncodePrivateKey;
        let kp = self
            .kp
            .to_pkcs8_der()
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp.to_bytes())
    }

    #[cfg(feature = "pem")]
    pub fn to_private_key_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        use p256::pkcs8::EncodePrivateKey;
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
pub struct PrivateKey(SigningKey);

impl PrivateKey {
    /// serializes to a big endian byte array
    pub fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let field_bytes = self.0.to_bytes();
        zeroize::Zeroizing::new(field_bytes.to_vec())
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a big endian byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        // the version of generic-array used by p256 panics if the input length
        // is incorrect (including when using `.try_into()`)
        if bytes.len() != 32 {
            return Err(Format::InvalidKeySize(bytes.len()));
        }
        SigningKey::from_bytes(bytes.into())
            .map(PrivateKey)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        use p256::pkcs8::DecodePrivateKey;

        let kp = SigningKey::from_pkcs8_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PrivateKey(kp))
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        use p256::pkcs8::DecodePrivateKey;

        let kp = SigningKey::from_pkcs8_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PrivateKey(kp))
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, error::Format> {
        use p256::pkcs8::EncodePrivateKey;
        let kp = self
            .0
            .to_pkcs8_der()
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp.to_bytes())
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<zeroize::Zeroizing<String>, error::Format> {
        use p256::pkcs8::EncodePrivateKey;
        use p256::pkcs8::LineEnding;
        let kp = self
            .0
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp)
    }

    /// returns the matching public key
    pub fn public(&self) -> PublicKey {
        PublicKey(*(&self.0).verifying_key())
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

/// the public part of a [KeyPair]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// serializes to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).to_bytes().into()
    }

    /// serializes to an hex-encoded string
    pub fn to_bytes_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// deserializes from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format> {
        let k = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)?;

        Ok(Self(k.into()))
    }

    /// deserializes from an hex-encoded string
    pub fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    #[cfg(feature = "pem")]
    pub fn from_der(bytes: &[u8]) -> Result<Self, error::Format> {
        use p256::pkcs8::DecodePublicKey;

        let pubkey = VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PublicKey(pubkey))
    }

    #[cfg(feature = "pem")]
    pub fn from_pem(str: &str) -> Result<Self, error::Format> {
        use p256::pkcs8::DecodePublicKey;

        let pubkey = VerifyingKey::from_public_key_pem(str)
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Ok(PublicKey(pubkey))
    }

    #[cfg(feature = "pem")]
    pub fn to_der(&self) -> Result<Vec<u8>, error::Format> {
        use p256::pkcs8::EncodePublicKey;
        let kp = self
            .0
            .to_public_key_der()
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp.to_vec())
    }

    #[cfg(feature = "pem")]
    pub fn to_pem(&self) -> Result<String, error::Format> {
        use p256::pkcs8::EncodePublicKey;
        use p256::pkcs8::LineEnding;
        let kp = self
            .0
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| error::Format::PKCS8(e.to_string()))?;
        Ok(kp)
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
        let sig = p256::ecdsa::Signature::from_der(&signature.0).map_err(|e| {
            error::Format::BlockSignatureDeserializationError(format!(
                "block signature deserialization error: {:?}",
                e
            ))
        })?;

        self.0
            .verify(&data, &sig)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignature)
            .map_err(error::Format::Signature)
    }

    pub fn algorithm(&self) -> crate::format::schema::public_key::Algorithm {
        crate::format::schema::public_key::Algorithm::Ed25519
    }

    pub(crate) fn write(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secp256r1/{}", hex::encode(&self.to_bytes()))
    }
    pub fn print(&self) -> String {
        format!("secp256r1/{}", hex::encode(&self.to_bytes()))
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (crate::format::schema::public_key::Algorithm::Ed25519 as i32).hash(state);
        self.to_bytes().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization() {
        let kp = KeyPair::new();
        let private = kp.private();
        let public = kp.public();
        let private_hex = private.to_bytes_hex();
        let public_hex = public.to_bytes_hex();

        println!("private: {private_hex}");
        println!("public: {public_hex}");

        let message = "hello world";
        let signature = kp.sign(message.as_bytes()).unwrap();
        println!("signature: {}", hex::encode(&signature.0));

        let deserialized_priv = PrivateKey::from_bytes_hex(&private_hex).unwrap();
        let deserialized_pub = PublicKey::from_bytes_hex(&public_hex).unwrap();

        assert_eq!(private.0.to_bytes(), deserialized_priv.0.to_bytes());
        assert_eq!(public, deserialized_pub);

        deserialized_pub
            .verify_signature(message.as_bytes(), &signature)
            .unwrap();
        //panic!();
    }

    #[test]
    fn invalid_sizes() {
        assert_eq!(
            PrivateKey::from_bytes(&[0xaa]).unwrap_err(),
            error::Format::InvalidKeySize(1)
        );
        assert_eq!(
            KeyPair::from_bytes(&[0xaa]).unwrap_err(),
            error::Format::InvalidKeySize(1)
        );
        PublicKey::from_bytes(&[0xaa]).unwrap_err();
    }
}
