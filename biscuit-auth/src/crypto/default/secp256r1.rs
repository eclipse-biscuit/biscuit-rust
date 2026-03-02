/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#![allow(non_snake_case)]

use crate::error::Format;
use std::fmt::{Display, Formatter};

use crate::crypto::{
    error, KeyPairImpl, KeySerialization, PrivateKeyImpl, PublicKeyImpl, Signature,
};

use crate::format::schema::public_key::Algorithm;
use p256::ecdsa::{signature::Signer, signature::Verifier, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{CryptoRng, OsRng, RngCore};
use p256::SecretKey;
use std::hash::{Hash, Hasher};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

#[cfg(feature = "pem")]
impl crate::crypto::KeyPemSerialization for PublicKey {
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        use p256::pkcs8::DecodePublicKey;
        let pubkey = VerifyingKey::from_public_key_der(bytes)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        Ok(Self(pubkey))
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use p256::pkcs8::DecodePublicKey;

        let pubkey = VerifyingKey::from_public_key_pem(str)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        Ok(Self(pubkey))
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        use p256::pkcs8::EncodePublicKey;
        self.0
            .to_public_key_der()
            .map(|b| b.to_vec())
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use p256::pkcs8::EncodePublicKey;
        use p256::pkcs8::LineEnding;
        self.0
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)
    }
}

impl KeySerialization for PublicKey {
    type Bytes = Vec<u8>;
    type String = String;

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        let key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)?;
        Ok(Self(key))
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "secp256r1/{}", self.to_bytes_hex())
    }
}

impl PublicKeyImpl for PublicKey {
    fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<(), Format> {
        let sig = p256::ecdsa::Signature::from_der(&signature.0).map_err(|e| {
            Format::BlockSignatureDeserializationError(format!(
                "block signature deserialization error: {:?}",
                e
            ))
        })?;

        self.0
            .verify(data, &sig)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignature)
            .map_err(Format::Signature)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256r1
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.algorithm() as i32).hash(state);
        self.0.to_encoded_point(true).as_bytes().hash(state);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(SecretKey);

impl KeySerialization for PrivateKey {
    type Bytes = Zeroizing<Vec<u8>>;
    type String = Zeroizing<String>;

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_bytes().to_vec().into()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        if bytes.len() != 32 {
            return Err(Format::InvalidKeySize(bytes.len()));
        }
        SecretKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|s| s.to_string())
            .map_err(Format::InvalidKey)
    }
}

#[cfg(feature = "pem")]
impl crate::crypto::KeyPemSerialization for PrivateKey {
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        use p256::pkcs8::DecodePrivateKey;
        SecretKey::from_pkcs8_der(bytes)
            .map(Self)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use p256::pkcs8::DecodePrivateKey;
        SecretKey::from_pkcs8_pem(str)
            .map(Self)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        use p256::pkcs8::EncodePrivateKey;
        self.0
            .to_pkcs8_der()
            .map(|d| d.to_bytes())
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use p256::pkcs8::EncodePrivateKey;
        use p256::pkcs8::LineEnding;
        self.0
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)
    }
}

impl PrivateKeyImpl for PrivateKey {
    type PublicKey = PublicKey;

    fn public(&self) -> Self::PublicKey {
        let kp: SigningKey = self.0.clone().into();
        PublicKey(*kp.verifying_key())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256r1
    }
}

#[derive(Debug, PartialEq)]
pub struct KeyPair(SigningKey);

impl KeyPairImpl for KeyPair {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    fn sign(&self, data: &[u8]) -> Result<Signature, Format> {
        let signature: p256::ecdsa::Signature = self
            .0
            .try_sign(data)
            .map_err(|s| s.to_string())
            .map_err(error::Signature::InvalidSignatureGeneration)
            .map_err(Format::Signature)?;
        Ok(Signature(signature.to_der().as_bytes().to_vec()))
    }

    fn from_private(key: &Self::PrivateKey) -> Self {
        let kp: SigningKey = key.0.clone().into();
        Self(kp)
    }

    fn public(&self) -> Self::PublicKey {
        PublicKey(*self.0.verifying_key())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256r1
    }

    fn private(&self) -> Self::PrivateKey {
        PrivateKey(SecretKey::new(self.0.as_nonzero_scalar().into()))
    }

    fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(SigningKey::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization() {
        let keypair = KeyPair::generate();
        let public = keypair.public();
        let private = keypair.private();
        let private_hex = private.to_bytes_hex();
        let public_hex = public.to_bytes_hex();

        println!("private: {}", private_hex.as_str());
        println!("public: {public_hex}");

        let message = "hello world";
        let signature = keypair.sign(message.as_bytes()).unwrap();
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
            Format::InvalidKeySize(1)
        );
        assert_eq!(
            PrivateKey::from_bytes(&[0xaa]).unwrap_err(),
            Format::InvalidKeySize(1)
        );
        PublicKey::from_bytes(&[0xaa]).unwrap_err();
    }
}
