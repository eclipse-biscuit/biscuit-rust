/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::cmp::max;

use prost::Message;

use crate::{
    builder::BlockBuilder,
    crypto::generate_external_signature_payload_v1,
    datalog::SymbolTable,
    error,
    format::{convert::token_block_to_proto_block, schema, SerializedBiscuit},
    KeyPair, PrivateKey,
};

use super::THIRD_PARTY_SIGNATURE_VERSION;

/// Third party block request
#[derive(PartialEq, Debug)]
pub struct ThirdPartyRequest {
    pub(crate) previous_signature: Vec<u8>,
}

impl ThirdPartyRequest {
    pub(crate) fn from_container(
        container: &SerializedBiscuit,
    ) -> Result<ThirdPartyRequest, error::Token> {
        if container.proof.is_sealed() {
            return Err(error::Token::AppendOnSealed);
        }

        let previous_signature = container
            .blocks
            .last()
            .unwrap_or(&container.authority)
            .signature
            .to_bytes()
            .to_vec();
        Ok(ThirdPartyRequest { previous_signature })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let previous_signature = self.previous_signature.clone();

        let request = schema::ThirdPartyBlockRequest {
            legacy_previous_key: None,
            legacy_public_keys: Vec::new(),
            previous_signature,
        };
        let mut v = Vec::new();

        request.encode(&mut v).map(|_| v).map_err(|e| {
            error::Token::Format(error::Format::SerializationError(format!(
                "serialization error: {e:?}"
            )))
        })
    }

    pub fn serialize_base64(&self) -> Result<String, error::Token> {
        Ok(base64::encode_config(self.serialize()?, base64::URL_SAFE))
    }

    pub fn deserialize(slice: &[u8]) -> Result<Self, error::Token> {
        let data = schema::ThirdPartyBlockRequest::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {e:?}"))
        })?;

        if !data.legacy_public_keys.is_empty() {
            return Err(error::Token::Format(error::Format::DeserializationError(
                "public keys were provided in third-party block request".to_owned(),
            )));
        }

        if data.legacy_previous_key.is_some() {
            return Err(error::Token::Format(error::Format::DeserializationError(
                "previous public key was provided in third-party block request".to_owned(),
            )));
        }

        let previous_signature = data.previous_signature.to_vec();

        Ok(ThirdPartyRequest { previous_signature })
    }

    pub fn deserialize_base64<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Self::deserialize(&decoded)
    }

    /// Creates a [`ThirdPartyBlock`] signed with the third party service's [`PrivateKey`]
    pub fn create_block(
        self,
        private_key: &PrivateKey,
        block_builder: BlockBuilder,
    ) -> Result<ThirdPartyBlock, error::Token> {
        let unsigned = self.prepare_block(block_builder)?;

        let keypair = KeyPair::from(private_key);
        let signature = keypair.sign(unsigned.bytes_to_sign())?;
        let public_key = keypair.public();

        unsigned.with_external_signature(public_key, signature.to_bytes())
    }

    /// Prepares a third-party block for an external signer.
    ///
    /// Some keys can never be handed over as a [`PrivateKey`]: HSMs, TPMs and
    /// secure enclaves will sign bytes for you, but won't give up the key.
    /// This splits [`ThirdPartyRequest::create_block`] in two so those signers
    /// work: take [`ThirdPartyUnsignedBlock::bytes_to_sign`], sign it wherever
    /// the key lives, then assemble the block with
    /// [`ThirdPartyUnsignedBlock::with_external_signature`].
    ///
    /// If the key is available in memory, `create_block` still does both steps
    /// in one call (it is built on top of this).
    pub fn prepare_block(
        self,
        block_builder: BlockBuilder,
    ) -> Result<ThirdPartyUnsignedBlock, error::Token> {
        let symbols = SymbolTable::new();
        let mut block = block_builder.build(symbols);
        block.version = max(super::DATALOG_3_2, block.version);

        let mut payload = Vec::new();
        token_block_to_proto_block(&block)
            .encode(&mut payload)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {e:?}"))
            })?;

        let bytes_to_sign = generate_external_signature_payload_v1(
            &payload,
            &self.previous_signature,
            THIRD_PARTY_SIGNATURE_VERSION,
        );

        Ok(ThirdPartyUnsignedBlock {
            payload,
            bytes_to_sign,
        })
    }
}

/// A third-party block waiting for its external signature.
///
/// Sign exactly [`ThirdPartyUnsignedBlock::bytes_to_sign`] (Ed25519 signs the
/// bytes directly; ECDSA P-256 signs their SHA-256, which is what hardware
/// modules do natively), then call
/// [`ThirdPartyUnsignedBlock::with_external_signature`].
#[derive(Clone, Debug)]
pub struct ThirdPartyUnsignedBlock {
    payload: Vec<u8>,
    bytes_to_sign: Vec<u8>,
}

impl ThirdPartyUnsignedBlock {
    /// The exact bytes the external signer must sign.
    pub fn bytes_to_sign(&self) -> &[u8] {
        &self.bytes_to_sign
    }

    /// Assembles the block from an externally produced signature.
    ///
    /// The signature is checked against `public_key` right here, so a wrong
    /// key or a corrupted signature fails immediately instead of later, when
    /// the token is deserialized.
    pub fn with_external_signature(
        self,
        public_key: crate::PublicKey,
        signature_bytes: &[u8],
    ) -> Result<ThirdPartyBlock, error::Token> {
        let signature =
            crate::crypto::Signature::from_bytes(signature_bytes).map_err(error::Token::Format)?;
        public_key
            .verify_signature(&self.bytes_to_sign, &signature)
            .map_err(error::Token::Format)?;

        Ok(ThirdPartyBlock(schema::ThirdPartyBlockContents {
            payload: self.payload,
            external_signature: schema::ExternalSignature {
                signature: signature.to_bytes().to_vec(),
                public_key: public_key.to_proto(),
            },
        }))
    }
}

/// Signed third party block content
///
/// this must be integrated with the token that created the [`ThirdPartyRequest`]
/// using [`Biscuit::append_third_party`](crate::Biscuit::append_third_party)
#[derive(Clone, Debug)]
pub struct ThirdPartyBlock(pub(crate) schema::ThirdPartyBlockContents);

impl ThirdPartyBlock {
    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let mut buffer = vec![];
        self.0.encode(&mut buffer).map(|_| buffer).map_err(|e| {
            error::Token::Format(error::Format::SerializationError(format!(
                "serialization error: {e:?}"
            )))
        })
    }

    pub fn serialize_base64(&self) -> Result<String, error::Token> {
        Ok(base64::encode_config(self.serialize()?, base64::URL_SAFE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A token and an external keypair for the external-signing tests.
    fn setup(
        external_alg: crate::builder::Algorithm,
    ) -> (KeyPair, crate::Biscuit, KeyPair, BlockBuilder) {
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(42);
        let root = KeyPair::new_with_rng(crate::builder::Algorithm::Ed25519, &mut rng);
        let biscuit = crate::Biscuit::builder()
            .fact("right(\"file1\", \"read\")")
            .unwrap()
            .build_with_rng(&root, crate::token::default_symbol_table(), &mut rng)
            .unwrap();
        let external = KeyPair::new_with_rng(external_alg, &mut rng);
        let block = BlockBuilder::new()
            .fact("external_fact(\"hello\")")
            .unwrap();
        (root, biscuit, external, block)
    }

    /// The prepare/sign/assemble path must produce a block a standard
    /// verifier accepts, without the private key ever entering the library.
    /// The "external signer" here only ever sees the bytes to sign -- exactly
    /// what an HSM would.
    #[test]
    fn external_signature_round_trip_ed25519() {
        let (root, biscuit, external, block) = setup(crate::builder::Algorithm::Ed25519);

        let unsigned = biscuit
            .third_party_request()
            .unwrap()
            .prepare_block(block)
            .unwrap();
        let signature = external.sign(unsigned.bytes_to_sign()).unwrap();
        let third_party_block = unsigned
            .with_external_signature(external.public(), signature.to_bytes())
            .unwrap();

        let biscuit2 = biscuit
            .append_third_party(external.public(), third_party_block)
            .unwrap();
        // Re-parsing verifies every signature in the chain, external included.
        crate::Biscuit::from(biscuit2.to_vec().unwrap(), root.public()).unwrap();
    }

    #[test]
    fn external_signature_round_trip_p256() {
        let (root, biscuit, external, block) = setup(crate::builder::Algorithm::Secp256r1);

        let unsigned = biscuit
            .third_party_request()
            .unwrap()
            .prepare_block(block)
            .unwrap();
        let signature = external.sign(unsigned.bytes_to_sign()).unwrap();
        let third_party_block = unsigned
            .with_external_signature(external.public(), signature.to_bytes())
            .unwrap();

        let biscuit2 = biscuit
            .append_third_party(external.public(), third_party_block)
            .unwrap();
        crate::Biscuit::from(biscuit2.to_vec().unwrap(), root.public()).unwrap();
    }

    /// Deterministic Ed25519: the split path and create_block must produce
    /// byte-identical blocks for the same key and content.
    #[test]
    fn external_signature_matches_create_block_ed25519() {
        let (_root, biscuit, external, block) = setup(crate::builder::Algorithm::Ed25519);

        let via_create = biscuit
            .third_party_request()
            .unwrap()
            .create_block(&external.private(), block.clone())
            .unwrap();

        let unsigned = biscuit
            .third_party_request()
            .unwrap()
            .prepare_block(block)
            .unwrap();
        let signature = external.sign(unsigned.bytes_to_sign()).unwrap();
        let via_external = unsigned
            .with_external_signature(external.public(), signature.to_bytes())
            .unwrap();

        assert_eq!(
            via_create.serialize_base64().unwrap(),
            via_external.serialize_base64().unwrap()
        );
    }

    /// A corrupted signature or a mismatched key fails at assembly, not
    /// later at token deserialization.
    #[test]
    fn external_signature_rejects_tampering_and_wrong_key() {
        let (_root, biscuit, external, block) = setup(crate::builder::Algorithm::Ed25519);

        let unsigned = biscuit
            .third_party_request()
            .unwrap()
            .prepare_block(block)
            .unwrap();
        let signature = external.sign(unsigned.bytes_to_sign()).unwrap();

        let mut tampered = signature.to_bytes().to_vec();
        tampered[0] ^= 0x01;
        assert!(unsigned
            .clone()
            .with_external_signature(external.public(), &tampered)
            .is_err());

        let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(7);
        let other = KeyPair::new_with_rng(crate::builder::Algorithm::Ed25519, &mut rng);
        assert!(unsigned
            .with_external_signature(other.public(), signature.to_bytes())
            .is_err());
    }

    #[test]
    fn third_party_request_roundtrip() {
        let mut rng: rand::rngs::StdRng = rand::SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(crate::builder::Algorithm::Ed25519, &mut rng);
        let biscuit1 = crate::Biscuit::builder()
            .fact("right(\"file1\", \"read\")")
            .unwrap()
            .fact("right(\"file2\", \"read\")")
            .unwrap()
            .fact("right(\"file1\", \"write\")")
            .unwrap()
            .build_with_rng(&root, crate::token::default_symbol_table(), &mut rng)
            .unwrap();
        let req = biscuit1.third_party_request().unwrap();
        let serialized_req = req.serialize().unwrap();
        let parsed_req = ThirdPartyRequest::deserialize(&serialized_req).unwrap();

        assert_eq!(req, parsed_req);
    }
}
