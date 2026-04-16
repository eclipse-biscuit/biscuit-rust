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
        let symbols = SymbolTable::new();
        let mut block = block_builder.build(symbols);
        block.version = max(super::DATALOG_3_2, block.version);

        let mut payload = Vec::new();
        token_block_to_proto_block(&block)
            .encode(&mut payload)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {e:?}"))
            })?;

        let signed_payload = generate_external_signature_payload_v1(
            &payload,
            &self.previous_signature,
            THIRD_PARTY_SIGNATURE_VERSION,
        );

        let keypair = KeyPair::from(private_key);
        let signature = keypair.sign(&signed_payload)?;

        let public_key = keypair.public();
        let content = schema::ThirdPartyBlockContents {
            payload,
            external_signature: schema::ExternalSignature {
                signature: signature.to_bytes().to_vec(),
                public_key: public_key.to_proto(),
            },
        };

        Ok(ThirdPartyBlock(content))
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
