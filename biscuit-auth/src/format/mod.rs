/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! token serialization/deserialization
//!
//! Biscuit tokens are serialized to Protobuf. There are two levels of serialization:
//!
//! - serialization of Biscuit blocks to Protobuf then `Vec<u8>`
//! - serialization of a wrapper structure containing serialized blocks and the signature
use super::crypto::{self, KeyPair, PrivateKey, PublicKey, TokenNext};

use prost::Message;

use super::error;
use super::token::Block;
use crate::crypto::ExternalSignature;
use crate::crypto::Signature;
use crate::datalog::SymbolTable;
use crate::token::RootKeyProvider;
use crate::token::DATALOG_3_3;

/// Structures generated from the Protobuf schema
pub mod schema; /*{
                    include!(concat!(env!("OUT_DIR"), "/biscuit.format.schema.rs"));
                }*/

pub mod convert;

use self::convert::*;

pub(crate) const THIRD_PARTY_SIGNATURE_VERSION: u32 = 1;
pub(crate) const DATALOG_3_3_SIGNATURE_VERSION: u32 = 1;
pub(crate) const NON_ED25519_SIGNATURE_VERSION: u32 = 1;
/// Intermediate structure for token serialization
///
/// This structure contains the blocks serialized to byte arrays. Those arrays
/// will be used for the signature
#[derive(Clone, Debug)]
pub struct SerializedBiscuit {
    pub root_key_id: Option<u32>,
    pub authority: crypto::Block,
    pub blocks: Vec<crypto::Block>,
    pub proof: crypto::TokenNext,
}

impl SerializedBiscuit {
    pub fn from_slice<KP>(slice: &[u8], key_provider: KP) -> Result<Self, error::Format>
    where
        KP: RootKeyProvider,
    {
        let deser = SerializedBiscuit::deserialize(
            slice,
            ThirdPartyVerificationMode::PreviousSignatureHashing,
        )?;

        let root = key_provider.choose(deser.root_key_id)?;
        deser.verify(&root)?;

        Ok(deser)
    }

    pub(crate) fn unsafe_from_slice<KP>(
        slice: &[u8],
        key_provider: KP,
    ) -> Result<Self, error::Format>
    where
        KP: RootKeyProvider,
    {
        let deser =
            SerializedBiscuit::deserialize(slice, ThirdPartyVerificationMode::UnsafeLegacy)?;

        let root = key_provider.choose(deser.root_key_id)?;
        deser.verify_inner(&root, ThirdPartyVerificationMode::UnsafeLegacy)?;

        Ok(deser)
    }

    pub(crate) fn deserialize(
        slice: &[u8],
        verification_mode: ThirdPartyVerificationMode,
    ) -> Result<Self, error::Format> {
        let data = schema::Biscuit::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {e:?}"))
        })?;

        let next_key = PublicKey::from_proto(&data.authority.next_key)?;
        let mut next_key_algorithm = next_key.algorithm();

        let signature = Signature::from_vec(data.authority.signature);

        if data.authority.external_signature.is_some() {
            return Err(error::Format::DeserializationError(
                "the authority block must not contain an external signature".to_string(),
            ));
        }

        let authority = crypto::Block {
            data: data.authority.block,
            next_key,
            signature,
            external_signature: None,
            version: data.authority.version.unwrap_or_default(),
        };

        let mut blocks = Vec::new();
        for block in data.blocks {
            let next_key = PublicKey::from_proto(&block.next_key)?;
            next_key_algorithm = next_key.algorithm();

            let signature = Signature::from_vec(block.signature);

            let external_signature = if let Some(ex) = block.external_signature {
                if verification_mode == ThirdPartyVerificationMode::PreviousSignatureHashing
                    && block.version != Some(THIRD_PARTY_SIGNATURE_VERSION)
                {
                    return Err(error::Format::DeserializationError(
                        "Unsupported third party block version".to_string(),
                    ));
                }

                let public_key = PublicKey::from_proto(&ex.public_key)?;
                let signature = Signature::from_vec(ex.signature);

                Some(ExternalSignature {
                    public_key,
                    signature,
                })
            } else {
                None
            };

            blocks.push(crypto::Block {
                data: block.block.clone(),
                next_key,
                signature,
                external_signature,
                version: block.version.unwrap_or_default(),
            });
        }

        let proof = match data.proof.content {
            None => {
                return Err(error::Format::DeserializationError(
                    "could not find proof".to_string(),
                ))
            }
            Some(schema::proof::Content::NextSecret(v)) => {
                let next_key_algorithm = match next_key_algorithm {
                    schema::public_key::Algorithm::Ed25519 => crate::builder::Algorithm::Ed25519,
                    schema::public_key::Algorithm::Secp256r1 => {
                        crate::builder::Algorithm::Secp256r1
                    }
                };
                TokenNext::Secret(PrivateKey::from_bytes(&v, next_key_algorithm)?)
            }
            Some(schema::proof::Content::FinalSignature(v)) => {
                let signature = Signature::from_vec(v);

                TokenNext::Seal(signature)
            }
        };

        let deser = SerializedBiscuit {
            root_key_id: data.root_key_id,
            authority,
            blocks,
            proof,
        };

        Ok(deser)
    }

    pub(crate) fn extract_blocks(
        &self,
        symbols: &mut SymbolTable,
    ) -> Result<(schema::Block, Vec<schema::Block>), error::Token> {
        let mut block_external_keys = Vec::new();

        let authority = schema::Block::decode(&self.authority.data[..]).map_err(|e| {
            error::Token::Format(error::Format::BlockDeserializationError(format!(
                "error deserializing authority block: {e:?}"
            )))
        })?;

        symbols.extend(&SymbolTable::from(authority.symbols.clone())?)?;

        for pk in &authority.public_keys {
            symbols
                .public_keys
                .insert_fallible(&PublicKey::from_proto(pk)?)?;
        }
        // the authority block should not have an external key
        block_external_keys.push(None);
        //FIXME: return an error if the authority block has an external key

        let mut blocks = vec![];

        for block in self.blocks.iter() {
            let deser = schema::Block::decode(&block.data[..]).map_err(|e| {
                error::Token::Format(error::Format::BlockDeserializationError(format!(
                    "error deserializing block: {e:?}"
                )))
            })?;

            if let Some(external_signature) = &block.external_signature {
                block_external_keys.push(Some(external_signature.public_key));
            } else {
                block_external_keys.push(None);
                symbols.extend(&SymbolTable::from(deser.symbols.clone())?)?;
                for pk in &deser.public_keys {
                    symbols
                        .public_keys
                        .insert_fallible(&PublicKey::from_proto(pk)?)?;
                }
            }

            blocks.push(deser);
        }

        Ok((authority, blocks))
    }

    /// serializes the token
    pub fn to_proto(&self) -> schema::Biscuit {
        let authority = schema::SignedBlock {
            block: self.authority.data.clone(),
            next_key: self.authority.next_key.to_proto(),
            signature: self.authority.signature.to_bytes().to_vec(),
            external_signature: None,
            version: if self.authority.version > 0 {
                Some(self.authority.version)
            } else {
                None
            },
        };

        let mut blocks = Vec::new();
        for block in &self.blocks {
            let b = schema::SignedBlock {
                block: block.data.clone(),
                next_key: block.next_key.to_proto(),
                signature: block.signature.to_bytes().to_vec(),
                external_signature: block.external_signature.as_ref().map(|external_signature| {
                    schema::ExternalSignature {
                        signature: external_signature.signature.to_bytes().to_vec(),
                        public_key: external_signature.public_key.to_proto(),
                    }
                }),
                version: if block.version > 0 {
                    Some(block.version)
                } else {
                    None
                },
            };

            blocks.push(b);
        }

        schema::Biscuit {
            root_key_id: self.root_key_id,
            authority,
            blocks,
            proof: schema::Proof {
                content: match &self.proof {
                    TokenNext::Seal(signature) => Some(schema::proof::Content::FinalSignature(
                        signature.to_bytes().to_vec(),
                    )),
                    TokenNext::Secret(private) => Some(schema::proof::Content::NextSecret(
                        private.to_bytes().to_vec(),
                    )),
                },
            },
        }
    }

    pub fn serialized_size(&self) -> usize {
        self.to_proto().encoded_len()
    }

    /// serializes the token
    pub fn to_vec(&self) -> Result<Vec<u8>, error::Format> {
        let b = self.to_proto();

        let mut v = Vec::new();

        b.encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {e:?}")))
    }

    /// creates a new token
    pub fn new(
        root_key_id: Option<u32>,
        root_keypair: &KeyPair,
        next_keypair: &KeyPair,
        authority: &Block,
    ) -> Result<Self, error::Token> {
        let authority_signature_version = block_signature_version(
            root_keypair,
            next_keypair,
            &None,
            &Some(authority.version),
            std::iter::empty(),
        );
        Self::new_inner(
            root_key_id,
            root_keypair,
            next_keypair,
            authority,
            authority_signature_version,
        )
    }

    /// creates a new token
    pub(crate) fn new_inner(
        root_key_id: Option<u32>,
        root_keypair: &KeyPair,
        next_keypair: &KeyPair,
        authority: &Block,
        authority_signature_version: u32,
    ) -> Result<Self, error::Token> {
        let mut v = Vec::new();
        token_block_to_proto_block(authority)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {e:?}"))
            })?;

        let signature = crypto::sign_authority_block(
            root_keypair,
            next_keypair,
            &v,
            authority_signature_version,
        )?;

        Ok(SerializedBiscuit {
            root_key_id,
            authority: crypto::Block {
                data: v,
                next_key: next_keypair.public(),
                signature,
                external_signature: None,
                version: authority_signature_version,
            },
            blocks: vec![],
            proof: TokenNext::Secret(next_keypair.private()),
        })
    }

    /// adds a new block, serializes it and sign a new token
    pub fn append(
        &self,
        next_keypair: &KeyPair,
        block: &Block,
        external_signature: Option<ExternalSignature>,
    ) -> Result<Self, error::Token> {
        let keypair = self.proof.keypair()?;

        let mut v = Vec::new();
        token_block_to_proto_block(block)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {e:?}"))
            })?;

        let signature_version = block_signature_version(
            &keypair,
            next_keypair,
            &external_signature,
            &Some(block.version),
            // std::iter::once(self.authority.version)
            //     .chain(self.blocks.iter().map(|block| block.version)),
            self.blocks
                .iter()
                .chain([&self.authority])
                .map(|block| block.version),
        );

        let signature = crypto::sign_block(
            &keypair,
            next_keypair,
            &v,
            external_signature.as_ref(),
            &self.last_block().signature,
            signature_version,
        )?;

        // Add new block
        let mut blocks = self.blocks.clone();
        blocks.push(crypto::Block {
            data: v,
            next_key: next_keypair.public(),
            signature,
            external_signature,
            version: signature_version,
        });

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks,
            proof: TokenNext::Secret(next_keypair.private()),
        })
    }

    /// adds a new block, serializes it and sign a new token
    pub fn append_serialized(
        &self,
        next_keypair: &KeyPair,
        block: Vec<u8>,
        external_signature: Option<ExternalSignature>,
    ) -> Result<Self, error::Token> {
        let keypair = self.proof.keypair()?;

        let signature_version = block_signature_version(
            &keypair,
            next_keypair,
            &external_signature,
            // The version block is not directly available, so we don’t take it into account here
            // `append_serialized` is only used for third-party blocks anyway, so maybe we should make `external_signature` mandatory and not bother
            &None,
            std::iter::once(self.authority.version)
                .chain(self.blocks.iter().map(|block| block.version)),
        );

        let signature = crypto::sign_block(
            &keypair,
            next_keypair,
            &block,
            external_signature.as_ref(),
            &self.last_block().signature,
            signature_version,
        )?;

        // Add new block
        let mut blocks = self.blocks.clone();
        blocks.push(crypto::Block {
            data: block,
            next_key: next_keypair.public(),
            signature,
            external_signature,
            version: signature_version,
        });

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks,
            proof: TokenNext::Secret(next_keypair.private()),
        })
    }

    /// checks the signature on a deserialized token
    pub fn verify(&self, root: &PublicKey) -> Result<(), error::Format> {
        self.verify_inner(root, ThirdPartyVerificationMode::PreviousSignatureHashing)
    }

    pub(crate) fn verify_inner(
        &self,
        root: &PublicKey,
        verification_mode: ThirdPartyVerificationMode,
    ) -> Result<(), error::Format> {
        //FIXME: try batched signature verification
        let mut current_pub = root;
        let mut previous_signature;

        crypto::verify_authority_block_signature(&self.authority, current_pub)?;
        current_pub = &self.authority.next_key;
        previous_signature = &self.authority.signature;

        for block in &self.blocks {
            let verification_mode = match (block.version, verification_mode) {
                (0, ThirdPartyVerificationMode::UnsafeLegacy) => {
                    ThirdPartyVerificationMode::UnsafeLegacy
                }
                _ => ThirdPartyVerificationMode::PreviousSignatureHashing,
            };

            crypto::verify_block_signature(
                block,
                current_pub,
                previous_signature,
                verification_mode,
            )?;
            current_pub = &block.next_key;
            previous_signature = &block.signature;
        }

        match &self.proof {
            TokenNext::Secret(private) => {
                if current_pub != &private.public() {
                    return Err(error::Format::Signature(
                        error::Signature::InvalidSignature(
                            "the last public key does not match the private key".to_string(),
                        ),
                    ));
                }
            }
            TokenNext::Seal(signature) => {
                //FIXME: replace with SHA512 hashing
                let block = if self.blocks.is_empty() {
                    &self.authority
                } else {
                    &self.blocks[self.blocks.len() - 1]
                };

                let to_verify = crypto::generate_seal_signature_payload_v0(block);

                current_pub.verify_signature(&to_verify, signature)?;
            }
        }

        Ok(())
    }

    pub fn seal(&self) -> Result<Self, error::Token> {
        let keypair = self.proof.keypair()?;

        //FIXME: replace with SHA512 hashing
        let block = if self.blocks.is_empty() {
            &self.authority
        } else {
            &self.blocks[self.blocks.len() - 1]
        };

        let to_sign = crypto::generate_seal_signature_payload_v0(block);

        let signature = keypair.sign(&to_sign)?;

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            proof: TokenNext::Seal(signature),
        })
    }

    pub(crate) fn last_block(&self) -> &crypto::Block {
        self.blocks.last().unwrap_or(&self.authority)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ThirdPartyVerificationMode {
    UnsafeLegacy,
    PreviousSignatureHashing,
}

fn block_signature_version<I>(
    block_keypair: &KeyPair,
    next_keypair: &KeyPair,
    external_signature: &Option<ExternalSignature>,
    block_version: &Option<u32>,
    previous_blocks_sig_versions: I,
) -> u32
where
    I: Iterator<Item = u32>,
{
    if external_signature.is_some() {
        return THIRD_PARTY_SIGNATURE_VERSION;
    }

    match block_version {
        Some(block_version) if *block_version >= DATALOG_3_3 => {
            return DATALOG_3_3_SIGNATURE_VERSION;
        }
        _ => {}
    }

    match (block_keypair, next_keypair) {
        (KeyPair::Ed25519(_), KeyPair::Ed25519(_)) => {}
        _ => {
            return NON_ED25519_SIGNATURE_VERSION;
        }
    }

    previous_blocks_sig_versions.max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::{
        builder::Algorithm,
        crypto::{ExternalSignature, Signature},
        format::block_signature_version,
        token::{DATALOG_3_1, DATALOG_3_3},
        KeyPair,
    };

    #[test]
    fn proto() {
        // somehow when building under cargo-tarpaulin, OUT_DIR is not set
        let out_dir = match std::env::var("OUT_DIR") {
            Ok(dir) => dir,
            Err(_) => return,
        };
        prost_build::compile_protos(&["src/format/schema.proto"], &["src/"]).unwrap();
        let mut file = std::fs::File::open(format!("{out_dir}/biscuit.format.schema.rs")).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        let commited_schema = include_str!("schema.rs");

        if contents != commited_schema {
            println!(
                "{}",
                colored_diff::PrettyDifference {
                    expected: &contents,
                    actual: commited_schema
                }
            );
            panic!();
        }
    }

    #[test]
    fn test_block_signature_version() {
        assert_eq!(
            block_signature_version(
                &KeyPair::new(),
                &KeyPair::new(),
                &None,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            0,
            "ed25519 everywhere, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &KeyPair::new_with_algorithm(Algorithm::Secp256r1),
                &KeyPair::new_with_algorithm(Algorithm::Ed25519),
                &None,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            1,
            "s256r1 root key, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &KeyPair::new_with_algorithm(Algorithm::Ed25519),
                &KeyPair::new_with_algorithm(Algorithm::Secp256r1),
                &None,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            1,
            "s256r1 next key, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &KeyPair::new_with_algorithm(Algorithm::Secp256r1),
                &KeyPair::new_with_algorithm(Algorithm::Secp256r1),
                &None,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            1,
            "s256r1 root & next key, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &KeyPair::new(),
                &KeyPair::new(),
                &Some(ExternalSignature {
                    public_key: KeyPair::new().public(),
                    signature: Signature::from_vec(Vec::new())
                }),
                &Some(DATALOG_3_1),
                std::iter::once(0)
            ),
            1,
            "ed25519 root & next key, third-party block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &KeyPair::new(),
                &KeyPair::new(),
                &None,
                &Some(DATALOG_3_3),
                std::iter::empty()
            ),
            1,
            "ed25519 root & next key, first-party block, new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &KeyPair::new(),
                &KeyPair::new(),
                &None,
                &Some(DATALOG_3_1),
                std::iter::once(1)
            ),
            1,
            "ed25519 root & next key, first-party block, no new datalog features, previous v1 block"
        );
    }
}
