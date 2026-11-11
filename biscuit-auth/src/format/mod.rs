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
use std::fmt::{self, Debug, Formatter};

use super::crypto::{self, PrivateKey, Proof};

use prost::Message;

use super::error;
use super::token::Block;
use crate::Algorithm;
use crate::crypto::{ExternalSignature, SerializePrivateKey, SerializePublicKey, Sign, Verify};
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

/// parses a signed block with the symbols and public keys defined by the previous first party
/// blocks, adding its own tables to `symbols` if it is a first party block
pub(crate) fn parse_block<NK, EK: SerializePublicKey>(
    block: &crypto::Block<NK, EK>,
    symbols: &mut SymbolTable,
    name: &str,
) -> Result<Block, error::Token> {
    let proto = schema::Block::decode(&block.data[..]).map_err(|e| {
        error::Format::BlockDeserializationError(format!("error deserializing {name}: {e:?}"))
    })?;
    let external_key = block.external_signature.as_ref().map(|ex| &ex.public_key);
    proto_block_to_token_block(&proto, external_key, Some(symbols)).map_err(Into::into)
}

pub(crate) const THIRD_PARTY_SIGNATURE_VERSION: u32 = 1;
pub(crate) const DATALOG_3_3_SIGNATURE_VERSION: u32 = 1;
pub(crate) const NON_ED25519_SIGNATURE_VERSION: u32 = 1;

/// Intermediate structure for token serialization
///
/// This structure contains the blocks serialized to byte arrays. Those arrays
/// will be used for the signature
#[derive(Clone)]
pub struct SerializedBiscuit<K: SerializePrivateKey = PrivateKey> {
    pub root_key_id: Option<u32>,
    pub authority: crypto::Block<K::PublicKey, K::PublicKey>,
    pub blocks: Vec<crypto::Block<K::PublicKey, K::PublicKey>>,
    pub proof: crypto::Proof<K>,
}

impl<K: SerializePrivateKey> SerializedBiscuit<K> {
    pub fn from_slice<KP>(slice: &[u8], key_provider: KP) -> Result<Self, error::Format>
    where
        KP: RootKeyProvider<Key = K::PublicKey>,
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
        KP: RootKeyProvider<Key = K::PublicKey>,
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

        let next_key: K::PublicKey = convert::public_key_from_proto(&data.authority.next_key)?;
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
            let next_key: K::PublicKey = convert::public_key_from_proto(&block.next_key)?;
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

                let public_key = convert::public_key_from_proto(&ex.public_key)?;
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
                Proof::Secret(K::from_bytes_and_algorithm(next_key_algorithm, &v)?)
            }
            Some(schema::proof::Content::FinalSignature(v)) => {
                let signature = Signature::from_vec(v);

                Proof::Seal(signature)
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

    /// parses the blocks of the token
    ///
    /// blocks are parsed in order, each with the symbols and public keys known at that point
    /// (`symbols`, which is extended with the tables of first party blocks), so a block cannot
    /// reference symbols or public keys from later blocks
    pub(crate) fn extract_blocks(
        &self,
        symbols: &mut SymbolTable,
    ) -> Result<(Block, Vec<Block>), error::Token> {
        let authority = parse_block(&self.authority, symbols, "authority block")?;

        let mut blocks = vec![];
        for block in self.blocks.iter() {
            blocks.push(parse_block(block, symbols, "block")?);
        }

        Ok((authority, blocks))
    }

    /// serializes the token
    pub fn to_proto(&self) -> schema::Biscuit {
        let authority = schema::SignedBlock {
            block: self.authority.data.clone(),
            next_key: convert::public_key_to_proto(&self.authority.next_key),
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
                next_key: convert::public_key_to_proto(&block.next_key),
                signature: block.signature.to_bytes().to_vec(),
                external_signature: block.external_signature.as_ref().map(|external_signature| {
                    schema::ExternalSignature {
                        signature: external_signature.signature.to_bytes().to_vec(),
                        public_key: convert::public_key_to_proto(&external_signature.public_key),
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
                    Proof::Seal(signature) => Some(schema::proof::Content::FinalSignature(
                        signature.to_bytes().to_vec(),
                    )),
                    Proof::Secret(private) => Some(schema::proof::Content::NextSecret(
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
    pub fn new<RK: Sign>(
        root_key_id: Option<u32>,
        root_private_key: &RK,
        next_private_key: &K,
        authority: &Block,
    ) -> Result<Self, error::Token> {
        let authority_signature_version = block_signature_version(
            root_private_key,
            next_private_key,
            &None::<ExternalSignature<K::PublicKey>>,
            &Some(authority.version),
            std::iter::empty(),
        );
        Self::new_inner(
            root_key_id,
            root_private_key,
            next_private_key,
            authority,
            authority_signature_version,
        )
    }

    /// creates a new token
    pub(crate) fn new_inner<RK: Sign>(
        root_key_id: Option<u32>,
        root_private_key: &RK,
        next_private_key: &K,
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
            root_private_key,
            &next_private_key.public(),
            &v,
            authority_signature_version,
        )?;

        Ok(SerializedBiscuit {
            root_key_id,
            authority: crypto::Block {
                data: v,
                next_key: next_private_key.public(),
                signature,
                external_signature: None,
                version: authority_signature_version,
            },
            blocks: vec![],
            proof: Proof::Secret(next_private_key.clone()),
        })
    }

    /// adds a new block, serializes it and sign a new token
    pub fn append(
        &self,
        next_private_key: &K,
        block: &Block,
        external_signature: Option<ExternalSignature<K::PublicKey>>,
    ) -> Result<Self, error::Token> {
        let private_key = self.proof.private_key()?;

        let mut v = Vec::new();
        token_block_to_proto_block(block)
            .encode(&mut v)
            .map_err(|e| {
                error::Format::SerializationError(format!("serialization error: {e:?}"))
            })?;

        let signature_version = block_signature_version(
            &private_key,
            next_private_key,
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
            &private_key,
            &next_private_key.public(),
            &v,
            external_signature.as_ref(),
            &self.last_block().signature,
            signature_version,
        )?;

        // Add new block
        let mut blocks = self.blocks.clone();
        blocks.push(crypto::Block {
            data: v,
            next_key: next_private_key.public(),
            signature,
            external_signature,
            version: signature_version,
        });

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks,
            proof: Proof::Secret(next_private_key.clone()),
        })
    }

    /// adds a new block, serializes it and sign a new token
    pub fn append_serialized(
        &self,
        next_private_key: &K,
        block: Vec<u8>,
        external_signature: Option<ExternalSignature<K::PublicKey>>,
    ) -> Result<Self, error::Token> {
        let private_key = self.proof.private_key()?;

        let signature_version = block_signature_version(
            &private_key,
            next_private_key,
            &external_signature,
            // The version block is not directly available, so we don’t take it into account here
            // `append_serialized` is only used for third-party blocks anyway, so maybe we should make `external_signature` mandatory and not bother
            &None,
            std::iter::once(self.authority.version)
                .chain(self.blocks.iter().map(|block| block.version)),
        );

        let signature = crypto::sign_block(
            &private_key,
            &next_private_key.public(),
            &block,
            external_signature.as_ref(),
            &self.last_block().signature,
            signature_version,
        )?;

        // Add new block
        let mut blocks = self.blocks.clone();
        blocks.push(crypto::Block {
            data: block,
            next_key: next_private_key.public(),
            signature,
            external_signature,
            version: signature_version,
        });

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks,
            proof: Proof::Secret(next_private_key.clone()),
        })
    }

    /// checks the signature on a deserialized token
    pub fn verify<RK: Verify>(&self, root: &RK) -> Result<(), error::Format> {
        self.verify_inner(root, ThirdPartyVerificationMode::PreviousSignatureHashing)
    }

    pub(crate) fn verify_inner<RK: Verify>(
        &self,
        root: &RK,
        verification_mode: ThirdPartyVerificationMode,
    ) -> Result<(), error::Format> {
        //FIXME: try batched signature verification
        let mut previous_signature;

        crypto::verify_authority_block_signature(&self.authority, root)?;
        let mut current_pub = &self.authority.next_key;
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
            Proof::Secret(private) => {
                if *current_pub != private.public() {
                    return Err(error::Format::Signature(
                        error::Signature::InvalidSignature(
                            "the last public key does not match the private key".to_string(),
                        ),
                    ));
                }
            }
            Proof::Seal(signature) => {
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
        let private_key = self.proof.private_key()?;

        //FIXME: replace with SHA512 hashing
        let block = if self.blocks.is_empty() {
            &self.authority
        } else {
            &self.blocks[self.blocks.len() - 1]
        };

        let to_sign = crypto::generate_seal_signature_payload_v0(block);

        let signature = private_key.sign(&to_sign)?;

        Ok(SerializedBiscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks: self.blocks.clone(),
            proof: Proof::Seal(signature),
        })
    }

    pub(crate) fn last_block(&self) -> &crypto::Block<K::PublicKey, K::PublicKey> {
        self.blocks.last().unwrap_or(&self.authority)
    }
}

impl<K> Debug for SerializedBiscuit<K>
where
    K: SerializePrivateKey + Debug,
    K::PublicKey: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("SerializedBiscuit")
            .field("root_key_id", &self.root_key_id)
            .field("authority", &self.authority)
            .field("blocks", &self.blocks)
            .field("proof", &self.proof)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ThirdPartyVerificationMode {
    UnsafeLegacy,
    PreviousSignatureHashing,
}

fn block_signature_version<I, RK: Sign, AK: Sign, EK>(
    block_private_key: &RK,
    next_private_key: &AK,
    external_signature: &Option<ExternalSignature<EK>>,
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

    match (block_private_key.algorithm(), next_private_key.algorithm()) {
        (Algorithm::Ed25519, Algorithm::Ed25519) => {}
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
        PrivateKey,
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

        let generated = rustfmt(&contents);
        let commited = rustfmt(commited_schema);

        if generated != commited {
            println!(
                "{}",
                colored_diff::PrettyDifference {
                    expected: &generated,
                    actual: &commited
                }
            );
            panic!();
        }
    }

    fn rustfmt(input: &str) -> String {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("rustfmt")
            .args(["--edition", "2018", "--emit", "stdout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn rustfmt");

        child
            .stdin
            .take()
            .expect("failed to open rustfmt stdin")
            .write_all(input.as_bytes())
            .expect("failed to write to rustfmt stdin");

        let output = child
            .wait_with_output()
            .expect("failed to read rustfmt output");
        assert!(output.status.success(), "rustfmt failed");

        String::from_utf8(output.stdout).expect("rustfmt output was not valid UTF-8")
    }

    #[test]
    fn test_block_signature_version() {
        assert_eq!(
            block_signature_version(
                &PrivateKey::new(),
                &PrivateKey::new(),
                &None::<ExternalSignature>,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            0,
            "ed25519 everywhere, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &PrivateKey::new_with_algorithm(Algorithm::Secp256r1),
                &PrivateKey::new_with_algorithm(Algorithm::Ed25519),
                &None::<ExternalSignature>,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            1,
            "s256r1 root key, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &PrivateKey::new_with_algorithm(Algorithm::Ed25519),
                &PrivateKey::new_with_algorithm(Algorithm::Secp256r1),
                &None::<ExternalSignature>,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            1,
            "s256r1 next key, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &PrivateKey::new_with_algorithm(Algorithm::Secp256r1),
                &PrivateKey::new_with_algorithm(Algorithm::Secp256r1),
                &None::<ExternalSignature>,
                &Some(DATALOG_3_1),
                std::iter::empty()
            ),
            1,
            "s256r1 root & next key, authority block, no new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &PrivateKey::new(),
                &PrivateKey::new(),
                &Some(ExternalSignature {
                    public_key: PrivateKey::new().public(),
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
                &PrivateKey::new(),
                &PrivateKey::new(),
                &None::<ExternalSignature>,
                &Some(DATALOG_3_3),
                std::iter::empty()
            ),
            1,
            "ed25519 root & next key, first-party block, new datalog features"
        );
        assert_eq!(
            block_signature_version(
                &PrivateKey::new(),
                &PrivateKey::new(),
                &None::<ExternalSignature>,
                &Some(DATALOG_3_1),
                std::iter::once(1)
            ),
            1,
            "ed25519 root & next key, first-party block, no new datalog features, previous v1 block"
        );
    }
}

#[cfg(test)]
mod symbol_reference_tests {
    use prost::Message;

    use crate::error::{Format, Token};
    use crate::format::schema;
    use crate::{Biscuit, BlockBuilder, PrivateKey, UnverifiedBiscuit};

    fn edit_block(token: &Biscuit, index: usize, edit: impl FnOnce(&mut schema::Block)) -> Vec<u8> {
        let mut proto = schema::Biscuit::decode(&token.to_vec().unwrap()[..]).unwrap();
        let signed = if index == 0 {
            &mut proto.authority
        } else {
            &mut proto.blocks[index - 1]
        };
        let mut block = schema::Block::decode(&signed.block[..]).unwrap();
        edit(&mut block);
        signed.block = block.encode_to_vec();
        proto.encode_to_vec()
    }

    fn block(token: &Biscuit, index: usize) -> schema::Block {
        let proto = schema::Biscuit::decode(&token.to_vec().unwrap()[..]).unwrap();
        let signed = if index == 0 {
            &proto.authority
        } else {
            &proto.blocks[index - 1]
        };
        schema::Block::decode(&signed.block[..]).unwrap()
    }

    #[test]
    fn forward_symbol_references_are_rejected() {
        let root = PrivateKey::new();
        let token = Biscuit::builder()
            .build(&root)
            .unwrap()
            .append(BlockBuilder::new().code("check if true;").unwrap())
            .unwrap()
            .append(BlockBuilder::new().code("defined_later(1);").unwrap())
            .unwrap();
        // the fact stays in the last block, so its name is defined there, and a copy is added
        // to the first attenuation, which cannot see that block's symbols
        let fact = block(&token, 2).facts[0].clone();
        let name = fact.predicate.name;
        let token = edit_block(&token, 1, |block| block.facts.push(fact));

        assert_eq!(
            UnverifiedBiscuit::from(&token).unwrap_err(),
            Token::Format(Format::UnknownSymbol(name))
        );
    }

    #[test]
    fn unknown_symbols_are_rejected() {
        let root = PrivateKey::new();
        let token = Biscuit::builder()
            .code("fact(\"string\");")
            .unwrap()
            .build(&root)
            .unwrap();
        let token = edit_block(&token, 0, |block| block.symbols.clear());

        assert!(matches!(
            UnverifiedBiscuit::from(&token).unwrap_err(),
            Token::Format(Format::UnknownSymbol(_))
        ));
    }

    #[test]
    fn unknown_public_keys_are_rejected() {
        let root = PrivateKey::new();
        let token = Biscuit::builder()
            .build(&root)
            .unwrap()
            .append(
                BlockBuilder::new()
                    .code("check if true trusting authority;")
                    .unwrap(),
            )
            .unwrap();
        let token = edit_block(&token, 1, |block| {
            block.scope.push(schema::Scope {
                content: Some(schema::scope::Content::PublicKey(0)),
            })
        });

        assert_eq!(
            UnverifiedBiscuit::from(&token).unwrap_err(),
            Token::Format(Format::UnknownExternalKey)
        );
    }

    #[test]
    fn third_party_blocks_only_see_their_own_symbols() {
        let root = PrivateKey::new();
        let token = Biscuit::builder()
            .code("authority_fact(1);")
            .unwrap()
            .build(&root)
            .unwrap();
        let external = PrivateKey::new();
        let third_party_block = token
            .third_party_request()
            .unwrap()
            .create_block(
                &external,
                BlockBuilder::new().code("third_party_fact(1);").unwrap(),
            )
            .unwrap();
        let token = token
            .append_third_party(external.public(), third_party_block)
            .unwrap();

        let shared_index = block(&token, 1).facts[0].predicate.name;
        assert_eq!(block(&token, 0).facts[0].predicate.name, shared_index);
        let token = edit_block(&token, 1, |block| block.symbols.clear());

        assert_eq!(
            UnverifiedBiscuit::from(&token).unwrap_err(),
            Token::Format(Format::UnknownSymbol(shared_index))
        );
    }

    #[test]
    fn valid_references_are_accepted() {
        let root = PrivateKey::new();
        let trusted = PrivateKey::new();
        let token = Biscuit::builder()
            .code(format!(
                r#"fact("string", {{"key": [1, {{"a"}}]}}); check if fact($x, $y), $x.extern::f($y), [1].any($p -> $p == 1) trusting {};"#,
                trusted.public()
            ))
            .unwrap()
            .build(&root)
            .unwrap()
            .append(
                BlockBuilder::new()
                    .code(r#"check if fact("string", $y) trusting authority;"#)
                    .unwrap(),
            )
            .unwrap();
        let bytes = token.to_vec().unwrap();

        assert!(UnverifiedBiscuit::from(&bytes).is_ok());
        assert!(Biscuit::from(&bytes, root.public()).is_ok());
    }
}
