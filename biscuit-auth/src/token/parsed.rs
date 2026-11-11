/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! contents shared by [crate::Biscuit] and [crate::UnverifiedBiscuit]
use std::iter::once;

use base64::prelude::*;

use super::public_keys::PublicKeys;
use super::{Block, ThirdPartyRequest};
use crate::builder::{self, BlockBuilder};
use crate::crypto::{self, SerializePrivateKey, Sign, Signature};
use crate::datalog::SymbolTable;
use crate::error;
use crate::format::convert::public_key_from_proto;
use crate::format::schema::ThirdPartyBlockContents;
use crate::format::{parse_block, SerializedBiscuit, THIRD_PARTY_SIGNATURE_VERSION};

/// a signed token and its parsed blocks
///
/// [crate::Biscuit] and [crate::UnverifiedBiscuit] only differ in whether the signatures of the
/// container have been verified, so they share this representation and its operations
#[derive(Clone)]
pub(crate) struct ParsedToken<K: SerializePrivateKey> {
    pub(crate) authority: Block,
    pub(crate) blocks: Vec<Block>,
    /// the symbols and public keys of the first party blocks
    pub(crate) symbols: SymbolTable,
    pub(crate) container: SerializedBiscuit<K>,
}

impl<K: SerializePrivateKey> ParsedToken<K> {
    /// parses the blocks of a deserialized container
    pub(crate) fn from_container(
        container: SerializedBiscuit<K>,
        mut symbols: SymbolTable,
    ) -> Result<Self, error::Token> {
        let (authority, blocks) = container.extract_blocks(&mut symbols)?;

        Ok(ParsedToken {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// creates a new token, signing the authority block with the root key
    pub(crate) fn new<RK: Sign>(
        root_key_id: Option<u32>,
        root_key: &RK,
        next_key: &K,
        mut symbols: SymbolTable,
        authority: Block,
    ) -> Result<Self, error::Token> {
        if !symbols.is_disjoint(&authority.symbols) {
            return Err(error::Token::Format(error::Format::SymbolTableOverlap));
        }

        let container = SerializedBiscuit::new(root_key_id, root_key, next_key, &authority)?;
        let authority = parse_block(&container.authority, &mut symbols, "authority block")?;

        Ok(ParsedToken {
            authority,
            blocks: vec![],
            symbols,
            container,
        })
    }

    /// builds the token for a container which has one more block than this token's container
    fn with_appended_block(&self, container: SerializedBiscuit<K>) -> Result<Self, error::Token> {
        let mut symbols = self.symbols.clone();
        let mut blocks = self.blocks.clone();

        blocks.push(parse_block(
            container
                .blocks
                .last()
                .expect("a new block was just added so the list is not empty"),
            &mut symbols,
            "block",
        )?);

        Ok(ParsedToken {
            authority: self.authority.clone(),
            blocks,
            symbols,
            container,
        })
    }

    pub(crate) fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        let key = K::new_with_rng(builder::Algorithm::Ed25519, &mut rand::rng());
        self.append_with_key(&key, block_builder)
    }

    pub(crate) fn append_with_key(
        &self,
        key: &K,
        block_builder: BlockBuilder,
    ) -> Result<Self, error::Token> {
        let block = block_builder.build(self.symbols.clone());

        if !self.symbols.is_disjoint(&block.symbols) {
            return Err(error::Token::Format(error::Format::SymbolTableOverlap));
        }

        let container = self.container.append(key, &block, None)?;
        self.with_appended_block(container)
    }

    /// appends a third party block after verifying its signature
    ///
    /// if `expected_key` is provided, the block must be signed by this key
    pub(crate) fn append_third_party_with_key(
        &self,
        expected_key: Option<&K::PublicKey>,
        contents: ThirdPartyBlockContents,
        next_key: K,
    ) -> Result<Self, error::Token> {
        let ThirdPartyBlockContents {
            payload,
            external_signature,
        } = contents;

        let external_key: K::PublicKey = public_key_from_proto(&external_signature.public_key)?;
        if let Some(expected_key) = expected_key {
            if *expected_key != external_key {
                return Err(error::Token::Format(error::Format::DeserializationError(
                    format!(
                        "deserialization error: unexpected key {}",
                        crypto::print(&external_key),
                    ),
                )));
            }
        }

        let external_signature = crypto::ExternalSignature {
            public_key: external_key,
            signature: Signature::from_vec(external_signature.signature),
        };

        let previous_block = self
            .container
            .blocks
            .last()
            .unwrap_or(&self.container.authority);
        crypto::verify_external_signature(
            &payload,
            &previous_block.signature,
            &external_signature,
            THIRD_PARTY_SIGNATURE_VERSION,
        )?;

        let container =
            self.container
                .append_serialized(&next_key, payload, Some(external_signature))?;
        self.with_appended_block(container)
    }

    pub(crate) fn seal(&self) -> Result<Self, error::Token> {
        let mut token = self.clone();
        token.container = self.container.seal()?;
        Ok(token)
    }

    pub(crate) fn third_party_request(&self) -> Result<ThirdPartyRequest, error::Token> {
        ThirdPartyRequest::from_container(&self.container)
    }

    pub(crate) fn to_vec(&self) -> Result<Vec<u8>, error::Token> {
        self.container.to_vec().map_err(error::Token::Format)
    }

    pub(crate) fn to_base64(&self) -> Result<String, error::Token> {
        self.to_vec().map(|v| BASE64_URL_SAFE.encode(v))
    }

    pub(crate) fn serialized_size(&self) -> usize {
        self.container.serialized_size()
    }

    pub(crate) fn root_key_id(&self) -> Option<u32> {
        self.container.root_key_id
    }

    pub(crate) fn context(&self) -> Vec<Option<String>> {
        self.blocks().map(|block| block.context.clone()).collect()
    }

    pub(crate) fn revocation_identifiers(&self) -> Vec<Vec<u8>> {
        once(&self.container.authority)
            .chain(self.container.blocks.iter())
            .map(|block| block.signature.to_bytes().to_vec())
            .collect()
    }

    pub(crate) fn external_public_keys(&self) -> Vec<Option<K::PublicKey>> {
        once(&self.container.authority)
            .chain(self.container.blocks.iter())
            .map(|block| {
                block
                    .external_signature
                    .as_ref()
                    .map(|signature| signature.public_key.clone())
            })
            .collect()
    }

    pub(crate) fn block_count(&self) -> usize {
        1 + self.blocks.len()
    }

    pub(crate) fn block(&self, index: usize) -> Result<&Block, error::Token> {
        if index == 0 {
            Ok(&self.authority)
        } else {
            self.blocks
                .get(index - 1)
                .ok_or(error::Token::Format(error::Format::InvalidBlockId(index)))
        }
    }

    pub(crate) fn blocks(&self) -> impl Iterator<Item = &Block> {
        once(&self.authority).chain(self.blocks.iter())
    }

    /// the symbols and public keys a block is evaluated with
    pub(crate) fn block_symbol_table<'a>(&'a self, block: &'a Block) -> &'a SymbolTable {
        if block.external_key.is_some() {
            &block.symbols
        } else {
            &self.symbols
        }
    }

    pub(crate) fn print_block_source(&self, index: usize) -> Result<String, error::Token> {
        self.block(index)
            .map(|block| block.print_source(self.block_symbol_table(block)))
    }

    pub(crate) fn block_version(&self, index: usize) -> Result<u32, error::Token> {
        self.block(index).map(|block| block.version)
    }

    pub(crate) fn block_symbols(&self, index: usize) -> Result<Vec<String>, error::Token> {
        self.block(index).map(|block| block.symbols.strings())
    }

    pub(crate) fn block_public_keys(&self, index: usize) -> Result<PublicKeys, error::Token> {
        self.block(index).map(|block| block.public_keys.clone())
    }

    pub(crate) fn block_external_key(
        &self,
        index: usize,
    ) -> Result<Option<K::PublicKey>, error::Token> {
        let block = if index == 0 {
            &self.container.authority
        } else {
            self.container
                .blocks
                .get(index - 1)
                .ok_or(error::Token::Format(error::Format::InvalidBlockId(index)))?
        };

        Ok(block
            .external_signature
            .as_ref()
            .map(|signature| signature.public_key.clone()))
    }
}
