/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use prost::Message;

use super::{default_symbol_table, Biscuit, Block};
use crate::{
    builder::BlockBuilder,
    crypto::{self, PublicKey, Signature},
    datalog::SymbolTable,
    error,
    format::{
        convert::proto_block_to_token_block,
        schema::{self, public_key::Algorithm},
        SerializedBiscuit,
    },
    token::{ThirdPartyBlockContents, ThirdPartyRequest},
    KeyPair, RootKeyProvider,
};

/// A token that was parsed without cryptographic signature verification
///
/// Use this if you want to attenuate or print the content of a token
/// without verifying it.
///
/// It can be converted to a [Biscuit] using [UnverifiedBiscuit::verify],
/// and then used for authorization
#[derive(Clone, Debug)]
pub struct UnverifiedBiscuit {
    pub(crate) authority: schema::Block,
    pub(crate) blocks: Vec<schema::Block>,
    pub(crate) symbols: SymbolTable,
    container: SerializedBiscuit,
}

impl UnverifiedBiscuit {
    /// deserializes a token from raw bytes
    pub fn from<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        Self::from_with_symbols(slice.as_ref(), default_symbol_table())
    }

    /// deserializes a token from raw bytes
    ///
    /// This allows the deprecated 3rd party block format
    pub fn unsafe_deprecated_deserialize<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let container = SerializedBiscuit::deserialize(
            slice.as_ref(),
            crate::format::ThirdPartyVerificationMode::UnsafeLegacy,
        )?;
        let mut symbols = default_symbol_table();

        let (authority, blocks) = container.extract_blocks(&mut symbols)?;

        Ok(UnverifiedBiscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// deserializes a token from base64
    pub fn from_base64<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        Self::from_base64_with_symbols(slice, default_symbol_table())
    }

    #[deprecated(since = "4.1.0", note = "please use `verify` instead")]
    /// checks the signature of the token and convert it to a [Biscuit] for authorization
    pub fn check_signature<F>(self, f: F) -> Result<Biscuit, error::Format>
    where
        F: Fn(Option<u32>) -> PublicKey,
    {
        self.verify(|kid| Ok(f(kid)))
    }

    /// checks the signature of the token and convert it to a [Biscuit] for authorization
    pub fn verify<KP>(self, key_provider: KP) -> Result<Biscuit, error::Format>
    where
        KP: RootKeyProvider,
    {
        let key = key_provider.choose(self.root_key_id())?;
        self.container.verify(&key)?;

        Ok(Biscuit {
            root_key_id: self.container.root_key_id,
            authority: self.authority,
            blocks: self.blocks,
            symbols: self.symbols,
            container: self.container,
        })
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        let keypair = KeyPair::new_with_rng(super::builder::Algorithm::Ed25519, &mut rand::rng());
        self.append_with_keypair(&keypair, block_builder)
    }

    /// serializes the token
    pub fn to_vec(&self) -> Result<Vec<u8>, error::Token> {
        self.container.to_vec().map_err(error::Token::Format)
    }

    /// serializes the token and encode it to a (URL safe) base64 string
    pub fn to_base64(&self) -> Result<String, error::Token> {
        self.container
            .to_vec()
            .map_err(error::Token::Format)
            .map(|v| base64::encode_config(v, base64::URL_SAFE))
    }

    /// deserializes from raw bytes with a custom symbol table
    pub fn from_with_symbols(slice: &[u8], mut symbols: SymbolTable) -> Result<Self, error::Token> {
        let container = SerializedBiscuit::deserialize(
            slice,
            crate::format::ThirdPartyVerificationMode::PreviousSignatureHashing,
        )?;

        let (authority, blocks) = container.extract_blocks(&mut symbols)?;

        Ok(UnverifiedBiscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// deserializes a token from base64 with a custom symbol table
    pub fn from_base64_with_symbols<T>(slice: T, symbols: SymbolTable) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Self::from_with_symbols(&decoded, symbols)
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append_with_keypair(
        &self,
        keypair: &KeyPair,
        block_builder: BlockBuilder,
    ) -> Result<Self, error::Token> {
        let block = block_builder.build(self.symbols.clone());

        if !self.symbols.is_disjoint(&block.symbols) {
            return Err(error::Token::Format(error::Format::SymbolTableOverlap));
        }

        let authority = self.authority.clone();
        let mut blocks = self.blocks.clone();
        let mut symbols = self.symbols.clone();

        let container = self.container.append(keypair, &block, None)?;

        symbols.extend(&block.symbols)?;
        symbols.public_keys.extend(&block.public_keys)?;

        let deser = schema::Block::decode(
            &container
                .blocks
                .last()
                .expect("a new block was just added so the list is not empty")
                .data[..],
        )
        .map_err(|e| {
            error::Token::Format(error::Format::BlockDeserializationError(format!(
                "error deserializing block: {:?}",
                e
            )))
        })?;
        blocks.push(deser);

        Ok(UnverifiedBiscuit {
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// returns an (optional) root key identifier. It provides a hint for public key selection during verification
    pub fn root_key_id(&self) -> Option<u32> {
        self.container.root_key_id
    }

    /// returns a list of revocation identifiers for each block, in order
    ///
    /// revocation identifiers are unique: tokens generated separately with
    /// the same contents will have different revocation ids
    pub fn revocation_identifiers(&self) -> Vec<Vec<u8>> {
        let mut res = vec![self.container.authority.signature.to_bytes().to_vec()];

        for block in self.container.blocks.iter() {
            res.push(block.signature.to_bytes().to_vec());
        }

        res
    }

    /// returns a list of external key for each block, in order
    ///
    /// Blocks carrying an external public key are _third-party blocks_
    /// and their contents can be trusted as coming from the holder of
    /// the corresponding private key
    pub fn external_public_keys(&self) -> Vec<Option<PublicKey>> {
        let mut res = vec![None];

        for block in self.container.blocks.iter() {
            res.push(block.external_signature.as_ref().map(|sig| sig.public_key));
        }

        res
    }

    /// returns the number of blocks (at least 1)
    pub fn block_count(&self) -> usize {
        1 + self.container.blocks.len()
    }

    /// prints the content of a block as Datalog source code
    pub fn print_block_source(&self, index: usize) -> Result<String, error::Token> {
        self.block(index).map(|block| {
            let symbols = if block.external_key.is_some() {
                &block.symbols
            } else {
                &self.symbols
            };
            block.print_source(symbols)
        })
    }

    /// gets the datalog version for a given block
    pub fn block_version(&self, index: usize) -> Result<u32, error::Token> {
        self.block(index).map(|block| block.version)
    }

    pub(crate) fn block(&self, index: usize) -> Result<Block, error::Token> {
        let mut block = if index == 0 {
            proto_block_to_token_block(
                &self.authority,
                self.container
                    .authority
                    .external_signature
                    .as_ref()
                    .map(|ex| ex.public_key),
            )
            .map_err(error::Token::Format)?
        } else {
            if index > self.blocks.len() + 1 {
                return Err(error::Token::Format(
                    error::Format::BlockDeserializationError("invalid block index".to_string()),
                ));
            }

            proto_block_to_token_block(
                &self.blocks[index - 1],
                self.container.blocks[index - 1]
                    .external_signature
                    .as_ref()
                    .map(|ex| ex.public_key),
            )
            .map_err(error::Token::Format)?
        };

        // we have to add the entire list of public keys here because
        // they are used to validate 3rd party tokens
        block.symbols.public_keys = self.symbols.public_keys.clone();
        Ok(block)
    }

    /// creates a sealed version of the token
    ///
    /// sealed tokens cannot be attenuated
    pub fn seal(&self) -> Result<UnverifiedBiscuit, error::Token> {
        let container = self.container.seal()?;
        let mut token = self.clone();
        token.container = container;
        Ok(token)
    }

    pub fn third_party_request(&self) -> Result<ThirdPartyRequest, error::Token> {
        ThirdPartyRequest::from_container(&self.container)
    }

    pub fn append_third_party(&self, slice: &[u8]) -> Result<Self, error::Token> {
        let next_keypair =
            KeyPair::new_with_rng(super::builder::Algorithm::Ed25519, &mut rand::rng());
        self.append_third_party_with_keypair(slice, next_keypair)
    }

    pub fn append_third_party_with_keypair(
        &self,
        slice: &[u8],
        next_keypair: KeyPair,
    ) -> Result<Self, error::Token> {
        let ThirdPartyBlockContents {
            payload,
            external_signature,
        } = schema::ThirdPartyBlockContents::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        let algorithm =
            Algorithm::from_i32(external_signature.public_key.algorithm).ok_or_else(|| {
                error::Format::DeserializationError(
                    "deserialization error: invalid external key algorithm".to_string(),
                )
            })?;
        let external_key =
            PublicKey::from_bytes(&external_signature.public_key.key, algorithm.into()).map_err(
                |e| {
                    error::Format::BlockSignatureDeserializationError(format!(
                        "block external public key deserialization error: {:?}",
                        e
                    ))
                },
            )?;

        let signature = Signature::from_vec(external_signature.signature);

        let block = schema::Block::decode(&payload[..]).map_err(|e| {
            error::Token::Format(error::Format::DeserializationError(format!(
                "deserialization error: {:?}",
                e
            )))
        })?;

        let external_signature = crypto::ExternalSignature {
            public_key: external_key,
            signature,
        };

        let mut symbols = self.symbols.clone();
        let mut blocks = self.blocks.clone();

        let container =
            self.container
                .append_serialized(&next_keypair, payload, Some(external_signature))?;

        let token_block = proto_block_to_token_block(&block, Some(external_key)).unwrap();
        for key in &token_block.public_keys.keys {
            symbols.public_keys.insert_fallible(key)?;
        }

        blocks.push(block);

        Ok(UnverifiedBiscuit {
            authority: self.authority.clone(),
            blocks,
            symbols,
            container,
        })
    }

    pub fn append_third_party_base64<T>(&self, slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        self.append_third_party(&decoded)
    }
}

#[cfg(test)]
mod tests {
    use crate::{BiscuitBuilder, BlockBuilder, KeyPair};

    use super::UnverifiedBiscuit;

    #[test]
    fn consistent_with_biscuit() {
        let root_key = KeyPair::new();
        let external_key = KeyPair::new();
        let biscuit = BiscuitBuilder::new()
            .fact("test(true)")
            .unwrap()
            .build(&root_key)
            .unwrap()
            .append(BlockBuilder::new().fact("test(false)").unwrap())
            .unwrap();
        let req = biscuit.third_party_request().unwrap();
        let res = req
            .create_block(
                &external_key.private(),
                BlockBuilder::new().fact("third_party(true)").unwrap(),
            )
            .unwrap();
        let biscuit = biscuit
            .append_third_party(external_key.public(), res)
            .unwrap();

        let unverified = UnverifiedBiscuit::from_base64(biscuit.to_base64().unwrap()).unwrap();

        unverified.clone().verify(root_key.public()).unwrap();

        assert_eq!(unverified.blocks, biscuit.blocks);

        assert_eq!(
            unverified.external_public_keys(),
            biscuit.external_public_keys()
        );
    }
}
