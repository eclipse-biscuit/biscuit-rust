/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::fmt::{self, Debug, Formatter};

use base64::prelude::*;
use prost::Message;

use super::limits::DeserializationLimits;
use super::parsed::ParsedToken;
use super::public_keys::PublicKeys;
use super::{default_symbol_table, Biscuit};
use crate::crypto::SerializePrivateKey;
use crate::{
    builder::{self, BlockBuilder},
    crypto::{PrivateKey, PublicKey},
    datalog::SymbolTable,
    error,
    format::{schema, SerializedBiscuit},
    token::ThirdPartyRequest,
    RootKeyProvider,
};

/// A token that was parsed without cryptographic signature verification
///
/// Use this if you want to attenuate or print the content of a token
/// without verifying it.
///
/// It can be converted to a [Biscuit] using [UnverifiedBiscuit::verify],
/// and then used for authorization
#[derive(Clone)]
pub struct UnverifiedBiscuit<K: SerializePrivateKey = PrivateKey> {
    pub(crate) inner: ParsedToken<K>,
}

impl<K> Debug for UnverifiedBiscuit<K>
where
    K: SerializePrivateKey + Debug,
    K::PublicKey: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnverifiedBiscuit")
            .field("authority", &self.inner.authority)
            .field("blocks", &self.inner.blocks)
            .field("symbols", &self.inner.symbols)
            .field("container", &self.inner.container)
            .finish()
    }
}

impl UnverifiedBiscuit {
    /// deserializes a token from raw bytes
    pub fn from<T>(slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        Self::from_with_symbols(slice.as_ref(), default_symbol_table())
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

    /// deserializes a token from raw bytes, rejecting it if it does not respect the limits
    pub fn from_with_limits<T>(
        slice: T,
        limits: &DeserializationLimits,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        Self::from_with_symbols_and_limits(slice.as_ref(), default_symbol_table(), limits)
    }

    /// deserializes a token from base64, rejecting it if it does not respect the limits
    pub fn from_base64_with_limits<T>(
        slice: T,
        limits: &DeserializationLimits,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        super::limits::check_base64_size(slice.as_ref(), limits)?;
        let decoded = BASE64_URL_SAFE.decode(slice)?;
        Self::from_with_limits(&decoded, limits)
    }

    /// deserializes from raw bytes with a custom symbol table
    pub fn from_with_symbols(slice: &[u8], symbols: SymbolTable) -> Result<Self, error::Token> {
        Self::from_with_symbols_and_limits(
            slice,
            symbols,
            &DeserializationLimits::allow_everything(),
        )
    }

    fn from_with_symbols_and_limits(
        slice: &[u8],
        symbols: SymbolTable,
        limits: &DeserializationLimits,
    ) -> Result<Self, error::Token> {
        let container = SerializedBiscuit::deserialize(slice, limits)?;

        Ok(UnverifiedBiscuit {
            inner: ParsedToken::from_container(container, symbols, limits)?,
        })
    }

    /// deserializes a token from base64 with a custom symbol table
    pub fn from_base64_with_symbols<T>(slice: T, symbols: SymbolTable) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = BASE64_URL_SAFE.decode(slice)?;
        Self::from_with_symbols(&decoded, symbols)
    }
}

impl<K: SerializePrivateKey> UnverifiedBiscuit<K> {
    /// checks the signature of the token and convert it to a [Biscuit] for authorization
    pub fn verify<KP>(self, key_provider: KP) -> Result<Biscuit<K>, error::Format>
    where
        KP: RootKeyProvider<Key = K::PublicKey>,
    {
        let key = key_provider.choose(self.root_key_id())?;
        self.inner.container.verify(&key)?;

        Ok(Biscuit { inner: self.inner })
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the key can be discarded right after
    /// calling this function
    pub fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        self.inner
            .append(block_builder)
            .map(|inner| UnverifiedBiscuit { inner })
    }

    /// serializes the token
    pub fn to_vec(&self) -> Result<Vec<u8>, error::Token> {
        self.inner.to_vec()
    }

    /// serializes the token and encode it to a (URL safe) base64 string
    pub fn to_base64(&self) -> Result<String, error::Token> {
        self.inner.to_base64()
    }

    /// serializes the token
    pub fn serialized_size(&self) -> Result<usize, error::Token> {
        Ok(self.inner.serialized_size())
    }

    /// returns the internal representation of the token
    pub fn container(&self) -> &SerializedBiscuit<K> {
        &self.inner.container
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the key can be discarded right after
    /// calling this function
    pub fn append_with_key(
        &self,
        key: &K,
        block_builder: BlockBuilder,
    ) -> Result<Self, error::Token> {
        self.inner
            .append_with_key(key, block_builder)
            .map(|inner| UnverifiedBiscuit { inner })
    }

    /// returns the list of context elements of each block
    ///
    /// the context is a free form text field in which application specific data
    /// can be stored
    pub fn context(&self) -> Vec<Option<String>> {
        self.inner.context()
    }

    /// returns an (optional) root key identifier. It provides a hint for public key selection during verification
    pub fn root_key_id(&self) -> Option<u32> {
        self.inner.root_key_id()
    }

    /// returns a list of revocation identifiers for each block, in order
    ///
    /// revocation identifiers are unique: tokens generated separately with
    /// the same contents will have different revocation ids
    pub fn revocation_identifiers(&self) -> Vec<Vec<u8>> {
        self.inner.revocation_identifiers()
    }

    /// returns a list of external key for each block, in order
    ///
    /// Blocks carrying an external public key are _third-party blocks_
    /// and their contents can be trusted as coming from the holder of
    /// the corresponding private key
    pub fn external_public_keys(&self) -> Vec<Option<K::PublicKey>> {
        self.inner.external_public_keys()
    }

    /// returns the number of blocks (at least 1)
    pub fn block_count(&self) -> usize {
        self.inner.block_count()
    }

    /// prints the content of a block as Datalog source code
    pub fn print_block_source(&self, index: usize) -> Result<String, error::Token> {
        self.inner.print_block_source(index)
    }

    /// gets the datalog version for a given block
    pub fn block_version(&self, index: usize) -> Result<u32, error::Token> {
        self.inner.block_version(index)
    }

    /// gets the list of symbols from a block
    pub fn block_symbols(&self, index: usize) -> Result<Vec<String>, error::Token> {
        self.inner.block_symbols(index)
    }

    /// gets the list of public keys from a block
    pub fn block_public_keys(&self, index: usize) -> Result<PublicKeys, error::Token> {
        self.inner.block_public_keys(index)
    }

    /// gets the list of public keys from a block
    pub fn block_external_key(&self, index: usize) -> Result<Option<K::PublicKey>, error::Token> {
        self.inner.block_external_key(index)
    }

    /// creates a sealed version of the token
    ///
    /// sealed tokens cannot be attenuated
    pub fn seal(&self) -> Result<Self, error::Token> {
        self.inner.seal().map(|inner| UnverifiedBiscuit { inner })
    }

    pub fn third_party_request(&self) -> Result<ThirdPartyRequest, error::Token> {
        self.inner.third_party_request()
    }

    /// adds a serialized third party block to the token
    ///
    /// the block's signature is checked against this token, but not its key: the token's
    /// signatures, including this block's, are checked by [UnverifiedBiscuit::verify]
    pub fn append_third_party(&self, slice: &[u8]) -> Result<Self, error::Token> {
        let next_key = K::new_with_rng(builder::Algorithm::Ed25519, &mut rand::rng());
        self.append_third_party_with_key(slice, next_key)
    }

    pub fn append_third_party_with_key(
        &self,
        slice: &[u8],
        next_key: K,
    ) -> Result<Self, error::Token> {
        let contents = schema::ThirdPartyBlockContents::decode(slice).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {e:?}"))
        })?;

        self.inner
            .append_third_party_with_key(None, contents, next_key)
            .map(|inner| UnverifiedBiscuit { inner })
    }

    pub fn append_third_party_base64<T>(&self, slice: T) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
    {
        let decoded = BASE64_URL_SAFE.decode(slice)?;
        self.append_third_party(&decoded)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Biscuit, BiscuitBuilder, BlockBuilder, PrivateKey};

    use super::UnverifiedBiscuit;

    fn assert_consistent(unverified: &UnverifiedBiscuit, biscuit: &Biscuit) {
        assert_eq!(unverified.to_vec().unwrap(), biscuit.to_vec().unwrap());
        assert_eq!(unverified.inner.blocks, biscuit.inner.blocks);
        assert_eq!(unverified.inner.symbols, biscuit.inner.symbols);
        assert_eq!(unverified.block_count(), biscuit.block_count());
        assert_eq!(unverified.context(), biscuit.context());
        assert_eq!(
            unverified.external_public_keys(),
            biscuit.external_public_keys()
        );
        for i in 0..biscuit.block_count() {
            assert_eq!(
                unverified.print_block_source(i),
                biscuit.print_block_source(i)
            );
            assert_eq!(unverified.block_version(i), biscuit.block_version(i));
            assert_eq!(unverified.block_symbols(i), biscuit.block_symbols(i));
            assert_eq!(
                unverified.block_public_keys(i),
                biscuit.block_public_keys(i)
            );
            assert_eq!(
                unverified.block_external_key(i),
                biscuit.block_external_key(i)
            );
        }
    }

    #[test]
    fn consistent_with_biscuit() {
        let root_key = PrivateKey::new();
        let external_key = PrivateKey::new();
        let trusted_key = PrivateKey::new();
        let biscuit = BiscuitBuilder::new()
            .fact("test(true)")
            .unwrap()
            .build(&root_key)
            .unwrap()
            .append(BlockBuilder::new().fact("test(false)").unwrap())
            .unwrap();
        let unverified = UnverifiedBiscuit::from(biscuit.to_vec().unwrap()).unwrap();
        assert_consistent(&unverified, &biscuit);

        // the third party block references its own public key table
        let response = biscuit
            .third_party_request()
            .unwrap()
            .create_block(
                &external_key,
                BlockBuilder::new()
                    .code(format!(
                        "third_party(true); check if test(true) trusting {}",
                        trusted_key.public()
                    ))
                    .unwrap(),
            )
            .unwrap();
        let next_key = PrivateKey::new();
        let biscuit = biscuit
            .append_third_party_with_key(external_key.public(), response.clone(), next_key.clone())
            .unwrap();
        let unverified = unverified
            .append_third_party_with_key(&response.serialize().unwrap(), next_key)
            .unwrap();
        assert_consistent(&unverified, &biscuit);

        let reparsed = UnverifiedBiscuit::from(biscuit.to_vec().unwrap()).unwrap();
        assert_consistent(&reparsed, &biscuit);
        assert_consistent(&unverified, &reparsed.verify(root_key.public()).unwrap());
    }

    #[test]
    fn third_party_signature_is_checked() {
        let root_key = PrivateKey::new();
        let external_key = PrivateKey::new();
        let token = BiscuitBuilder::new().build(&root_key).unwrap();
        let other_token = BiscuitBuilder::new().build(&root_key).unwrap();

        // a block created for another token cannot be appended
        let response = other_token
            .third_party_request()
            .unwrap()
            .create_block(&external_key, BlockBuilder::new())
            .unwrap();
        let unverified = UnverifiedBiscuit::from(token.to_vec().unwrap()).unwrap();

        assert!(unverified
            .append_third_party(&response.serialize().unwrap())
            .is_err());
        assert!(token
            .append_third_party(external_key.public(), response)
            .is_err());
    }
}
