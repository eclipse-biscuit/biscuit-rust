/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! main structures to interact with Biscuit tokens
use std::fmt::{self, Debug, Display, Formatter};
use std::rc::Rc;
use std::sync::Arc;

use base64::prelude::*;
use builder::{BiscuitBuilder, BlockBuilder};
use rand_core::{CryptoRng, Rng};

use self::public_keys::PublicKeys;
use super::datalog::SymbolTable;
use super::error;
use super::format::SerializedBiscuit;
use crate::crypto::{PrivateKey, PublicKey, SerializePrivateKey, Verify, Sign};
use authorizer::Authorizer;
use limits::DeserializationLimits;
use parsed::ParsedToken;

pub mod authorizer;
pub(crate) mod block;
pub mod limits;
pub mod builder;
pub mod builder_ext;
mod parsed;
pub mod public_keys;
pub(crate) mod third_party;
pub mod unverified;
pub use block::Block;
pub use third_party::*;

/// minimum supported version of the serialization format
pub const MIN_SCHEMA_VERSION: u32 = 3;
/// maximum supported version of the serialization format
pub const MAX_SCHEMA_VERSION: u32 = 6;
/// starting version for datalog 3.1 features (check all, bitwise operators, !=, …)
pub const DATALOG_3_1: u32 = 4;
/// starting version for 3rd party blocks (datalog 3.2)
pub const DATALOG_3_2: u32 = 5;
/// starting version for datalog 3.3 features (reject if, closures, array/map, null, external functions, …)
pub const DATALOG_3_3: u32 = 6;

/// some symbols are predefined and available in every implementation, to avoid
/// transmitting them with every token
pub fn default_symbol_table() -> SymbolTable {
    SymbolTable::new()
}

/// This structure represents a valid Biscuit token
///
/// It contains multiple `Block` elements, the associated symbol table,
/// and a serialized version of this data
///
/// ```rust
/// extern crate biscuit_auth as biscuit;
///
/// use biscuit::{PrivateKey, Biscuit, builder::*, builder_ext::*};
///
/// fn main() -> Result<(), biscuit::error::Token> {
///   let root = PrivateKey::new();
///
///   // first we define the authority block for global data,
///   // like access rights
///   // data from the authority block cannot be created in any other block
///   let token1 = Biscuit::builder()
///       .fact(fact("right", &[string("/a/file1.txt"), string("read")]))?
///
///       // facts and rules can also be parsed from a string
///       .fact("right(\"/a/file1.txt\", \"read\")")?
///       .build(&root)?;
///
///   // we can create a new block builder from that token
///   let builder2 = BlockBuilder::new()
///       .check_operation("read");
///
///   let token2 = token1.append(builder2)?;
///
///   Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct Biscuit<K: SerializePrivateKey = PrivateKey> {
    pub(crate) inner: ParsedToken<K>,
}

impl Biscuit {
    /// create the first block's builder
    ///
    /// call [`builder::BiscuitBuilder::build`] to create the token
    pub fn builder() -> BiscuitBuilder {
        BiscuitBuilder::new()
    }

    /// deserializes a token and validates the signature using the root public key
    pub fn from<T, KP>(slice: T, key_provider: KP) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider<Key = PublicKey>,
    {
        Biscuit::from_with_symbols(
            slice.as_ref(),
            key_provider,
            default_symbol_table(),
            &DeserializationLimits::allow_everything(),
        )
    }

    /// deserializes a token and validates the signature using the root public key
    pub fn from_base64<T, KP>(slice: T, key_provider: KP) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider<Key = PublicKey>,
    {
        Biscuit::from_base64_with_symbols(slice, key_provider, default_symbol_table())
    }

    /// deserializes a token and validates the signature using the root public key,
    /// rejecting it if it does not respect the limits
    pub fn from_with_limits<T, KP>(
        slice: T,
        key_provider: KP,
        limits: &DeserializationLimits,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider<Key = PublicKey>,
    {
        Biscuit::from_with_symbols(slice.as_ref(), key_provider, default_symbol_table(), limits)
    }

    /// deserializes a token from base64 and validates the signature using the root public key,
    /// rejecting it if it does not respect the limits
    pub fn from_base64_with_limits<T, KP>(
        slice: T,
        key_provider: KP,
        limits: &DeserializationLimits,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider<Key = PublicKey>,
    {
        limits::check_base64_size(slice.as_ref(), limits)?;
        let decoded = BASE64_URL_SAFE.decode(slice)?;
        Biscuit::from_with_limits(&decoded, key_provider, limits)
    }

    /// creates an authorizer from this token
    ///
    /// Such an authorizer can only be used for querying, since it will contain no authorization policy.
    pub fn authorizer(&self) -> Result<Authorizer, error::Token> {
        Authorizer::from_token(self)
    }
}

impl<K: SerializePrivateKey> Biscuit<K> {
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

    /// creates a sealed version of the token
    ///
    /// sealed tokens cannot be attenuated
    pub fn seal(&self) -> Result<Self, error::Token> {
        self.inner.seal().map(|inner| Biscuit { inner })
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the private key can be
    /// discarded right after calling this function
    pub fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        self.inner
            .append(block_builder)
            .map(|inner| Biscuit { inner })
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

    /// pretty printer for this token
    pub fn print(&self) -> String {
        format!("{}", &self)
    }

    /// prints the content of a block as Datalog source code
    pub fn print_block_source(&self, index: usize) -> Result<String, error::Token> {
        self.inner.print_block_source(index)
    }

    /// gets the datalog version for a given block
    pub fn block_version(&self, index: usize) -> Result<u32, error::Token> {
        self.inner.block_version(index)
    }

    /// creates a new token, using a provided CSPRNG
    ///
    /// the public part of the root key must be used for verification
    pub(crate) fn new_with_rng<RK: Sign, T: Rng + CryptoRng + ?Sized>(
        rng: &mut T,
        root_key_id: Option<u32>,
        root: &RK,
        symbols: SymbolTable,
        authority: Block,
    ) -> Result<Biscuit<K>, error::Token> {
        Self::new_with_key_pair(
            root_key_id,
            root,
            &K::new_with_rng(root.algorithm(), rng),
            symbols,
            authority,
        )
    }

    /// creates a new token, using provided keys (the root key, and the key used to sign the next
    /// block)
    ///
    /// the public part of the root keypair must be used for verification
    pub(crate) fn new_with_key_pair<RK: Sign>(
        root_key_id: Option<u32>,
        root_key: &RK,
        next_key: &K,
        symbols: SymbolTable,
        authority: Block,
    ) -> Result<Biscuit<K>, error::Token> {
        Ok(Biscuit {
            inner: ParsedToken::new(root_key_id, root_key, next_key, symbols, authority)?,
        })
    }

    /// deserializes a token and validates the signature using the root public key, with a custom symbol table
    fn from_with_symbols<KP>(
        slice: &[u8],
        key_provider: KP,
        symbols: SymbolTable,
        limits: &DeserializationLimits,
    ) -> Result<Self, error::Token>
    where
        KP: RootKeyProvider<Key = K::PublicKey>,
    {
        let container = SerializedBiscuit::from_slice_with_limits(slice, key_provider, limits)
            .map_err(error::Token::Format)?;

        Ok(Biscuit {
            inner: ParsedToken::from_container(container, symbols, limits)?,
        })
    }

    /// deserializes a token and validates the signature using the root public key, with a custom
    /// symbol table
    fn from_base64_with_symbols<T, KP>(
        slice: T,
        key_provider: KP,
        symbols: SymbolTable,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider<Key = K::PublicKey>,
    {
        let decoded = BASE64_URL_SAFE.decode(slice)?;
        Biscuit::from_with_symbols(
            &decoded,
            key_provider,
            symbols,
            &DeserializationLimits::allow_everything(),
        )
    }

    /// returns the internal representation of the token
    pub fn container(&self) -> &SerializedBiscuit<K> {
        &self.inner.container
    }

    /// adds a new block to the token, using the provided CSPRNG
    ///
    /// since the public key is integrated into the token, the key can be
    /// discarded right after calling this function
    pub fn append_with_key(
        &self,
        key: &K,
        block_builder: BlockBuilder,
    ) -> Result<Self, error::Token> {
        self.inner
            .append_with_key(key, block_builder)
            .map(|inner| Biscuit { inner })
    }

    pub fn third_party_request(&self) -> Result<ThirdPartyRequest, error::Token> {
        self.inner.third_party_request()
    }

    pub fn append_third_party(
        &self,
        external_key: K::PublicKey,
        response: ThirdPartyBlock,
    ) -> Result<Self, error::Token> {
        let next_key = K::new_with_rng(builder::Algorithm::Ed25519, &mut rand::rng());
        self.append_third_party_with_key(external_key, response, next_key)
    }

    pub fn append_third_party_with_key(
        &self,
        external_key: K::PublicKey,
        response: ThirdPartyBlock,
        next_key: K,
    ) -> Result<Self, error::Token> {
        self.inner
            .append_third_party_with_key(Some(&external_key), response.0, next_key)
            .map(|inner| Biscuit { inner })
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

    /// returns the number of blocks (at least 1)
    pub fn block_count(&self) -> usize {
        self.inner.block_count()
    }

    pub(crate) fn blocks(&self) -> impl Iterator<Item = &Block> {
        self.inner.blocks()
    }
}

impl<K> Debug for Biscuit<K>
where
    K: SerializePrivateKey + Debug,
    K::PublicKey: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Biscuit")
            .field("root_key_id", &self.inner.root_key_id())
            .field("authority", &self.inner.authority)
            .field("blocks", &self.inner.blocks)
            .field("symbols", &self.inner.symbols)
            .field("container", &self.inner.container)
            .finish()
    }
}

impl<K: SerializePrivateKey> Display for Biscuit<K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let symbols = &self.inner.symbols;
        let authority = print_block(symbols, &self.inner.authority);
        let blocks: Vec<_> = self
            .inner
            .blocks
            .iter()
            .map(|block| print_block(symbols, block))
            .collect();

        write!(f, "Biscuit {{\n    symbols: {:?}\n    public keys: {:?}\n    authority: {}\n    blocks: [\n        {}\n    ]\n}}",
        symbols.strings(),
        symbols.public_keys.keys.iter().map(|pk| format!("{}", pk)).collect::<Vec<_>>(),
        authority,
        blocks.join(",\n\t")
    )
    }
}

fn print_block(symbols: &SymbolTable, block: &Block) -> String {
    let facts: Vec<_> = block.facts.iter().map(|f| symbols.print_fact(f)).collect();
    let rules: Vec<_> = block.rules.iter().map(|r| symbols.print_rule(r)).collect();
    let checks: Vec<_> = block
        .checks
        .iter()
        .map(|r| symbols.print_check(r))
        .collect();

    let facts = if facts.is_empty() {
        String::new()
    } else {
        format!(
            "\n                {}\n            ",
            facts.join(",\n                ")
        )
    };
    let rules = if rules.is_empty() {
        String::new()
    } else {
        format!(
            "\n                {}\n            ",
            rules.join(",\n                ")
        )
    };
    let checks = if checks.is_empty() {
        String::new()
    } else {
        format!(
            "\n                {}\n            ",
            checks.join(",\n                ")
        )
    };

    format!(
        "Block {{\n            symbols: {:?}\n            version: {}\n            context: \"{}\"\n            external key: {}\n            public keys: {:?}\n            scopes: {:?}\n            facts: [{}]\n            rules: [{}]\n            checks: [{}]\n        }}",
        block.symbols.strings(),
        block.version,
        block.context.as_deref().unwrap_or(""),
        block.external_key.as_ref().map(|k| hex::encode(k.to_bytes())).unwrap_or_default(),
        block.public_keys.keys.iter().map(|k| format!("{}", k)).collect::<Vec<_>>(),
        block.scopes,
        facts,
        rules,
        checks,
    )
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Scope {
    Authority,
    Previous,
    // index of the public key in the symbol table
    PublicKey(u64),
}

/// Chooses a root public key to verify the token
///
/// In case of key rotation, it is possible to add a root key id
/// to the token with [`BiscuitBuilder::root_key_id`]. This
/// value will be passed to the implementor of `RootKeyProvider`
/// to choose which key will be used.
pub trait RootKeyProvider {
    type Key: Verify;

    fn choose(&self, key_id: Option<u32>) -> Result<Self::Key, error::Format>;
}

impl<K: Verify> RootKeyProvider for Box<dyn RootKeyProvider<Key = K>> {
    type Key = K;

    fn choose(&self, key_id: Option<u32>) -> Result<K, error::Format> {
        self.as_ref().choose(key_id)
    }
}

impl<K: Verify> RootKeyProvider for Rc<dyn RootKeyProvider<Key = K>> {
    type Key = K;

    fn choose(&self, key_id: Option<u32>) -> Result<K, error::Format> {
        self.as_ref().choose(key_id)
    }
}

impl<K: Verify> RootKeyProvider for Arc<dyn RootKeyProvider<Key = K>> {
    type Key = K;

    fn choose(&self, key_id: Option<u32>) -> Result<K, error::Format> {
        self.as_ref().choose(key_id)
    }
}

impl RootKeyProvider for PublicKey {
    type Key = PublicKey;

    fn choose(&self, _: Option<u32>) -> Result<PublicKey, error::Format> {
        Ok(*self)
    }
}

impl RootKeyProvider for &PublicKey {
    type Key = PublicKey;

    fn choose(&self, _: Option<u32>) -> Result<PublicKey, error::Format> {
        Ok(**self)
    }
}

impl<F: Fn(Option<u32>) -> Result<K, error::Format>, K: Verify> RootKeyProvider for F {
    type Key = K;

    fn choose(&self, root_key_id: Option<u32>) -> Result<K, error::Format> {
        self(root_key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{check, fact, pred, rule, string, var};
    use super::builder_ext::BuilderExt;
    use super::*;
    use crate::builder::CheckKind;
    use crate::crypto::PrivateKey;
    use crate::{error::*, AuthorizerLimits, UnverifiedBiscuit};
    use builder::AuthorizerBuilder;
    use builder_ext::AuthorizerExt;
    use rand::prelude::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn basic() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let serialized1 = {
            let biscuit1 = Biscuit::builder()
                .fact("right(\"file1\", \"read\")")
                .unwrap()
                .fact("right(\"file2\", \"read\")")
                .unwrap()
                .fact("right(\"file1\", \"write\")")
                .unwrap()
                .build_with_rng(&root, default_symbol_table(), &mut rng)
                .unwrap();

            println!("biscuit1 (authority): {biscuit1}");

            biscuit1.to_vec().unwrap()
        };

        //println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));
        println!("generated biscuit token: {} bytes", serialized1.len());
        //panic!();

        /*
        for i in 0..9 {
            let biscuit1_deser = Biscuit::from(&serialized1, root.public).unwrap();

            // new check: can only have read access1
            let mut block2 = BlockBuilder::new();

            block2.add_check(&rule(
                "check1",
                &[var(0)],
                &[
                    pred("resource", &[var(0)]),
                    pred("operation", &[string("read")]),
                    pred("right", &[var(0), string("read")]),
                ],
            ));

            let keypair2 = PrivateKey::new_with_rng(&mut rng);
            let biscuit2 = biscuit1_deser.append(&keypair2, block2.to_block()).unwrap();

            println!("biscuit2 (1 check): {}", biscuit2);

            serialized1 = biscuit2.to_vec().unwrap();

        }
        println!("generated biscuit token 2: {} bytes", serialized1.len());
        panic!();
        */

        let serialized2 = {
            let biscuit1_deser = Biscuit::from(&serialized1, root.public()).unwrap();

            // new check: can only have read access1
            let block2 = BlockBuilder::new()
                .check(rule(
                    "check1",
                    &[var("resource")],
                    &[
                        pred("resource", &[var("resource")]),
                        pred("operation", &[string("read")]),
                        pred("right", &[var("resource"), string("read")]),
                    ],
                ))
                .unwrap();

            let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
            let biscuit2 = biscuit1_deser
                .append_with_key(&keypair2, block2)
                .unwrap();

            println!("biscuit2 (1 check): {biscuit2}");

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let serialized3 = {
            let biscuit2_deser = Biscuit::from(&serialized2, root.public()).unwrap();

            // new check: can only access file1
            let block3 = BlockBuilder::new()
                .check(rule(
                    "check2",
                    &[string("file1")],
                    &[pred("resource", &[string("file1")])],
                ))
                .unwrap();

            let keypair3 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
            let biscuit3 = biscuit2_deser
                .append_with_key(&keypair3, block3)
                .unwrap();

            biscuit3.to_vec().unwrap()
        };

        //println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));
        println!("generated biscuit token 3: {} bytes", serialized3.len());
        //panic!();

        let final_token = Biscuit::from(&serialized3, root.public()).unwrap();
        println!("final token:\n{final_token}");
        {
            let mut builder = AuthorizerBuilder::new();

            let mut facts = vec![
                fact("resource", &[string("file1")]),
                fact("operation", &[string("read")]),
            ];

            for fact in facts.drain(..) {
                builder = builder.fact(fact).unwrap();
            }

            //println!("final token: {:#?}", final_token);

            let mut authorizer = builder.allow_all().build(&final_token).unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res1: {res:?}");
            res.unwrap();
        }

        {
            let mut builder = AuthorizerBuilder::new();

            let mut facts = vec![
                fact("resource", &[string("file2")]),
                fact("operation", &[string("write")]),
            ];

            for fact in facts.drain(..) {
                builder = builder.fact(fact).unwrap();
            }
            builder = builder.allow_all();

            let mut authorizer = builder.build(&final_token).unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res2: {res:#?}");
            assert_eq!(res,
              Err(Token::FailedLogic(Logic::Unauthorized {
                  policy: MatchedPolicy::Allow(0),
                  checks: vec![
                FailedCheck::Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: String::from("check if resource($resource), operation(\"read\"), right($resource, \"read\")") }),
                FailedCheck::Block(FailedBlockCheck { block_id: 2, check_id: 0, rule: String::from("check if resource(\"file1\")") })
              ]
              })));
        }
    }

    #[test]
    fn folders() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .right("/folder1/file1", "read")
            .right("/folder1/file1", "write")
            .right("/folder1/file2", "read")
            .right("/folder1/file2", "write")
            .right("/folder2/file3", "read")
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let block2 = BlockBuilder::new()
            .check_resource_prefix("/folder1/")
            .check_right("read")
            .unwrap();

        let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_key(&keypair2, block2).unwrap();

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"/folder1/file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .allow_all()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res1: {res:?}");
            println!("authorizer:\n{}", authorizer.print_world());
            res.unwrap();
        }

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"/folder2/file3\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .allow_all()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res2: {res:?}");
            assert_eq!(
                res,
                Err(Token::FailedLogic(Logic::Unauthorized {
                    policy: MatchedPolicy::Allow(0),
                    checks: vec![FailedCheck::Block(FailedBlockCheck {
                        block_id: 1,
                        check_id: 0,
                        rule: String::from(
                            "check if resource($resource), $resource.starts_with(\"/folder1/\")"
                        )
                    }),]
                }))
            );
        }

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"/folder2/file1\")")
                .unwrap()
                .fact("operation(\"write\")")
                .unwrap()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize();
            println!("res3: {res:?}");
            assert_eq!(res,
              Err(Token::FailedLogic(Logic::NoMatchingPolicy {
                  checks: vec![
                FailedCheck::Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: String::from("check if resource($resource), $resource.starts_with(\"/folder1/\")") }),
                FailedCheck::Block(FailedBlockCheck { block_id: 1, check_id: 1, rule: String::from("check if resource($resource_name), operation(\"read\"), right($resource_name, \"read\")") }),
              ]})));
        }
    }

    #[test]
    fn constraints() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .right("file1", "read")
            .right("file2", "read")
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let block2 = BlockBuilder::new()
            .check_expiration_date(SystemTime::now() + Duration::from_secs(30))
            .fact("key(1234)")
            .unwrap();

        let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_key(&keypair2, block2).unwrap();

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .time()
                .allow_all()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res1: {res:?}");
            res.unwrap();
        }

        {
            println!("biscuit2: {biscuit2}");
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .time()
                .allow_all()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res3: {res:?}");

            // error message should be like this:
            //"authorizer check 0 failed: check if revocation_id($0), $0 not in [2, 1234, 1, 5, 0]"
            assert!(res.is_ok());
        }
    }

    #[test]
    fn sealed_token() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit1 = Biscuit::builder()
            .right("/folder1/file1", "read")
            .right("/folder1/file1", "write")
            .right("/folder1/file2", "read")
            .right("/folder1/file2", "write")
            .right("/folder2/file3", "read")
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let block2 = BlockBuilder::new()
            .check_resource_prefix("/folder1/")
            .check_right("read")
            .unwrap();

        let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_key(&keypair2, block2).unwrap();

        //println!("biscuit2:\n{:#?}", biscuit2);
        //panic!();
        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"/folder1/file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .allow_all()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res1: {res:?}");
            res.unwrap();
        }

        let _serialized = biscuit2.to_vec().unwrap();
        //println!("biscuit2 serialized ({} bytes):\n{}", serialized.len(), serialized.to_hex(16));

        let sealed = biscuit2.seal().unwrap().to_vec().unwrap();
        //println!("biscuit2 sealed ({} bytes):\n{}", sealed.len(), sealed.to_hex(16));

        let biscuit3 = Biscuit::from(sealed, root.public()).unwrap();

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"/folder1/file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .allow_all()
                .build(&biscuit3)
                .unwrap();

            let res = authorizer.authorize();
            println!("res1: {res:?}");
            res.unwrap();
        }
    }

    #[test]
    fn verif_no_blocks() {
        use crate::token::builder::*;

        let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .fact(fact("right", &[string("file1"), string("read")]))
            .unwrap()
            .fact(fact("right", &[string("file2"), string("read")]))
            .unwrap()
            .fact(fact("right", &[string("file1"), string("write")]))
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();
        println!("{biscuit1}");

        let mut authorizer = AuthorizerBuilder::new()
            .check(rule(
                "right",
                &[string("right")],
                &[pred("right", &[string("file2"), string("write")])],
            ))
            .unwrap()
            .build(&biscuit1)
            .unwrap();

        //assert!(v.verify().is_err());
        let res = authorizer.authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        });
        println!("res: {res:?}");
        assert_eq!(
            res,
            Err(Token::FailedLogic(Logic::NoMatchingPolicy {
                checks: vec![FailedCheck::Authorizer(FailedAuthorizerCheck {
                    check_id: 0,
                    rule: String::from("check if right(\"file2\", \"write\")")
                }),]
            }))
        );
    }

    #[test]
    fn authorizer_queries() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .right("file1", "read")
            .right("file2", "read")
            .fact("key(0000)")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let block2 = BlockBuilder::new()
            .check_expiration_date(SystemTime::now() + Duration::from_secs(30))
            .fact("key(1234)")
            .unwrap();

        let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_key(&keypair2, block2).unwrap();

        let block3 = BlockBuilder::new()
            .check_expiration_date(SystemTime::now() + Duration::from_secs(10))
            .fact("key(5678)")
            .unwrap();

        let keypair3 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit3 = biscuit2.append_with_key(&keypair3, block3).unwrap();
        {
            println!("biscuit3: {biscuit3}");

            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .time()
                .build(&biscuit3)
                .unwrap();

            // test that cloning correctly embeds the first block's facts
            let mut other_authorizer = authorizer.clone();

            let authorization_res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("authorization result: {authorization_res:?}");

            println!("world:\n{}", authorizer.print_world());
            let res2: Result<Vec<builder::Fact>, crate::error::Token> = authorizer
                .query_all_with_limits(
                    "key_verif($id) <- key($id)",
                    AuthorizerLimits {
                        max_time: Duration::from_secs(10),
                        ..Default::default()
                    },
                );

            println!("res2: {res2:?}");
            let mut res2 = res2
                .unwrap()
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>();
            res2.sort();
            assert_eq!(
                res2,
                vec![
                    "key_verif(0)".to_string(),
                    "key_verif(1234)".to_string(),
                    "key_verif(5678)".to_string(),
                ]
            );

            let res1: Result<Vec<builder::Fact>, crate::error::Token> = other_authorizer
                .query_with_limits(
                    "key_verif($id) <- key($id)",
                    AuthorizerLimits {
                        max_time: Duration::from_secs(10),
                        ..Default::default()
                    },
                );
            println!("res1: {res1:?}");
            assert_eq!(
                res1.unwrap()
                    .into_iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>(),
                vec!["key_verif(0)".to_string()]
            );
        }
    }

    #[test]
    fn check_head_name() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .check(check(
                &[pred("resource", &[string("hello")])],
                CheckKind::One,
            ))
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        // new check: can only have read access1
        let block2 = BlockBuilder::new()
            .fact(fact("check1", &[string("test")]))
            .unwrap();

        let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_key(&keypair2, block2).unwrap();

        println!("biscuit2: {biscuit2}");

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("resource(\"file1\")")
                .unwrap()
                .fact("operation(\"read\")")
                .unwrap()
                .time()
                .build(&biscuit2)
                .unwrap();

            println!("world:\n{}", authorizer.print_world());
            println!("symbols: {:?}", authorizer.symbols);

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res1: {res:?}");

            assert_eq!(
                res,
                Err(Token::FailedLogic(Logic::NoMatchingPolicy {
                    checks: vec![FailedCheck::Block(FailedBlockCheck {
                        block_id: 0,
                        check_id: 0,
                        rule: String::from("check if resource(\"hello\")"),
                    }),]
                }))
            );
        }
    }

    /*
    #[test]
    fn check_requires_fact_in_future_block() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(&mut rng);

        let mut builder = Biscuit::builder(&root);

        builder
            .add_authority_check(check(&[pred("name", &[var("name")])]))
            .unwrap();

        let biscuit1 = builder.build_with_rng(&mut rng).unwrap();

        println!("biscuit1 (authority): {}", biscuit1);
        let mut authorizer1 = biscuit1.verify().unwrap();
        authorizer1.allow().unwrap();
        let res1 = authorizer1.verify();
        println!("res1: {:?}", res1);
        assert_eq!(
            res1,
            Err(Token::FailedLogic(Logic::FailedChecks(vec![
                FailedCheck::Block(FailedBlockCheck {
                    block_id: 0,
                    check_id: 0,
                    rule: String::from("check if name($name)"),
                }),
            ])))
        );

        let mut block2 = BlockBuilder::new();
        block2.add_fact(fact("name", &[string("test")])).unwrap();

        let keypair2 = PrivateKey::new_with_rng(&mut rng);
        let biscuit2 = biscuit1
            .append_with_keypair(&keypair2, block2)
            .unwrap();

        println!("biscuit2 (with name fact): {}", biscuit2);
        let mut authorizer2 = biscuit2.verify().unwrap();
        authorizer2.allow().unwrap();
        let res2 = authorizer2.verify();
        assert_eq!(res2, Ok(0));
    }*/

    #[test]
    fn bytes_constraints() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .fact("bytes(hex:0102AB)")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let block2 = BlockBuilder::new()
            .rule("has_bytes($0) <- bytes($0), { hex:00000000, hex:0102AB }.contains($0)")
            .unwrap();
        let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_key(&keypair2, block2).unwrap();

        let mut authorizer = AuthorizerBuilder::new()
            .check("check if bytes($0), { hex:00000000, hex:0102AB }.contains($0)")
            .unwrap()
            .allow_all()
            .set_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .build(&biscuit2)
            .unwrap();

        let res = authorizer.authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        });
        println!("res1: {res:?}");
        res.unwrap();

        let res: Vec<(Vec<u8>,)> = authorizer
            .query_with_limits(
                "data($0) <- bytes($0)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        println!("query result: {res:x?}");
        println!("query result: {:?}", res[0]);
    }

    #[test]
    fn block1_generates_authority_or_ambient() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let serialized1 = {
            let biscuit1 = Biscuit::builder()
                .fact("right(\"/folder1/file1\", \"read\")")
                .unwrap()
                .fact("right(\"/folder1/file1\", \"write\")")
                .unwrap()
                .fact("right(\"/folder2/file1\", \"read\")")
                .unwrap()
                .check("check if operation(\"read\")")
                .unwrap()
                .build_with_rng(&root, default_symbol_table(), &mut rng)
                .unwrap();

            println!("biscuit1 (authority): {biscuit1}");

            biscuit1.to_vec().unwrap()
        };

        //println!("generated biscuit token: {} bytes:\n{}", serialized1.len(), serialized1.to_hex(16));
        println!("generated biscuit token: {} bytes", serialized1.len());
        //panic!();

        let serialized2 = {
            let biscuit1_deser = Biscuit::from(&serialized1, |_| Ok(root.public())).unwrap();

            // new check: can only have read access1
            let  block2 = BlockBuilder::new()

            // Bypass `check if operation("read")` from authority block
                .rule("operation(\"read\") <- operation($any)")
                .unwrap()

            // Bypass `check if resource($file), $file.starts_with("/folder1/")` from block #1
                .rule("resource(\"/folder1/\") <- resource($any)")
                .unwrap()

            // Add missing rights
          .rule("right($file, $right) <- right($any1, $any2), resource($file), operation($right)")
                .unwrap();

            let keypair2 = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
            let biscuit2 = biscuit1_deser
                .append_with_key(&keypair2, block2)
                .unwrap();

            println!("biscuit2 (1 check): {biscuit2}");

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let final_token = Biscuit::from(&serialized2, root.public()).unwrap();
        println!("final token:\n{final_token}");

        let mut authorizer = AuthorizerBuilder::new()
            .fact("resource(\"/folder2/file1\")")
            .unwrap()
            .fact("operation(\"write\")")
            .unwrap()
            .policy("allow if resource($file), operation($op), right($file, $op)")
            .unwrap()
            .deny_all()
            .build(&final_token)
            .unwrap();

        let res = authorizer.authorize_with_limits(crate::token::authorizer::AuthorizerLimits {
            max_time: Duration::from_secs(1),
            ..Default::default()
        });
        println!("res1: {res:?}");
        println!("authorizer:\n{}", authorizer.print_world());

        assert!(res.is_err());
    }

    #[test]
    fn check_all() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .check("check if fact($v), $v < 1")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let biscuit2 = Biscuit::builder()
            .check("check all fact($v), $v < 1")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit2 (authority): {biscuit2}");

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("fact(0)")
                .unwrap()
                .fact("fact(1)")
                .unwrap()
                //println!("final token: {:#?}", final_token);
                .allow_all()
                .build(&biscuit1)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res1: {res:?}");
            res.unwrap();
        }

        {
            let mut authorizer = AuthorizerBuilder::new()
                .fact("fact(0)")
                .unwrap()
                .fact("fact(1)")
                .unwrap()
                //println!("final token: {:#?}", final_token);
                .allow_all()
                .build(&biscuit2)
                .unwrap();

            let res = authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            });
            println!("res2: {res:?}");

            assert_eq!(
                res,
                Err(Token::FailedLogic(Logic::Unauthorized {
                    policy: MatchedPolicy::Allow(0),
                    checks: vec![FailedCheck::Block(FailedBlockCheck {
                        block_id: 0,
                        check_id: 0,
                        rule: String::from("check all fact($v), $v < 1"),
                    }),]
                }))
            );
        }
    }

    // tests that the authority block signature version 1 works
    #[test]
    fn authority_signature_v1() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let authority_block = Block {
            symbols: default_symbol_table(),
            facts: vec![],
            rules: vec![],
            checks: vec![],
            context: None,
            version: MIN_SCHEMA_VERSION,
            external_key: None,
            public_keys: PublicKeys::new(),
            scopes: vec![],
        };

        let next_keypair = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let token =
            SerializedBiscuit::new_inner(None, &root, &next_keypair, &authority_block, 1).unwrap();
        let serialized = token.to_vec().unwrap();

        let _ = Biscuit::from(&serialized, root.public()).unwrap();
    }

    #[test]
    fn verified_unverified_consistency() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = PrivateKey::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit1 = Biscuit::builder()
            .fact("right(\"file1\", \"read\")")
            .unwrap()
            .fact("right(\"file2\", \"read\")")
            .unwrap()
            .fact("right(\"file1\", \"write\")")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {biscuit1}");

        let serialized = biscuit1.to_vec().unwrap();

        let parsed = UnverifiedBiscuit::from(serialized).unwrap();

        for i in 0..parsed.block_count() {
            assert_eq!(parsed.print_block_source(i), biscuit1.print_block_source(i));
            assert_eq!(parsed.block_version(i), biscuit1.block_version(i));
        }
    }

    // indexing one past the last block used to panic instead of returning an error
    #[test]
    fn out_of_bounds_block_index() {
        let root = PrivateKey::new();
        let token = Biscuit::builder()
            .build(&root)
            .unwrap()
            .append(BlockBuilder::new())
            .unwrap();
        let unverified = UnverifiedBiscuit::from(token.to_vec().unwrap()).unwrap();
        let index = token.block_count();

        let expected = error::Token::Format(error::Format::InvalidBlockId(index));
        assert_eq!(token.print_block_source(index).unwrap_err(), expected);
        assert_eq!(token.block_version(index).unwrap_err(), expected);
        assert_eq!(token.block_symbols(index).unwrap_err(), expected);
        assert_eq!(unverified.print_block_source(index).unwrap_err(), expected);
        assert_eq!(unverified.block_version(index).unwrap_err(), expected);
    }
}
