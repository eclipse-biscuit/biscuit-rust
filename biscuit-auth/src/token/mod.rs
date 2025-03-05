//! main structures to interact with Biscuit tokens
use std::fmt::Display;
use std::iter::once;

use builder::{BiscuitBuilder, BlockBuilder};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

use self::public_keys::PublicKeys;
use super::crypto::{KeyPair, PublicKey, Signature};
use super::datalog::SymbolTable;
use super::error;
use super::format::SerializedBiscuit;
use crate::crypto::{self};
use crate::format::convert::proto_block_to_token_block;
use crate::format::schema::{self, ThirdPartyBlockContents};
use crate::format::{ThirdPartyVerificationMode, THIRD_PARTY_SIGNATURE_VERSION};
use authorizer::Authorizer;

pub mod authorizer;
pub(crate) mod block;
pub mod builder;
pub mod builder_ext;
pub(crate) mod public_keys;
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
/// use biscuit::{KeyPair, Biscuit, builder::*, builder_ext::*};
///
/// fn main() -> Result<(), biscuit::error::Token> {
///   let root = KeyPair::new();
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
#[derive(Clone, Debug)]
pub struct Biscuit {
    pub(crate) root_key_id: Option<u32>,
    pub(crate) authority: schema::Block,
    pub(crate) blocks: Vec<schema::Block>,
    pub(crate) symbols: SymbolTable,
    pub(crate) container: SerializedBiscuit,
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
        KP: RootKeyProvider,
    {
        Biscuit::from_with_symbols(slice.as_ref(), key_provider, default_symbol_table())
    }

    /// deserializes a token and validates the signature using the root public key
    pub fn from_base64<T, KP>(slice: T, key_provider: KP) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider,
    {
        Biscuit::from_base64_with_symbols(slice, key_provider, default_symbol_table())
    }

    /// deserializes a token and validates the signature using the root public key
    ///
    /// This allows the deprecated 3rd party block format
    pub fn unsafe_deprecated_deserialize<T, KP>(
        slice: T,
        key_provider: KP,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider,
    {
        let container = SerializedBiscuit::unsafe_from_slice(slice.as_ref(), key_provider)
            .map_err(error::Token::Format)?;

        Biscuit::from_serialized_container(container, default_symbol_table())
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

    /// serializes the token
    pub fn serialized_size(&self) -> Result<usize, error::Token> {
        Ok(self.container.serialized_size())
    }

    /// creates a sealed version of the token
    ///
    /// sealed tokens cannot be attenuated
    pub fn seal(&self) -> Result<Biscuit, error::Token> {
        let container = self.container.seal()?;

        let mut token = self.clone();
        token.container = container;

        Ok(token)
    }

    /// creates an authorizer from this token
    pub fn authorizer(&self) -> Result<Authorizer, error::Token> {
        Authorizer::from_token(self)
    }

    /// adds a new block to the token
    ///
    /// since the public key is integrated into the token, the keypair can be
    /// discarded right after calling this function
    pub fn append(&self, block_builder: BlockBuilder) -> Result<Self, error::Token> {
        let keypair = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rand::rngs::OsRng);
        self.append_with_keypair(&keypair, block_builder)
    }

    /// returns the list of context elements of each block
    ///
    /// the context is a free form text field in which application specific data
    /// can be stored
    pub fn context(&self) -> Vec<Option<String>> {
        let mut res = vec![self.authority.context.clone()];

        for b in self.blocks.iter() {
            res.push(b.context.clone());
        }

        res
    }

    /// returns an (optional) root key identifier. It provides a hint for public key selection during verification
    pub fn root_key_id(&self) -> Option<u32> {
        self.root_key_id
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

    /// pretty printer for this token
    pub fn print(&self) -> String {
        format!("{}", &self)
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

    /// creates a new token, using a provided CSPRNG
    ///
    /// the public part of the root keypair must be used for verification
    pub(crate) fn new_with_rng<T: RngCore + CryptoRng>(
        rng: &mut T,
        root_key_id: Option<u32>,
        root: &KeyPair,
        symbols: SymbolTable,
        authority: Block,
    ) -> Result<Biscuit, error::Token> {
        Self::new_with_key_pair(
            root_key_id,
            root,
            &KeyPair::new_with_rng(builder::Algorithm::Ed25519, rng),
            symbols,
            authority,
        )
    }

    /// creates a new token, using provided keypairs (the root keypair, and the keypair used to sign the next block)
    ///
    /// the public part of the root keypair must be used for verification
    pub(crate) fn new_with_key_pair(
        root_key_id: Option<u32>,
        root: &KeyPair,
        next_keypair: &KeyPair,
        mut symbols: SymbolTable,
        authority: Block,
    ) -> Result<Biscuit, error::Token> {
        if !symbols.is_disjoint(&authority.symbols) {
            return Err(error::Token::Format(error::Format::SymbolTableOverlap));
        }

        symbols.extend(&authority.symbols)?;

        let blocks = vec![];

        let container = SerializedBiscuit::new(root_key_id, root, next_keypair, &authority)?;

        symbols.public_keys.extend(&authority.public_keys)?;

        let authority = schema::Block::decode(&container.authority.data[..]).map_err(|e| {
            error::Token::Format(error::Format::BlockDeserializationError(format!(
                "error deserializing block: {:?}",
                e
            )))
        })?;

        Ok(Biscuit {
            root_key_id,
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// deserializes a token and validates the signature using the root public key, with a custom symbol table
    fn from_with_symbols<KP>(
        slice: &[u8],
        key_provider: KP,
        symbols: SymbolTable,
    ) -> Result<Self, error::Token>
    where
        KP: RootKeyProvider,
    {
        let container =
            SerializedBiscuit::from_slice(slice, key_provider).map_err(error::Token::Format)?;

        Biscuit::from_serialized_container(container, symbols)
    }

    fn from_serialized_container(
        container: SerializedBiscuit,
        mut symbols: SymbolTable,
    ) -> Result<Self, error::Token> {
        let (authority, blocks) = container.extract_blocks(&mut symbols)?;

        let root_key_id = container.root_key_id;

        Ok(Biscuit {
            root_key_id,
            authority,
            blocks,
            symbols,
            container,
        })
    }

    /// deserializes a token and validates the signature using the root public key, with a custom symbol table
    fn from_base64_with_symbols<T, KP>(
        slice: T,
        key_provider: KP,
        symbols: SymbolTable,
    ) -> Result<Self, error::Token>
    where
        T: AsRef<[u8]>,
        KP: RootKeyProvider,
    {
        let decoded = base64::decode_config(slice, base64::URL_SAFE)?;
        Biscuit::from_with_symbols(&decoded, key_provider, symbols)
    }

    /// returns the internal representation of the token
    pub fn container(&self) -> &SerializedBiscuit {
        &self.container
    }

    /// adds a new block to the token, using the provided CSPRNG
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

        Ok(Biscuit {
            root_key_id: self.root_key_id,
            authority,
            blocks,
            symbols,
            container,
        })
    }

    pub fn third_party_request(&self) -> Result<ThirdPartyRequest, error::Token> {
        ThirdPartyRequest::from_container(&self.container)
    }

    pub fn append_third_party(
        &self,
        external_key: PublicKey,
        response: ThirdPartyBlock,
    ) -> Result<Self, error::Token> {
        let next_keypair =
            KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rand::rngs::OsRng);

        self.append_third_party_with_keypair(external_key, response, next_keypair)
    }
    pub fn append_third_party_with_keypair(
        &self,
        external_key: PublicKey,
        response: ThirdPartyBlock,
        next_keypair: KeyPair,
    ) -> Result<Self, error::Token> {
        let ThirdPartyBlockContents {
            payload,
            external_signature,
        } = response.0;

        let provided_key = PublicKey::from_proto(&external_signature.public_key)?;
        if external_key != provided_key {
            return Err(error::Token::Format(error::Format::DeserializationError(
                format!(
                    "deserialization error: unexpected key {}",
                    provided_key.print()
                ),
            )));
        }

        let signature = Signature::from_vec(external_signature.signature);

        let previous_key = self
            .container
            .blocks
            .last()
            .unwrap_or(&self.container.authority)
            .next_key;

        let external_signature = crypto::ExternalSignature {
            public_key: external_key,
            signature,
        };
        crypto::verify_external_signature(
            &payload,
            &previous_key,
            &self
                .container
                .blocks
                .last()
                .unwrap_or(&self.container.authority)
                .signature,
            &external_signature,
            THIRD_PARTY_SIGNATURE_VERSION,
            ThirdPartyVerificationMode::PreviousSignatureHashing,
        )?;

        let block = schema::Block::decode(&payload[..]).map_err(|e| {
            error::Token::Format(error::Format::DeserializationError(format!(
                "deserialization error: {:?}",
                e
            )))
        })?;

        let symbols = self.symbols.clone();
        let mut blocks = self.blocks.clone();

        let container =
            self.container
                .append_serialized(&next_keypair, payload, Some(external_signature))?;

        blocks.push(block);

        Ok(Biscuit {
            root_key_id: self.root_key_id,
            authority: self.authority.clone(),
            blocks,
            symbols,
            container,
        })
    }

    /// gets the list of symbols from a block
    pub fn block_symbols(&self, index: usize) -> Result<Vec<String>, error::Token> {
        let block = if index == 0 {
            &self.authority
        } else {
            match self.blocks.get(index - 1) {
                None => return Err(error::Token::Format(error::Format::InvalidBlockId(index))),
                Some(block) => block,
            }
        };

        Ok(block.symbols.clone())
    }

    /// gets the list of public keys from a block
    pub fn block_public_keys(&self, index: usize) -> Result<PublicKeys, error::Token> {
        let block = if index == 0 {
            &self.authority
        } else {
            match self.blocks.get(index - 1) {
                None => return Err(error::Token::Format(error::Format::InvalidBlockId(index))),
                Some(block) => block,
            }
        };

        let mut public_keys = PublicKeys::new();

        for pk in &block.public_keys {
            public_keys.insert(&PublicKey::from_proto(pk)?);
        }
        Ok(public_keys)
    }

    /// gets the list of public keys from a block
    pub fn block_external_key(&self, index: usize) -> Result<Option<PublicKey>, error::Token> {
        let block = if index == 0 {
            &self.container.authority
        } else {
            match self.container.blocks.get(index - 1) {
                None => return Err(error::Token::Format(error::Format::InvalidBlockId(index))),
                Some(block) => block,
            }
        };

        Ok(block
            .external_signature
            .as_ref()
            .map(|signature| signature.public_key))
    }

    /// returns the number of blocks (at least 1)
    pub fn block_count(&self) -> usize {
        1 + self.blocks.len()
    }

    pub(crate) fn block(&self, index: usize) -> Result<Block, error::Token> {
        let block = if index == 0 {
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

        Ok(block)
    }

    pub(crate) fn blocks(&self) -> impl Iterator<Item = Result<Block, error::Token>> + use<'_> {
        once(
            proto_block_to_token_block(
                &self.authority,
                self.container
                    .authority
                    .external_signature
                    .as_ref()
                    .map(|ex| ex.public_key),
            )
            .map_err(error::Token::Format),
        )
        .chain(self.blocks.iter().zip(self.container.blocks.iter()).map(
            |(block, container)| {
                proto_block_to_token_block(
                    block,
                    container
                        .external_signature
                        .as_ref()
                        .map(|ex| ex.public_key),
                )
                .map_err(error::Token::Format)
            },
        ))
    }
}

impl Display for Biscuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let authority = self
            .block(0)
            .as_ref()
            .map(|block| print_block(&self.symbols, block))
            .unwrap_or_else(|_| String::new());
        let blocks: Vec<_> = (1..self.block_count())
            .map(|i| {
                self.block(i)
                    .as_ref()
                    .map(|block| print_block(&self.symbols, block))
                    .unwrap_or_else(|_| String::new())
            })
            .collect();

        write!(f, "Biscuit {{\n    symbols: {:?}\n    public keys: {:?}\n    authority: {}\n    blocks: [\n        {}\n    ]\n}}",
        self.symbols.strings(),
        self.symbols.public_keys.keys.iter().map(|pk| hex::encode(pk.to_bytes())).collect::<Vec<_>>(),
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
        block.public_keys.keys.iter().map(|k | hex::encode(k.to_bytes())).collect::<Vec<_>>(),
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
/// to the token with [`BiscuitBuilder::set_root_key_id`]. This
/// value will be passed to the implementor of `RootKeyProvider`
/// to choose which key will be used.
pub trait RootKeyProvider {
    fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, error::Format>;
}

impl RootKeyProvider for Box<dyn RootKeyProvider> {
    fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, error::Format> {
        self.as_ref().choose(key_id)
    }
}

impl RootKeyProvider for std::rc::Rc<dyn RootKeyProvider> {
    fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, error::Format> {
        self.as_ref().choose(key_id)
    }
}

impl RootKeyProvider for std::sync::Arc<dyn RootKeyProvider> {
    fn choose(&self, key_id: Option<u32>) -> Result<PublicKey, error::Format> {
        self.as_ref().choose(key_id)
    }
}

impl RootKeyProvider for PublicKey {
    fn choose(&self, _: Option<u32>) -> Result<PublicKey, error::Format> {
        Ok(*self)
    }
}

impl RootKeyProvider for &PublicKey {
    fn choose(&self, _: Option<u32>) -> Result<PublicKey, error::Format> {
        Ok(**self)
    }
}

impl<F: Fn(Option<u32>) -> Result<PublicKey, error::Format>> RootKeyProvider for F {
    fn choose(&self, root_key_id: Option<u32>) -> Result<PublicKey, error::Format> {
        self(root_key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{check, fact, pred, rule, string, var};
    use super::builder_ext::BuilderExt;
    use super::*;
    use crate::builder::CheckKind;
    use crate::crypto::KeyPair;
    use crate::{error::*, AuthorizerLimits, UnverifiedBiscuit};
    use builder::AuthorizerBuilder;
    use builder_ext::AuthorizerExt;
    use rand::prelude::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn basic() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

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

            println!("biscuit1 (authority): {}", biscuit1);

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

            let keypair2 = KeyPair::new_with_rng(&mut rng);
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

            let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
            let biscuit2 = biscuit1_deser
                .append_with_keypair(&keypair2, block2)
                .unwrap();

            println!("biscuit2 (1 check): {}", biscuit2);

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

            let keypair3 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
            let biscuit3 = biscuit2_deser
                .append_with_keypair(&keypair3, block3)
                .unwrap();

            biscuit3.to_vec().unwrap()
        };

        //println!("generated biscuit token 3: {} bytes\n{}", serialized3.len(), serialized3.to_hex(16));
        println!("generated biscuit token 3: {} bytes", serialized3.len());
        //panic!();

        let final_token = Biscuit::from(&serialized3, root.public()).unwrap();
        println!("final token:\n{}", final_token);
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

            let res = authorizer.authorize();
            println!("res1: {:?}", res);
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
            println!("res2: {:#?}", res);
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
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .right("/folder1/file1", "read")
            .right("/folder1/file1", "write")
            .right("/folder1/file2", "read")
            .right("/folder1/file2", "write")
            .right("/folder2/file3", "read")
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let block2 = BlockBuilder::new()
            .check_resource_prefix("/folder1/")
            .check_right("read")
            .unwrap();

        let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

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
            println!("res1: {:?}", res);
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
            println!("res2: {:?}", res);
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
            println!("res3: {:?}", res);
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
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .right("file1", "read")
            .right("file2", "read")
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let block2 = BlockBuilder::new()
            .check_expiration_date(SystemTime::now() + Duration::from_secs(30))
            .fact("key(1234)")
            .unwrap();

        let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

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
            println!("res1: {:?}", res);
            res.unwrap();
        }

        {
            println!("biscuit2: {}", biscuit2);
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
            println!("res3: {:?}", res);

            // error message should be like this:
            //"authorizer check 0 failed: check if revocation_id($0), $0 not in [2, 1234, 1, 5, 0]"
            assert!(res.is_ok());
        }
    }

    #[test]
    fn sealed_token() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit1 = Biscuit::builder()
            .right("/folder1/file1", "read")
            .right("/folder1/file1", "write")
            .right("/folder1/file2", "read")
            .right("/folder1/file2", "write")
            .right("/folder2/file3", "read")
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let block2 = BlockBuilder::new()
            .check_resource_prefix("/folder1/")
            .check_right("read")
            .unwrap();

        let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

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
            println!("res1: {:?}", res);
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
            println!("res1: {:?}", res);
            res.unwrap();
        }
    }

    #[test]
    fn verif_no_blocks() {
        use crate::token::builder::*;

        let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .fact(fact("right", &[string("file1"), string("read")]))
            .unwrap()
            .fact(fact("right", &[string("file2"), string("read")]))
            .unwrap()
            .fact(fact("right", &[string("file1"), string("write")]))
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();
        println!("{}", biscuit1);

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
        println!("res: {:?}", res);
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
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .right("file1", "read")
            .right("file2", "read")
            .fact("key(0000)")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let block2 = BlockBuilder::new()
            .check_expiration_date(SystemTime::now() + Duration::from_secs(30))
            .fact("key(1234)")
            .unwrap();

        let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        let block3 = BlockBuilder::new()
            .check_expiration_date(SystemTime::now() + Duration::from_secs(10))
            .fact("key(5678)")
            .unwrap();

        let keypair3 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
        {
            println!("biscuit3: {}", biscuit3);

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
            println!("authorization result: {:?}", authorization_res);

            println!("world:\n{}", authorizer.print_world());
            let res2: Result<Vec<builder::Fact>, crate::error::Token> = authorizer
                .query_all_with_limits(
                    "key_verif($id) <- key($id)",
                    AuthorizerLimits {
                        max_time: Duration::from_secs(10),
                        ..Default::default()
                    },
                );

            println!("res2: {:?}", res2);
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

            let res1: Result<Vec<builder::Fact>, crate::error::Token> =
                other_authorizer.query("key_verif($id) <- key($id)");
            println!("res1: {:?}", res1);
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
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .check(check(
                &[pred("resource", &[string("hello")])],
                CheckKind::One,
            ))
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        // new check: can only have read access1
        let block2 = BlockBuilder::new()
            .fact(fact("check1", &[string("test")]))
            .unwrap();

        let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

        println!("biscuit2: {}", biscuit2);

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
            println!("res1: {:?}", res);

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
        let root = KeyPair::new_with_rng(&mut rng);

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

        let keypair2 = KeyPair::new_with_rng(&mut rng);
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
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .fact("bytes(hex:0102AB)")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let block2 = BlockBuilder::new()
            .rule("has_bytes($0) <- bytes($0), { hex:00000000, hex:0102AB }.contains($0)")
            .unwrap();
        let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();

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
        println!("res1: {:?}", res);
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
        println!("query result: {:x?}", res);
        println!("query result: {:?}", res[0]);
    }

    #[test]
    fn block1_generates_authority_or_ambient() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

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

            println!("biscuit1 (authority): {}", biscuit1);

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

            let keypair2 = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
            let biscuit2 = biscuit1_deser
                .append_with_keypair(&keypair2, block2)
                .unwrap();

            println!("biscuit2 (1 check): {}", biscuit2);

            biscuit2.to_vec().unwrap()
        };

        //println!("generated biscuit token 2: {} bytes\n{}", serialized2.len(), serialized2.to_hex(16));
        println!("generated biscuit token 2: {} bytes", serialized2.len());

        let final_token = Biscuit::from(&serialized2, root.public()).unwrap();
        println!("final token:\n{}", final_token);

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
        println!("res1: {:?}", res);
        println!("authorizer:\n{}", authorizer.print_world());

        assert!(res.is_err());
    }

    #[test]
    fn check_all() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let biscuit1 = Biscuit::builder()
            .check("check if fact($v), $v < 1")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let biscuit2 = Biscuit::builder()
            .check("check all fact($v), $v < 1")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit2 (authority): {}", biscuit2);

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
            println!("res1: {:?}", res);
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
            println!("res2: {:?}", res);

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

    // check that we can still allow the verification of the old 3rd party block signature
    #[test]
    fn third_party_unsafe_deserialize() {
        // this is a token generated with the old third party signature, that does not include the previous block's signature
        let token_bytes = include_bytes!("../../tests/fixtures/unsafe_third_party.bc");
        let _ = UnverifiedBiscuit::unsafe_deprecated_deserialize(token_bytes).unwrap();
        assert_eq!(
            UnverifiedBiscuit::from(token_bytes).unwrap_err(),
            error::Token::Format(error::Format::DeserializationError(
                "Unsupported third party block version".to_string()
            ))
        );

        let root_key = PublicKey::from_bytes_hex(
            "1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284",
            builder::Algorithm::Ed25519,
        )
        .unwrap();
        let _ = Biscuit::unsafe_deprecated_deserialize(token_bytes, root_key).unwrap();
        assert_eq!(
            Biscuit::from(token_bytes, root_key).unwrap_err(),
            error::Token::Format(error::Format::DeserializationError(
                "Unsupported third party block version".to_string()
            ))
        );
    }

    // tests that the authority block signature version 1 works
    #[test]
    fn authority_signature_v1() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);

        let authority_block = Block {
            symbols: default_symbol_table(),
            facts: vec![],
            rules: vec![],
            checks: vec![],
            context: None,
            version: 0,
            external_key: None,
            public_keys: PublicKeys::new(),
            scopes: vec![],
        };

        let next_keypair = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let token =
            SerializedBiscuit::new_inner(None, &root, &next_keypair, &authority_block, 1).unwrap();
        let serialized = token.to_vec().unwrap();

        let _ = Biscuit::from(&serialized, root.public()).unwrap();
    }

    #[test]
    fn verified_unverified_consistency() {
        let mut rng: StdRng = SeedableRng::seed_from_u64(0);
        let root = KeyPair::new_with_rng(builder::Algorithm::Ed25519, &mut rng);
        let biscuit1 = Biscuit::builder()
            .fact("right(\"file1\", \"read\")")
            .unwrap()
            .fact("right(\"file2\", \"read\")")
            .unwrap()
            .fact("right(\"file1\", \"write\")")
            .unwrap()
            .build_with_rng(&root, default_symbol_table(), &mut rng)
            .unwrap();

        println!("biscuit1 (authority): {}", biscuit1);

        let serialized = biscuit1.to_vec().unwrap();

        let parsed = UnverifiedBiscuit::from(serialized).unwrap();

        for i in 0..parsed.block_count() {
            assert_eq!(parsed.print_block_source(i), biscuit1.print_block_source(i));
            assert_eq!(parsed.block_version(i), biscuit1.block_version(i));
        }
    }
}
