/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! restrictions on the features a token may contain, enforced during deserialization
use std::collections::HashSet;

use crate::builder::{Algorithm, CheckKind};
use crate::error::TokenLimit;
use crate::format::schema;

/// Restrictions on the features a token may contain, enforced while it is deserialized
///
/// Settings which apply to the token as a whole are fields of `DeserializationLimits` itself,
/// while settings which apply within each block are part of [BlockLimits]. Separate
/// [BlockLimits] are used for the authority block and for attenuation blocks, so that
/// attenuations can be restricted more tightly than the authority block.
///
/// Sets are optional: `None` means that any valid element is allowed.
///
/// Start from [DeserializationLimits::allow_everything] and restrict only what you need:
///
/// ```rust
/// use biscuit_auth::DeserializationLimits;
///
/// let mut limits = DeserializationLimits::allow_everything();
/// limits.max_blocks = 4;
/// limits.attenuations.allow_closures = false;
/// ```
///
/// Alternatively, start from [DeserializationLimits::allow_nothing] and enable only the features
/// you need.
///
/// A token which does not respect the limits fails to deserialize with
/// [crate::error::Format::TokenLimit].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeserializationLimits {
    /// whether attenuation blocks may be signed by a third party
    pub allow_attenuations_with_external_signatures: bool,
    /// whether attenuation blocks may be signed without a third party
    pub allow_attenuations_without_external_signatures: bool,
    /// whether the token may be sealed
    pub allow_sealed_tokens: bool,
    /// whether the token may be unsealed
    pub allow_unsealed_tokens: bool,

    /// maximum size of the serialized token, in bytes
    pub max_token_size: usize,
    /// maximum number of blocks, including the authority block
    pub max_blocks: usize,
    /// minimum signature scheme version for each block
    pub min_signature_version: u32,

    /// signing algorithms allowed for the keys which sign each block of the token and its proof
    pub allowed_internal_signing_algorithms: Option<HashSet<Algorithm>>,
    /// signing algorithms allowed for the third party keys which sign attenuation blocks
    pub allowed_external_signing_algorithms: Option<HashSet<Algorithm>>,

    /// limits for the authority block
    pub authority: BlockLimits,
    /// limits for each attenuation block
    pub attenuations: BlockLimits,
}

impl DeserializationLimits {
    /// limits which allow all features
    pub fn allow_everything() -> Self {
        DeserializationLimits {
            allow_attenuations_with_external_signatures: true,
            allow_attenuations_without_external_signatures: true,
            allow_sealed_tokens: true,
            allow_unsealed_tokens: true,
            max_token_size: usize::MAX,
            max_blocks: usize::MAX,
            min_signature_version: 0,
            allowed_internal_signing_algorithms: None,
            allowed_external_signing_algorithms: None,
            authority: BlockLimits::allow_everything(),
            attenuations: BlockLimits::allow_everything(),
        }
    }

    /// limits which allow no features
    ///
    /// Future versions of this library may add settings, which will be disallowed by these
    /// limits: tokens accepted by limits built from these may be rejected after upgrading,
    /// until those features are enabled.
    pub fn allow_nothing() -> Self {
        DeserializationLimits {
            allow_attenuations_with_external_signatures: false,
            allow_attenuations_without_external_signatures: false,
            allow_sealed_tokens: false,
            allow_unsealed_tokens: false,
            max_token_size: 0,
            max_blocks: 0,
            min_signature_version: 1,
            allowed_internal_signing_algorithms: Some(HashSet::new()),
            allowed_external_signing_algorithms: Some(HashSet::new()),
            authority: BlockLimits::allow_nothing(),
            attenuations: BlockLimits::allow_nothing(),
        }
    }
}

/// The features allowed within a single block of a token
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockLimits {
    /// whether expressions may contain closures
    pub allow_closures: bool,

    /// maximum size of the serialized Datalog block, in bytes
    pub max_block_size: usize,
    /// maximum number of facts in the block
    pub max_facts: usize,
    /// maximum number of rules in the block
    pub max_rules: usize,
    /// maximum number of checks in the block
    pub max_checks: usize,
    /// maximum number of symbols in the block's symbol table
    pub max_symbols_per_block: usize,
    /// maximum number of public keys in the block's public key table
    pub max_public_keys_per_block: usize,
    /// maximum length of the block's context, in bytes
    pub max_context_length: usize,
    /// maximum number of queries in each check
    pub max_queries_per_check: usize,
    /// maximum number of predicates in the body of each rule or check query
    pub max_predicates_per_body: usize,
    /// maximum number of expressions in the body of each rule or check query
    pub max_expressions_per_body: usize,
    /// maximum number of ops in each expression, including the ops of nested closures
    pub max_ops_per_expression: usize,
    /// maximum number of terms in each fact or predicate
    pub max_terms_per_predicate: usize,
    /// maximum length of names (predicates, variables, closure parameters, external
    /// functions), in bytes
    pub max_name_length: usize,
    /// maximum length of bytes terms
    pub max_bytes_length: usize,
    /// maximum length of string terms, in bytes
    pub max_string_length: usize,
    /// maximum number of elements in each set, not counting nested collections
    pub max_set_length: usize,
    /// maximum number of elements in each array, not counting nested collections
    pub max_array_length: usize,
    /// maximum number of entries in each map, not counting nested collections
    pub max_map_length: usize,

    /// kinds of checks allowed (`check if`, `check all`, `reject if`)
    pub allowed_check_kinds: Option<HashSet<CheckKind>>,
    /// Datalog term types allowed
    pub allowed_term_types: Option<HashSet<TermType>>,
    /// map key types allowed
    pub allowed_map_key_types: Option<HashSet<MapKeyType>>,
    /// unary operations allowed in expressions
    pub allowed_unary_ops: Option<HashSet<UnaryOpKind>>,
    /// binary operations allowed in expressions
    pub allowed_binary_ops: Option<HashSet<BinaryOpKind>>,
    /// scopes allowed to be trusted by the block, its rules and its checks
    pub allowed_trusting_scopes: Option<HashSet<ScopeKind>>,
    /// names of the external functions allowed to be called with no arguments
    pub allowed_unary_external_functions: Option<HashSet<String>>,
    /// names of the external functions allowed to be called with one argument
    pub allowed_binary_external_functions: Option<HashSet<String>>,
}

impl BlockLimits {
    /// limits which allow all features
    pub fn allow_everything() -> Self {
        BlockLimits {
            allow_closures: true,
            max_block_size: usize::MAX,
            max_facts: usize::MAX,
            max_rules: usize::MAX,
            max_checks: usize::MAX,
            max_symbols_per_block: usize::MAX,
            max_public_keys_per_block: usize::MAX,
            max_context_length: usize::MAX,
            max_queries_per_check: usize::MAX,
            max_predicates_per_body: usize::MAX,
            max_expressions_per_body: usize::MAX,
            max_ops_per_expression: usize::MAX,
            max_terms_per_predicate: usize::MAX,
            max_name_length: usize::MAX,
            max_bytes_length: usize::MAX,
            max_string_length: usize::MAX,
            max_set_length: usize::MAX,
            max_array_length: usize::MAX,
            max_map_length: usize::MAX,
            allowed_check_kinds: None,
            allowed_term_types: None,
            allowed_map_key_types: None,
            allowed_unary_ops: None,
            allowed_binary_ops: None,
            allowed_trusting_scopes: None,
            allowed_unary_external_functions: None,
            allowed_binary_external_functions: None,
        }
    }

    /// limits which allow no features
    ///
    /// Future versions of this library may add settings, which will be disallowed by these
    /// limits.
    pub fn allow_nothing() -> Self {
        BlockLimits {
            allow_closures: false,
            max_block_size: 0,
            max_facts: 0,
            max_rules: 0,
            max_checks: 0,
            max_symbols_per_block: 0,
            max_public_keys_per_block: 0,
            max_context_length: 0,
            max_queries_per_check: 0,
            max_predicates_per_body: 0,
            max_expressions_per_body: 0,
            max_ops_per_expression: 0,
            max_terms_per_predicate: 0,
            max_name_length: 0,
            max_bytes_length: 0,
            max_string_length: 0,
            max_set_length: 0,
            max_array_length: 0,
            max_map_length: 0,
            allowed_check_kinds: Some(HashSet::new()),
            allowed_term_types: Some(HashSet::new()),
            allowed_map_key_types: Some(HashSet::new()),
            allowed_unary_ops: Some(HashSet::new()),
            allowed_binary_ops: Some(HashSet::new()),
            allowed_trusting_scopes: Some(HashSet::new()),
            allowed_unary_external_functions: Some(HashSet::new()),
            allowed_binary_external_functions: Some(HashSet::new()),
        }
    }
}

/// type of a Datalog term, as used in [BlockLimits::allowed_term_types]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TermType {
    Integer,
    String,
    Date,
    Bytes,
    Bool,
    Set,
    Null,
    Array,
    Map,
}

/// type of a map key, as used in [BlockLimits::allowed_map_key_types]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MapKeyType {
    Integer,
    String,
}

/// kind of a unary operation, as used in [BlockLimits::allowed_unary_ops]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnaryOpKind {
    /// `!`
    Negate,
    /// parentheses
    Parens,
    /// `.length()`
    Length,
    /// `.type()`
    TypeOf,
    /// call to an external function with no arguments, `.extern::name()`
    Ffi,
}

impl UnaryOpKind {
    pub(crate) fn from_schema(kind: schema::op_unary::Kind) -> Self {
        match kind {
            schema::op_unary::Kind::Negate => UnaryOpKind::Negate,
            schema::op_unary::Kind::Parens => UnaryOpKind::Parens,
            schema::op_unary::Kind::Length => UnaryOpKind::Length,
            schema::op_unary::Kind::TypeOf => UnaryOpKind::TypeOf,
            schema::op_unary::Kind::Ffi => UnaryOpKind::Ffi,
        }
    }
}

/// kind of a binary operation, as used in [BlockLimits::allowed_binary_ops]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BinaryOpKind {
    /// `<`
    LessThan,
    /// `>`
    GreaterThan,
    /// `<=`
    LessOrEqual,
    /// `>=`
    GreaterOrEqual,
    /// `===`
    Equal,
    /// `.contains()`
    Contains,
    /// `.starts_with()`
    Prefix,
    /// `.ends_with()`
    Suffix,
    /// `.matches()`
    Regex,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `&&`, evaluating both operands
    And,
    /// `||`, evaluating both operands
    Or,
    /// `.intersection()`
    Intersection,
    /// `.union()`
    Union,
    /// `&`
    BitwiseAnd,
    /// `|`
    BitwiseOr,
    /// `^`
    BitwiseXor,
    /// `!==`
    NotEqual,
    /// `==`
    HeterogeneousEqual,
    /// `!=`
    HeterogeneousNotEqual,
    /// `&&`, only evaluating the right operand if needed
    LazyAnd,
    /// `||`, only evaluating the right operand if needed
    LazyOr,
    /// `.all()`
    All,
    /// `.any()`
    Any,
    /// `.get()`
    Get,
    /// call to an external function with one argument, `.extern::name(arg)`
    Ffi,
    /// `.try_or()`
    TryOr,
}

impl BinaryOpKind {
    pub(crate) fn from_schema(kind: schema::op_binary::Kind) -> Self {
        match kind {
            schema::op_binary::Kind::LessThan => BinaryOpKind::LessThan,
            schema::op_binary::Kind::GreaterThan => BinaryOpKind::GreaterThan,
            schema::op_binary::Kind::LessOrEqual => BinaryOpKind::LessOrEqual,
            schema::op_binary::Kind::GreaterOrEqual => BinaryOpKind::GreaterOrEqual,
            schema::op_binary::Kind::Equal => BinaryOpKind::Equal,
            schema::op_binary::Kind::Contains => BinaryOpKind::Contains,
            schema::op_binary::Kind::Prefix => BinaryOpKind::Prefix,
            schema::op_binary::Kind::Suffix => BinaryOpKind::Suffix,
            schema::op_binary::Kind::Regex => BinaryOpKind::Regex,
            schema::op_binary::Kind::Add => BinaryOpKind::Add,
            schema::op_binary::Kind::Sub => BinaryOpKind::Sub,
            schema::op_binary::Kind::Mul => BinaryOpKind::Mul,
            schema::op_binary::Kind::Div => BinaryOpKind::Div,
            schema::op_binary::Kind::And => BinaryOpKind::And,
            schema::op_binary::Kind::Or => BinaryOpKind::Or,
            schema::op_binary::Kind::Intersection => BinaryOpKind::Intersection,
            schema::op_binary::Kind::Union => BinaryOpKind::Union,
            schema::op_binary::Kind::BitwiseAnd => BinaryOpKind::BitwiseAnd,
            schema::op_binary::Kind::BitwiseOr => BinaryOpKind::BitwiseOr,
            schema::op_binary::Kind::BitwiseXor => BinaryOpKind::BitwiseXor,
            schema::op_binary::Kind::NotEqual => BinaryOpKind::NotEqual,
            schema::op_binary::Kind::HeterogeneousEqual => BinaryOpKind::HeterogeneousEqual,
            schema::op_binary::Kind::HeterogeneousNotEqual => BinaryOpKind::HeterogeneousNotEqual,
            schema::op_binary::Kind::LazyAnd => BinaryOpKind::LazyAnd,
            schema::op_binary::Kind::LazyOr => BinaryOpKind::LazyOr,
            schema::op_binary::Kind::All => BinaryOpKind::All,
            schema::op_binary::Kind::Any => BinaryOpKind::Any,
            schema::op_binary::Kind::Get => BinaryOpKind::Get,
            schema::op_binary::Kind::Ffi => BinaryOpKind::Ffi,
            schema::op_binary::Kind::TryOr => BinaryOpKind::TryOr,
        }
    }
}

/// kind of trusted scope, as used in [BlockLimits::allowed_trusting_scopes]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScopeKind {
    /// `trusting authority`
    Authority,
    /// `trusting previous`
    Previous,
    /// trusting a public key using the given algorithm
    PublicKey(Algorithm),
}

/// rejects base64 input which cannot decode to a token within the size limit, before
/// allocating the decoded buffer
pub(crate) fn check_base64_size(
    encoded: &[u8],
    limits: &DeserializationLimits,
) -> Result<(), TokenLimit> {
    // every complete group of 4 characters decodes to at least 1 byte, and all but the last
    // one decode to 3 bytes
    let min_decoded = (encoded.len() / 4).saturating_mul(3).saturating_sub(2);
    check_max(
        min_decoded,
        limits.max_token_size,
        TokenLimit::TokenTooLarge,
    )
}

/// whether `value` is in `set`, if the set is restricted
pub(crate) fn allowed<T: std::hash::Hash + Eq>(set: &Option<HashSet<T>>, value: &T) -> bool {
    set.as_ref().is_none_or(|set| set.contains(value))
}

fn check_max<E>(value: usize, max: usize, error: E) -> Result<(), E> {
    if value > max {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BlockLimit;
    use crate::error::{Format, Token};
    use crate::{Biscuit, BlockBuilder, PrivateKey, UnverifiedBiscuit};

    // destructuring without `..` makes this fail to compile when a setting is added, so
    // that its `allow_nothing` value and its enforcement test are not forgotten
    #[test]
    fn allow_nothing_allows_nothing() {
        let DeserializationLimits {
            allow_attenuations_with_external_signatures,
            allow_attenuations_without_external_signatures,
            allow_sealed_tokens,
            allow_unsealed_tokens,
            max_token_size,
            max_blocks,
            min_signature_version,
            allowed_internal_signing_algorithms,
            allowed_external_signing_algorithms,
            authority,
            attenuations,
        } = DeserializationLimits::allow_nothing();
        assert!(!allow_attenuations_with_external_signatures);
        assert!(!allow_attenuations_without_external_signatures);
        assert!(!allow_sealed_tokens);
        assert!(!allow_unsealed_tokens);
        assert_eq!(max_token_size, 0);
        assert_eq!(max_blocks, 0);
        // highest supported signature version
        assert_eq!(min_signature_version, 1);
        assert_eq!(allowed_internal_signing_algorithms, Some(HashSet::new()));
        assert_eq!(allowed_external_signing_algorithms, Some(HashSet::new()));
        assert_eq!(authority, BlockLimits::allow_nothing());
        assert_eq!(attenuations, BlockLimits::allow_nothing());

        let BlockLimits {
            allow_closures,
            max_block_size,
            max_facts,
            max_rules,
            max_checks,
            max_symbols_per_block,
            max_public_keys_per_block,
            max_context_length,
            max_queries_per_check,
            max_predicates_per_body,
            max_expressions_per_body,
            max_ops_per_expression,
            max_terms_per_predicate,
            max_name_length,
            max_bytes_length,
            max_string_length,
            max_set_length,
            max_array_length,
            max_map_length,
            allowed_check_kinds,
            allowed_term_types,
            allowed_map_key_types,
            allowed_unary_ops,
            allowed_binary_ops,
            allowed_trusting_scopes,
            allowed_unary_external_functions,
            allowed_binary_external_functions,
        } = BlockLimits::allow_nothing();
        assert!(!allow_closures);
        for max in [
            max_block_size,
            max_facts,
            max_rules,
            max_checks,
            max_symbols_per_block,
            max_public_keys_per_block,
            max_context_length,
            max_queries_per_check,
            max_predicates_per_body,
            max_expressions_per_body,
            max_ops_per_expression,
            max_terms_per_predicate,
            max_name_length,
            max_bytes_length,
            max_string_length,
            max_set_length,
            max_array_length,
            max_map_length,
        ] {
            assert_eq!(max, 0);
        }
        assert_eq!(allowed_check_kinds, Some(HashSet::new()));
        assert_eq!(allowed_term_types, Some(HashSet::new()));
        assert_eq!(allowed_map_key_types, Some(HashSet::new()));
        assert_eq!(allowed_unary_ops, Some(HashSet::new()));
        assert_eq!(allowed_binary_ops, Some(HashSet::new()));
        assert_eq!(allowed_trusting_scopes, Some(HashSet::new()));
        assert_eq!(allowed_unary_external_functions, Some(HashSet::new()));
        assert_eq!(allowed_binary_external_functions, Some(HashSet::new()));
    }

    fn deserialize(
        token: &[u8],
        root: &PrivateKey,
        limits: &DeserializationLimits,
        verified: bool,
    ) -> Result<(), Token> {
        if verified {
            Biscuit::from_with_limits(token, root.public(), limits).map(|_| ())
        } else {
            UnverifiedBiscuit::from_with_limits(token, limits).map(|_| ())
        }
    }

    fn assert_accepted(
        token: &[u8],
        root: &PrivateKey,
        limits: &DeserializationLimits,
        message: &str,
    ) {
        for verified in [true, false] {
            if let Err(e) = deserialize(token, root, limits, verified) {
                panic!("{} (verified: {}): {:?}", message, verified, e);
            }
        }
    }

    fn assert_rejected(
        token: &[u8],
        root: &PrivateKey,
        limits: &DeserializationLimits,
        expected: Format,
        message: &str,
    ) {
        for verified in [true, false] {
            assert_eq!(
                deserialize(token, root, limits, verified).unwrap_err(),
                Token::Format(expected.clone()),
                "{message} (verified: {verified})"
            );
        }
    }

    fn biscuit(root: &PrivateKey) -> Biscuit {
        Biscuit::builder()
            .code("fact(1);")
            .unwrap()
            .build(root)
            .unwrap()
    }

    fn third_party_token(root: &PrivateKey) -> Vec<u8> {
        let token = biscuit(root);
        let external = PrivateKey::new();
        let block = token
            .third_party_request()
            .unwrap()
            .create_block(
                &external,
                BlockBuilder::new().code("check if true;").unwrap(),
            )
            .unwrap();
        token
            .append_third_party(external.public(), block)
            .unwrap()
            .to_vec()
            .unwrap()
    }

    fn attenuated_token(root: &PrivateKey) -> Vec<u8> {
        biscuit(root)
            .append(BlockBuilder::new().code("check if true;").unwrap())
            .unwrap()
            .to_vec()
            .unwrap()
    }

    #[test]
    fn deserialization_limits_are_enforced() {
        let root = PrivateKey::new();
        type Case = (
            &'static str,
            fn(&mut DeserializationLimits),
            Format,
            Vec<u8>,
        );
        let cases: Vec<Case> = vec![
            (
                "allow_attenuations_with_external_signatures",
                |l| l.allow_attenuations_with_external_signatures = false,
                BlockLimit::AttenuationsWithExternalSignaturesNotAllowed.in_block(1),
                third_party_token(&root),
            ),
            (
                "allow_attenuations_without_external_signatures",
                |l| l.allow_attenuations_without_external_signatures = false,
                BlockLimit::AttenuationsWithoutExternalSignaturesNotAllowed.in_block(1),
                attenuated_token(&root),
            ),
            (
                "allow_sealed_tokens",
                |l| l.allow_sealed_tokens = false,
                TokenLimit::SealedTokensNotAllowed.into(),
                biscuit(&root).seal().unwrap().to_vec().unwrap(),
            ),
            (
                "allow_unsealed_tokens",
                |l| l.allow_unsealed_tokens = false,
                TokenLimit::UnsealedTokensNotAllowed.into(),
                biscuit(&root).to_vec().unwrap(),
            ),
            (
                "max_token_size",
                |l| l.max_token_size = 10,
                TokenLimit::TokenTooLarge.into(),
                biscuit(&root).to_vec().unwrap(),
            ),
            (
                "max_blocks",
                |l| l.max_blocks = 1,
                TokenLimit::TooManyBlocks.into(),
                attenuated_token(&root),
            ),
            (
                // ed25519 blocks with datalog < 3.3 use version 0 signatures
                "min_signature_version",
                |l| l.min_signature_version = 1,
                BlockLimit::SignatureVersionTooLow.in_block(0),
                biscuit(&root).to_vec().unwrap(),
            ),
            (
                "allowed_internal_signing_algorithms",
                |l| {
                    l.allowed_internal_signing_algorithms =
                        Some(HashSet::from([Algorithm::Secp256r1]))
                },
                BlockLimit::InternalSigningAlgorithmNotAllowed.in_block(0),
                biscuit(&root).to_vec().unwrap(),
            ),
            (
                "allowed_external_signing_algorithms",
                |l| {
                    l.allowed_external_signing_algorithms =
                        Some(HashSet::from([Algorithm::Secp256r1]))
                },
                BlockLimit::ExternalSigningAlgorithmNotAllowed.in_block(1),
                third_party_token(&root),
            ),
        ];

        for (name, restrict, expected, token) in cases {
            assert_accepted(
                &token,
                &root,
                &DeserializationLimits::allow_everything(),
                &format!("{name}: token should be accepted without limits"),
            );
            let mut limits = DeserializationLimits::allow_everything();
            restrict(&mut limits);
            assert_rejected(&token, &root, &limits, expected, name);
        }
    }

    // each block limit is checked with the restricted feature in the authority block and in an
    // attenuation, and must only apply to the block it was set for
    #[test]
    fn block_limits_are_enforced() {
        let root = PrivateKey::new();
        let trusted_key = PrivateKey::new().public().to_string();
        type Case = (&'static str, fn(&mut BlockLimits), BlockLimit, BlockBuilder);
        let code = |code: &str| BlockBuilder::new().code(code).unwrap();
        let cases: Vec<Case> = vec![
            (
                "allow_closures",
                |l| l.allow_closures = false,
                BlockLimit::ClosuresNotAllowed,
                code("check if [1].any($x -> $x == 1);"),
            ),
            (
                "max_block_size",
                |l| l.max_block_size = 10,
                BlockLimit::BlockTooLarge,
                code("check if claim(\"YELLOW SUBMARINE\");"),
            ),
            (
                "max_facts",
                |l| l.max_facts = 0,
                BlockLimit::TooManyFacts,
                code("fact(1);"),
            ),
            (
                "max_rules",
                |l| l.max_rules = 0,
                BlockLimit::TooManyRules,
                code("derived($x) <- fact($x);"),
            ),
            (
                "max_checks",
                |l| l.max_checks = 0,
                BlockLimit::TooManyChecks,
                code("check if true;"),
            ),
            (
                "max_symbols_per_block",
                |l| l.max_symbols_per_block = 0,
                BlockLimit::TooManySymbols,
                code("fact(\"symbol\");"),
            ),
            (
                "max_public_keys_per_block",
                |l| l.max_public_keys_per_block = 0,
                BlockLimit::TooManyPublicKeys,
                code(&format!("check if true trusting {trusted_key};")),
            ),
            (
                "max_context_length",
                |l| l.max_context_length = 2,
                BlockLimit::ContextTooLong,
                code("fact(1);").context("context".to_string()),
            ),
            (
                "max_queries_per_check",
                |l| l.max_queries_per_check = 1,
                BlockLimit::TooManyQueries,
                code("check if true or false;"),
            ),
            (
                "max_predicates_per_body",
                |l| l.max_predicates_per_body = 0,
                BlockLimit::TooManyPredicates,
                code("check if fact(1);"),
            ),
            (
                "max_expressions_per_body",
                |l| l.max_expressions_per_body = 0,
                BlockLimit::TooManyExpressions,
                code("check if true;"),
            ),
            (
                "max_ops_per_expression",
                |l| l.max_ops_per_expression = 2,
                BlockLimit::TooManyOps,
                code("check if 1 == 1;"),
            ),
            (
                "max_terms_per_predicate",
                |l| l.max_terms_per_predicate = 0,
                BlockLimit::TooManyTerms,
                code("fact(1);"),
            ),
            (
                "max_name_length",
                |l| l.max_name_length = 3,
                BlockLimit::NameTooLong,
                code("longname(1);"),
            ),
            (
                "max_bytes_length",
                |l| l.max_bytes_length = 0,
                BlockLimit::BytesTooLong,
                code("fact(hex:00);"),
            ),
            (
                "max_string_length",
                |l| l.max_string_length = 0,
                BlockLimit::StringTooLong,
                code("fact(\"a\");"),
            ),
            (
                "max_set_length",
                |l| l.max_set_length = 0,
                BlockLimit::SetTooLong,
                code("fact({1});"),
            ),
            (
                "max_array_length",
                |l| l.max_array_length = 0,
                BlockLimit::ArrayTooLong,
                code("fact([1]);"),
            ),
            (
                "max_map_length",
                |l| l.max_map_length = 0,
                BlockLimit::MapTooLong,
                code("fact({\"key\": 1});"),
            ),
            (
                "allowed_check_kinds",
                |l| l.allowed_check_kinds = Some(HashSet::from([CheckKind::All])),
                BlockLimit::CheckKindNotAllowed,
                code("check if true;"),
            ),
            (
                "allowed_term_types",
                |l| l.allowed_term_types = Some(HashSet::from([TermType::String])),
                BlockLimit::TermTypeNotAllowed,
                code("fact(1);"),
            ),
            (
                "allowed_map_key_types",
                |l| l.allowed_map_key_types = Some(HashSet::from([MapKeyType::Integer])),
                BlockLimit::MapKeyTypeNotAllowed,
                code("fact({\"key\": 1});"),
            ),
            (
                "allowed_unary_ops",
                |l| l.allowed_unary_ops = Some(HashSet::from([UnaryOpKind::Length])),
                BlockLimit::UnaryOperationNotAllowed,
                code("check if !false;"),
            ),
            (
                "allowed_binary_ops",
                |l| l.allowed_binary_ops = Some(HashSet::from([BinaryOpKind::Add])),
                BlockLimit::BinaryOperationNotAllowed,
                code("check if 1 == 1;"),
            ),
            (
                "allowed_trusting_scopes",
                |l| l.allowed_trusting_scopes = Some(HashSet::from([ScopeKind::Authority])),
                BlockLimit::TrustedScopeNotAllowed,
                code("check if true trusting previous;"),
            ),
            (
                "allowed_unary_external_functions",
                |l| l.allowed_unary_external_functions = Some(HashSet::from(["other".to_string()])),
                BlockLimit::ExternalFunctionNotAllowed,
                code("check if 1.extern::function();"),
            ),
            (
                "allowed_binary_external_functions",
                |l| {
                    l.allowed_binary_external_functions = Some(HashSet::from(["other".to_string()]))
                },
                BlockLimit::ExternalFunctionNotAllowed,
                code("check if 1.extern::function(2);"),
            ),
        ];

        for (name, restrict, expected, block) in cases {
            let in_authority = Biscuit::builder()
                .merge(block.clone())
                .build(&root)
                .unwrap()
                .to_vec()
                .unwrap();
            let in_attenuation = Biscuit::builder()
                .build(&root)
                .unwrap()
                .append(block)
                .unwrap()
                .to_vec()
                .unwrap();

            let everything = DeserializationLimits::allow_everything();
            assert_accepted(&in_authority, &root, &everything, name);
            assert_accepted(&in_attenuation, &root, &everything, name);

            let mut limits = DeserializationLimits::allow_everything();
            restrict(&mut limits.authority);
            assert_rejected(
                &in_authority,
                &root,
                &limits,
                expected.clone().in_block(0),
                name,
            );
            assert_accepted(
                &in_attenuation,
                &root,
                &limits,
                &format!("authority.{name} should not apply to attenuations"),
            );

            let mut limits = DeserializationLimits::allow_everything();
            restrict(&mut limits.attenuations);
            assert_rejected(&in_attenuation, &root, &limits, expected.in_block(1), name);
            assert_accepted(
                &in_authority,
                &root,
                &limits,
                &format!("attenuations.{name} should not apply to the authority block"),
            );
        }
    }

    // third party blocks resolve symbols and public keys from their own tables
    #[test]
    fn third_party_block_limits() {
        let root = PrivateKey::new();
        let token = biscuit(&root);
        let external = PrivateKey::new();
        let trusted = PrivateKey::new_with_algorithm(Algorithm::Secp256r1);
        let block = token
            .third_party_request()
            .unwrap()
            .create_block(
                &external,
                BlockBuilder::new()
                    .code(format!(
                        "check if longname(1) trusting {};",
                        trusted.public()
                    ))
                    .unwrap(),
            )
            .unwrap();
        let token = token
            .append_third_party(external.public(), block)
            .unwrap()
            .to_vec()
            .unwrap();

        let mut limits = DeserializationLimits::allow_everything();
        limits.attenuations.allowed_trusting_scopes =
            Some(HashSet::from([ScopeKind::PublicKey(Algorithm::Secp256r1)]));
        assert_accepted(&token, &root, &limits, "secp256r1 keys are trusted");
        limits.attenuations.allowed_trusting_scopes =
            Some(HashSet::from([ScopeKind::PublicKey(Algorithm::Ed25519)]));
        assert_rejected(
            &token,
            &root,
            &limits,
            BlockLimit::TrustedScopeNotAllowed.in_block(1),
            "only ed25519 keys are trusted",
        );

        let mut limits = DeserializationLimits::allow_everything();
        limits.attenuations.max_name_length = 3;
        assert_rejected(
            &token,
            &root,
            &limits,
            BlockLimit::NameTooLong.in_block(1),
            "names are looked up in the third party block's symbols",
        );
    }

    #[test]
    fn base64_size_is_checked_before_decoding() {
        let root = PrivateKey::new();
        let token = biscuit(&root).to_base64().unwrap();
        let mut limits = DeserializationLimits::allow_everything();
        limits.max_token_size = token.len() * 3 / 4;
        assert!(Biscuit::from_base64_with_limits(&token, root.public(), &limits).is_ok());
        assert!(UnverifiedBiscuit::from_base64_with_limits(&token, &limits).is_ok());

        limits.max_token_size = 10;
        // not valid base64, so this fails with a decoding error unless the size is checked first
        let garbage = "!".repeat(1000);
        let expected = Token::Format(Format::TokenLimit(TokenLimit::TokenTooLarge));
        assert_eq!(
            Biscuit::from_base64_with_limits(&garbage, root.public(), &limits).unwrap_err(),
            expected
        );
        assert_eq!(
            UnverifiedBiscuit::from_base64_with_limits(&garbage, &limits).unwrap_err(),
            expected
        );
    }

    #[test]
    fn errors_report_the_block_index() {
        let root = PrivateKey::new();
        let token = biscuit(&root)
            .append(BlockBuilder::new().code("check if true;").unwrap())
            .unwrap()
            .append(BlockBuilder::new().code("fact(2);").unwrap())
            .unwrap()
            .to_vec()
            .unwrap();
        let mut limits = DeserializationLimits::allow_everything();
        limits.attenuations.max_facts = 0;
        assert_rejected(
            &token,
            &root,
            &limits,
            BlockLimit::TooManyFacts.in_block(2),
            "facts",
        );

        let error = Biscuit::from_with_limits(&token, root.public(), &limits).unwrap_err();
        let Token::Format(error) = error else {
            panic!("unexpected error {:?}", error)
        };
        assert_eq!(
            error.to_string(),
            "block 2 exceeds the deserialization limits: a block contains too many facts"
        );
        assert_eq!(
            Format::from(TokenLimit::TooManyBlocks).to_string(),
            "the token exceeds the deserialization limits: the token contains too many blocks"
        );
    }
}
