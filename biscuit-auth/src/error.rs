/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! error types
//!

use std::{
    convert::{From, Infallible},
    fmt::Display,
};
use thiserror::Error;

/// the global error type for Biscuit
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Token {
    #[error("internal error")]
    InternalError,
    #[error("error deserializing or verifying the token")]
    Format(Format),
    #[error("tried to append a block to a sealed token")]
    AppendOnSealed,
    #[error("tried to seal an already sealed token")]
    AlreadySealed,
    #[error("authorization failed: {0}")]
    FailedLogic(Logic),
    #[error("error generating Datalog: {0}")]
    Language(biscuit_parser::error::LanguageError),
    #[error("Reached Datalog execution limits")]
    RunLimit(RunLimit),
    #[error("Cannot convert from Term: {0}")]
    ConversionError(String),
    #[error("Cannot decode base64 token: {0}")]
    Base64(Base64Error),
    #[error("Datalog  execution failure: {0}")]
    Execution(Expression),
}

impl From<Infallible> for Token {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

impl From<Format> for Token {
    fn from(e: Format) -> Self {
        Token::Format(e)
    }
}

impl From<Logic> for Token {
    fn from(e: Logic) -> Self {
        Token::FailedLogic(e)
    }
}

impl From<biscuit_parser::error::LanguageError> for Token {
    fn from(e: biscuit_parser::error::LanguageError) -> Self {
        Token::Language(e)
    }
}

impl From<base64::DecodeError> for Token {
    fn from(e: base64::DecodeError) -> Self {
        let err = match e {
            base64::DecodeError::InvalidByte(offset, byte) => {
                Base64Error::InvalidByte(offset, byte)
            }
            base64::DecodeError::InvalidLength => Base64Error::InvalidLength,
            base64::DecodeError::InvalidLastSymbol(offset, byte) => {
                Base64Error::InvalidLastSymbol(offset, byte)
            }
        };

        Token::Base64(err)
    }
}

impl From<Execution> for Token {
    fn from(e: Execution) -> Self {
        match e {
            Execution::RunLimit(limit) => Token::RunLimit(limit),
            Execution::Expression(e) => Token::Execution(e),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Base64Error {
    InvalidByte(usize, u8),
    InvalidLength,
    InvalidLastSymbol(usize, u8),
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Base64Error::InvalidByte(index, byte) => {
                write!(f, "Invalid byte {byte}, offset {index}.")
            }
            Base64Error::InvalidLength => write!(f, "Encoded text cannot have a 6-bit remainder."),
            Base64Error::InvalidLastSymbol(index, byte) => {
                write!(f, "Invalid last symbol {byte}, offset {index}.")
            }
        }
    }
}

/// Errors related to the token's serialization format or cryptographic
/// signature
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Format {
    #[error("failed verifying the signature")]
    Signature(Signature),
    #[error("failed verifying the signature of a sealed token")]
    SealedSignature,
    #[error("the token does not provide intermediate public keys")]
    EmptyKeys,
    #[error("the root public key was not recognized")]
    UnknownPublicKey,
    #[error("could not deserialize the wrapper object")]
    DeserializationError(String),
    #[error("could not serialize the wrapper object")]
    SerializationError(String),
    #[error("could not deserialize the block")]
    BlockDeserializationError(String),
    #[error("could not serialize the block")]
    BlockSerializationError(String),
    #[error("Block format version is higher than supported")]
    Version {
        maximum: u32,
        minimum: u32,
        actual: u32,
    },
    #[error("invalid key size")]
    InvalidKeySize(usize),
    #[error("invalid signature size")]
    InvalidSignatureSize(usize),
    #[error("invalid key")]
    InvalidKey(String),
    #[error("could not deserialize signature")]
    SignatureDeserializationError(String),
    #[error("could not deserialize the block signature")]
    BlockSignatureDeserializationError(String),
    #[error("invalid block id")]
    InvalidBlockId(usize),
    #[error("the public key is already present in previous blocks")]
    ExistingPublicKey(String),
    #[error("multiple blocks declare the same symbols")]
    SymbolTableOverlap,
    #[error("multiple blocks declare the same public keys")]
    PublicKeyTableOverlap,
    #[error("the external public key was not recognized")]
    UnknownExternalKey,
    #[error("the symbol id was not in the table")]
    UnknownSymbol(u64),
    #[cfg(feature = "pem")]
    #[error("PKCS8 serialization error")]
    PKCS8(String),
}

/// Signature errors
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Signature {
    #[error("could not parse the signature elements")]
    InvalidFormat,
    #[error("the signature did not match")]
    InvalidSignature(String),
    #[error("could not sign")]
    InvalidSignatureGeneration(String),
}

/// errors in the Datalog evaluation
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Logic {
    #[error("a rule provided by a block is producing a fact with unbound variables")]
    InvalidBlockRule(u32, String),
    #[error("{policy}, and the following checks failed: {}", display_failed_checks(.checks))]
    Unauthorized {
        /// the policy that matched
        policy: MatchedPolicy,
        /// list of checks that failed validation
        checks: Vec<FailedCheck>,
    },
    #[error("the authorizer already contains a token")]
    AuthorizerNotEmpty,
    #[error("no matching policy was found, and the following checks failed: {}", display_failed_checks(.checks))]
    NoMatchingPolicy {
        /// list of checks that failed validation
        checks: Vec<FailedCheck>,
    },
}

#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum MatchedPolicy {
    #[error("an allow policy matched (policy index: {0})")]
    Allow(usize),
    #[error("a deny policy matched (policy index: {0})")]
    Deny(usize),
}

/// check errors
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum FailedCheck {
    #[error("{0}")]
    Block(FailedBlockCheck),
    #[error("{0}")]
    Authorizer(FailedAuthorizerCheck),
}

fn display_failed_checks(c: &[FailedCheck]) -> String {
    c.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub struct FailedBlockCheck {
    pub block_id: u32,
    pub check_id: u32,
    /// pretty print of the rule that failed
    pub rule: String,
}

impl Display for FailedBlockCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Check n°{} in block n°{}: {}",
            self.check_id, self.block_id, self.rule
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub struct FailedAuthorizerCheck {
    pub check_id: u32,
    /// pretty print of the rule that failed
    pub rule: String,
}

impl Display for FailedAuthorizerCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Check n°{} in authorizer: {}", self.check_id, self.rule)
    }
}

/// Datalog execution errors
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Execution {
    #[error("Reached Datalog execution limits")]
    RunLimit(RunLimit),
    #[error("Expression execution failure")]
    Expression(Expression),
}

/// Datalog expression execution failure
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum Expression {
    #[error("Unknown symbol")]
    UnknownSymbol(u64),
    #[error("Unknown variable")]
    UnknownVariable(u32),
    #[error("Invalid type")]
    InvalidType,
    #[error("Overflow")]
    Overflow,
    #[error("Division by zero")]
    DivideByZero,
    #[error("Wrong number of elements on stack")]
    InvalidStack,
    #[error("Shadowed variable")]
    ShadowedVariable,
    #[error("Undefined extern func: {0}")]
    UndefinedExtern(String),
    #[error("Error while evaluating extern func {0}: {1}")]
    ExternEvalError(String, String),
}

/// runtime limits errors
#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-error", derive(serde::Serialize, serde::Deserialize))]
pub enum RunLimit {
    #[error("too many facts generated")]
    TooManyFacts,
    #[error("too many engine iterations")]
    TooManyIterations,
    #[error("spent too much time verifying")]
    Timeout,
    #[error("Unexpected query results, expected {0} got {1}")]
    UnexpectedQueryResult(usize, usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_format_strings() {
        assert_eq!(
            format!("{}", Token::ConversionError("test".to_owned())),
            "Cannot convert from Term: test"
        );

        assert_eq!(
            format!("{}", Token::Base64(Base64Error::InvalidLength)),
            "Cannot decode base64 token: Encoded text cannot have a 6-bit remainder."
        );

        assert_eq!(
            format!(
                "{}",
                Token::FailedLogic(Logic::Unauthorized {
                    policy: MatchedPolicy::Allow(0),
                    checks: vec![
                        FailedCheck::Authorizer(FailedAuthorizerCheck {
                            check_id: 0,
                            rule: "check if false".to_string()
                        }),
                        FailedCheck::Block(FailedBlockCheck {
                            block_id: 0,
                            check_id: 0,
                            rule: "check if false".to_string()
                        })
                    ]
                })
            )
            .to_string(),
            "authorization failed: an allow policy matched (policy index: 0), and the following checks failed: Check n°0 in authorizer: check if false, Check n°0 in block n°0: check if false"
        );
    }
}
