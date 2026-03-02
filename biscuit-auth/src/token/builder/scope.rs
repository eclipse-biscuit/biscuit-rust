/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::fmt;

use crate::{datalog::SymbolTable, error, PublicKey};

use super::Convert;

/// Builder for a block or rule scope
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Scope {
    /// Trusts the first block, current block and the authorizer
    Authority,
    /// Trusts the current block and all previous ones
    Previous,
    /// Trusts the current block and any block signed by the public key
    PublicKey(PublicKey),
    /// Used for parameter substitution
    Parameter(String),
}

impl Convert<crate::token::Scope> for Scope {
    fn convert(&self, symbols: &mut SymbolTable) -> crate::token::Scope {
        match self {
            Scope::Authority => crate::token::Scope::Authority,
            Scope::Previous => crate::token::Scope::Previous,
            Scope::PublicKey(key) => {
                crate::token::Scope::PublicKey(symbols.public_keys.insert(key))
            }
            // The error is caught in the `add_xxx` functions, so this should
            // not happen™
            Scope::Parameter(s) => panic!("Remaining parameter {}", &s),
        }
    }

    fn convert_from(
        scope: &crate::token::Scope,
        symbols: &SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(match scope {
            crate::token::Scope::Authority => Scope::Authority,
            crate::token::Scope::Previous => Scope::Previous,
            crate::token::Scope::PublicKey(key_id) => Scope::PublicKey(
                *symbols
                    .public_keys
                    .get_key(*key_id)
                    .ok_or(error::Format::UnknownExternalKey)?,
            ),
        })
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Authority => write!(f, "authority"),
            Scope::Previous => write!(f, "previous"),
            Scope::PublicKey(pk) => write!(f, "{}", pk),
            Scope::Parameter(s) => {
                write!(f, "{{{}}}", s)
            }
        }
    }
}

impl From<biscuit_parser::builder::Scope> for Scope {
    fn from(scope: biscuit_parser::builder::Scope) -> Self {
        match scope {
            biscuit_parser::builder::Scope::Authority => Scope::Authority,
            biscuit_parser::builder::Scope::Previous => Scope::Previous,
            biscuit_parser::builder::Scope::PublicKey(pk) => Scope::PublicKey(
                PublicKey::from_bytes(&pk.key, pk.algorithm.into()).expect("invalid public key"),
            ),
            biscuit_parser::builder::Scope::Parameter(s) => Scope::Parameter(s),
        }
    }
}
