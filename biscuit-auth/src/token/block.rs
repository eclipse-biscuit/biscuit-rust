/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::{
    builder::{self, Convert},
    datalog::{Check, Fact, Rule, SymbolTable, Term},
    error,
};

use super::{public_keys::{self, PublicKeys}, Scope};

/// a block contained in a token
#[derive(Clone, Debug)]
pub struct Block {
    /// list of symbols introduced by this block
    pub symbols: SymbolTable,
    /// list of facts provided by this block
    pub facts: Vec<Fact>,
    /// list of rules provided by this block
    pub rules: Vec<Rule>,
    /// checks that the token and ambient data must validate
    pub checks: Vec<Check>,
    /// contextual information that can be looked up before the verification
    /// (as an example, a user id to query rights into a database)
    pub context: Option<String>,
    /// format version used to generate this block
    pub version: u32,
    /// key used in optional external signature
    pub external_key: Option<public_keys::PublicKey>,
    /// list of public keys referenced by this block
    pub public_keys: PublicKeys,
    /// list of scopes defining which blocks are trusted by this block
    pub scopes: Vec<Scope>,
}

impl Block {
    pub fn symbol_add(&mut self, s: &str) -> Term {
        self.symbols.add(s)
    }

    pub fn symbol_insert(&mut self, s: &str) -> u64 {
        self.symbols.insert(s)
    }

    pub(crate) fn print_source(&self, symbols: &SymbolTable) -> String {
        let facts: Vec<_> = self.facts.iter().map(|f| symbols.print_fact(f)).collect();
        let rules: Vec<_> = self
            .rules
            .iter()
            .map(|rule| symbols.print_rule(rule))
            .collect();
        let checks: Vec<_> = self
            .checks
            .iter()
            .map(|check| symbols.print_check(check))
            .collect();

        let mut res = facts.join(";\n");
        if !facts.is_empty() {
            res.push_str(";\n");
        }
        res.push_str(&rules.join(";\n"));
        if !rules.is_empty() {
            res.push_str(";\n");
        }
        res.push_str(&checks.join(";\n"));
        if !checks.is_empty() {
            res.push_str(";\n");
        }

        res
    }

    pub(crate) fn translate(
        &self,
        from_symbols: &SymbolTable,
        to_symbols: &mut SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(Block {
            symbols: SymbolTable::new(),
            facts: self
                .facts
                .iter()
                .map(|f| {
                    builder::Fact::convert_from(f, from_symbols).map(|f| f.convert(to_symbols))
                })
                .collect::<Result<Vec<Fact>, error::Format>>()?,
            rules: self
                .rules
                .iter()
                .map(|r| {
                    builder::Rule::convert_from(r, from_symbols).map(|r| r.convert(to_symbols))
                })
                .collect::<Result<Vec<Rule>, error::Format>>()?,
            checks: self
                .checks
                .iter()
                .map(|c| {
                    builder::Check::convert_from(c, from_symbols).map(|c| c.convert(to_symbols))
                })
                .collect::<Result<Vec<Check>, error::Format>>()?,
            context: self.context.clone(),
            version: self.version,
            external_key: self.external_key.clone(),
            public_keys: self.public_keys.clone(),
            scopes: self
                .scopes
                .iter()
                .map(|s| {
                    builder::Scope::convert_from(s, from_symbols).map(|s| s.convert(to_symbols))
                })
                .collect::<Result<Vec<Scope>, error::Format>>()?,
        })
    }
}
