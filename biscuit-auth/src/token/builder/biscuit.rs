/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use super::{BlockBuilder, Check, Fact, Rule, Scope, Term};
use crate::builder_ext::BuilderExt;
use crate::crypto::PublicKey;
use crate::datalog::SymbolTable;
use crate::token::default_symbol_table;
use crate::{error, Biscuit, KeyPair};
use rand::{CryptoRng, RngCore};

use std::fmt;
use std::time::SystemTime;
use std::{collections::HashMap, convert::TryInto, fmt::Write};

/// creates a Biscuit
#[derive(Clone, Default)]
pub struct BiscuitBuilder {
    inner: BlockBuilder,
    root_key_id: Option<u32>,
}

impl BiscuitBuilder {
    pub fn new() -> BiscuitBuilder {
        BiscuitBuilder {
            inner: BlockBuilder::new(),
            root_key_id: None,
        }
    }

    pub fn merge(mut self, other: BlockBuilder) -> Self {
        self.inner = self.inner.merge(other);
        self
    }

    pub fn fact<F: TryInto<Fact>>(mut self, fact: F) -> Result<Self, error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        self.inner = self.inner.fact(fact)?;
        Ok(self)
    }

    pub fn rule<Ru: TryInto<Rule>>(mut self, rule: Ru) -> Result<Self, error::Token>
    where
        error::Token: From<<Ru as TryInto<Rule>>::Error>,
    {
        self.inner = self.inner.rule(rule)?;
        Ok(self)
    }

    pub fn check<C: TryInto<Check>>(mut self, check: C) -> Result<Self, error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        self.inner = self.inner.check(check)?;
        Ok(self)
    }

    pub fn code<T: AsRef<str>>(mut self, source: T) -> Result<Self, error::Token> {
        self.inner = self
            .inner
            .code_with_params(source, HashMap::new(), HashMap::new())?;
        Ok(self)
    }

    pub fn code_with_params<T: AsRef<str>>(
        mut self,
        source: T,
        params: HashMap<String, Term>,
        scope_params: HashMap<String, PublicKey>,
    ) -> Result<Self, error::Token> {
        self.inner = self.inner.code_with_params(source, params, scope_params)?;
        Ok(self)
    }

    pub fn scope(mut self, scope: Scope) -> Self {
        self.inner = self.inner.scope(scope);
        self
    }

    #[cfg(test)]
    pub(crate) fn right(self, resource: &str, right: &str) -> Self {
        use crate::builder::fact;

        use super::string;

        self.fact(fact("right", &[string(resource), string(right)]))
            .unwrap()
    }

    pub fn context(mut self, context: String) -> Self {
        self.inner = self.inner.context(context);
        self
    }

    pub fn root_key_id(mut self, root_key_id: u32) -> Self {
        self.root_key_id = Some(root_key_id);
        self
    }

    /// returns all of the datalog loaded in the biscuit builder
    pub fn dump(&self) -> (Vec<Fact>, Vec<Rule>, Vec<Check>) {
        (
            self.inner.facts.clone(),
            self.inner.rules.clone(),
            self.inner.checks.clone(),
        )
    }

    pub fn dump_code(&self) -> String {
        let (facts, rules, checks) = self.dump();
        let mut f = String::new();
        for fact in facts {
            let _ = writeln!(f, "{};", fact);
        }
        for rule in rules {
            let _ = writeln!(f, "{};", rule);
        }
        for check in checks {
            let _ = writeln!(f, "{};", check);
        }
        f
    }

    pub fn build(self, root_key: &KeyPair) -> Result<Biscuit, error::Token> {
        self.build_with_symbols(root_key, default_symbol_table())
    }

    pub fn build_with_symbols(
        self,
        root_key: &KeyPair,
        symbols: SymbolTable,
    ) -> Result<Biscuit, error::Token> {
        self.build_with_rng(root_key, symbols, &mut rand::rng())
    }

    pub fn build_with_rng<R: RngCore + CryptoRng + ?Sized>(
        self,
        root: &KeyPair,
        symbols: SymbolTable,
        rng: &mut R,
    ) -> Result<Biscuit, error::Token> {
        let authority_block = self.inner.build(symbols.clone());
        Biscuit::new_with_rng(rng, self.root_key_id, root, symbols, authority_block)
    }

    pub fn build_with_key_pair(
        self,
        root: &KeyPair,
        symbols: SymbolTable,
        next: &KeyPair,
    ) -> Result<Biscuit, error::Token> {
        let authority_block = self.inner.build(symbols.clone());
        Biscuit::new_with_key_pair(self.root_key_id, root, next, symbols, authority_block)
    }
}

impl fmt::Display for BiscuitBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.root_key_id {
            None => writeln!(f, "// no root key id set")?,
            Some(id) => writeln!(f, "// root key id: {}", id)?,
        }
        self.inner.fmt(f)
    }
}

impl BuilderExt for BiscuitBuilder {
    fn resource(mut self, name: &str) -> Self {
        self.inner = self.inner.resource(name);
        self
    }
    fn check_resource(mut self, name: &str) -> Self {
        self.inner = self.inner.check_resource(name);
        self
    }
    fn check_resource_prefix(mut self, prefix: &str) -> Self {
        self.inner = self.inner.check_resource_prefix(prefix);
        self
    }
    fn check_resource_suffix(mut self, suffix: &str) -> Self {
        self.inner = self.inner.check_resource_suffix(suffix);
        self
    }
    fn operation(mut self, name: &str) -> Self {
        self.inner = self.inner.operation(name);
        self
    }
    fn check_operation(mut self, name: &str) -> Self {
        self.inner = self.inner.check_operation(name);
        self
    }
    fn check_expiration_date(mut self, date: SystemTime) -> Self {
        self.inner = self.inner.check_expiration_date(date);
        self
    }
}
