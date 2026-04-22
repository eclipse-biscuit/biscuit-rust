/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Symbol table implementation
use std::collections::HashSet;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub type SymbolIndex = u64;
use crate::crypto::PublicKey;
use crate::token::default_symbol_table;
use crate::{error, token::public_keys::PublicKeys};

use super::{Check, Fact, Predicate, Rule, Term, World};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolTable {
    symbols: Vec<String>,
    pub(crate) public_keys: PublicKeys,
}

const DEFAULT_SYMBOLS: [&str; 28] = [
    "read",
    "write",
    "resource",
    "operation",
    "right",
    "time",
    "role",
    "owner",
    "tenant",
    "namespace",
    "user",
    "team",
    "service",
    "admin",
    "email",
    "group",
    "member",
    "ip_address",
    "client",
    "client_ip",
    "domain",
    "path",
    "version",
    "cluster",
    "node",
    "hostname",
    "nonce",
    "query",
];

const OFFSET: usize = 1024;

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable {
            symbols: vec![],
            public_keys: PublicKeys::new(),
        }
    }

    pub fn from(symbols: Vec<String>) -> Result<Self, error::Format> {
        let h1 = DEFAULT_SYMBOLS.iter().copied().collect::<HashSet<_>>();
        let h2 = symbols.iter().map(|s| s.as_str()).collect::<HashSet<_>>();

        if !h1.is_disjoint(&h2) {
            return Err(error::Format::SymbolTableOverlap);
        }

        Ok(SymbolTable {
            symbols,
            public_keys: PublicKeys::new(),
        })
    }

    pub fn from_symbols_and_public_keys(
        symbols: Vec<String>,
        public_keys: Vec<PublicKey>,
    ) -> Result<Self, error::Format> {
        let mut table = Self::from(symbols)?;
        table.public_keys = PublicKeys::from(public_keys);
        Ok(table)
    }

    pub fn extend(&mut self, other: &SymbolTable) -> Result<(), error::Format> {
        if !self.is_disjoint(other) {
            return Err(error::Format::SymbolTableOverlap);
        }
        self.symbols.extend(other.symbols.iter().cloned());
        self.public_keys.extend(&other.public_keys)?;
        Ok(())
    }

    pub fn insert(&mut self, s: &str) -> SymbolIndex {
        if let Some(index) = DEFAULT_SYMBOLS.iter().position(|sym| *sym == s) {
            return index as u64;
        }

        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => (OFFSET + index) as u64,
            None => {
                self.symbols.push(s.to_string());
                (OFFSET + (self.symbols.len() - 1)) as u64
            }
        }
    }

    pub fn add(&mut self, s: &str) -> Term {
        let term = self.insert(s);
        Term::Str(term)
    }

    pub fn get(&self, s: &str) -> Option<SymbolIndex> {
        if let Some(index) = DEFAULT_SYMBOLS.iter().position(|sym| *sym == s) {
            return Some(index as u64);
        }

        self.symbols
            .iter()
            .position(|sym| sym.as_str() == s)
            .map(|i| (OFFSET + i) as SymbolIndex)
    }

    pub fn strings(&self) -> Vec<String> {
        self.symbols.clone()
    }

    pub fn current_offset(&self) -> usize {
        self.symbols.len()
    }

    pub fn split_at(&mut self, offset: usize) -> SymbolTable {
        let mut table = SymbolTable::new();
        table.symbols = self.symbols.split_off(offset);
        table
    }

    pub fn is_disjoint(&self, other: &SymbolTable) -> bool {
        let h1 = self.symbols.iter().collect::<HashSet<_>>();
        let h2 = other.symbols.iter().collect::<HashSet<_>>();

        h1.is_disjoint(&h2)
    }

    pub fn get_symbol(&self, i: SymbolIndex) -> Option<&str> {
        if i >= OFFSET as u64 {
            self.symbols
                .get((i - OFFSET as u64) as usize)
                .map(|s| s.as_str())
        } else {
            DEFAULT_SYMBOLS.get(i as usize).copied()
        }
    }

    pub fn print_symbol(&self, i: SymbolIndex) -> Result<String, error::Format> {
        self.get_symbol(i)
            .map(|s| s.to_string())
            .ok_or(error::Format::UnknownSymbol(i))
    }

    // infallible symbol printing method
    pub fn print_symbol_default(&self, i: SymbolIndex) -> String {
        self.get_symbol(i)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("<{i}?>"))
    }

    pub fn print_world(&self, w: &World) -> String {
        let facts = w
            .facts
            .inner
            .iter()
            .flat_map(|facts| facts.1.iter())
            .map(|f| self.print_fact(f))
            .collect::<Vec<_>>();
        let rules = w
            .rules
            .inner
            .iter()
            .flat_map(|rules| rules.1.iter())
            .map(|(_, r)| self.print_rule(r))
            .collect::<Vec<_>>();
        format!("World {{\n  facts: {facts:#?}\n  rules: {rules:#?}\n}}")
    }

    pub fn print_term(&self, term: &Term) -> String {
        match term {
            Term::Variable(i) => format!("${}", self.print_symbol_default(*i as u64)),
            Term::Integer(i) => i.to_string(),
            Term::Str(index) => format!("\"{}\"", self.print_symbol_default(*index)),
            Term::Date(d) => OffsetDateTime::from_unix_timestamp(*d as i64)
                .ok()
                .and_then(|t| t.format(&Rfc3339).ok())
                .unwrap_or_else(|| "<invalid date>".to_string()),
            Term::Bytes(s) => format!("hex:{}", hex::encode(s)),
            Term::Bool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            Term::Set(s) => {
                if s.is_empty() {
                    "{,}".to_string()
                } else {
                    let terms = s
                        .iter()
                        .map(|term| self.print_term(term))
                        .collect::<Vec<_>>();
                    format!("{{{}}}", terms.join(", "))
                }
            }
            Term::Null => "null".to_string(),
            Term::Array(a) => {
                let terms = a
                    .iter()
                    .map(|term| self.print_term(term))
                    .collect::<Vec<_>>();
                format!("[{}]", terms.join(", "))
            }
            Term::Map(m) => {
                let terms = m
                    .iter()
                    .map(|(key, term)| match key {
                        crate::datalog::MapKey::Integer(i) => {
                            format!("{}: {}", i, self.print_term(term))
                        }
                        crate::datalog::MapKey::Str(s) => {
                            format!(
                                "\"{}\": {}",
                                self.print_symbol_default(*s),
                                self.print_term(term)
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                format!("{{{}}}", terms.join(", "))
            }
        }
    }

    pub fn print_fact(&self, f: &Fact) -> String {
        self.print_predicate(&f.predicate)
    }

    pub fn print_predicate(&self, p: &Predicate) -> String {
        let strings = p
            .terms
            .iter()
            .map(|term| self.print_term(term))
            .collect::<Vec<_>>();
        format!(
            "{}({})",
            self.get_symbol(p.name).unwrap_or("<?>"),
            strings.join(", ")
        )
    }

    pub fn print_expression(&self, e: &super::expression::Expression) -> String {
        e.print(self)
            .unwrap_or_else(|| format!("<invalid expression: {:?}>", e.ops))
    }

    pub fn print_rule_body(&self, r: &Rule) -> String {
        let preds: Vec<_> = r.body.iter().map(|p| self.print_predicate(p)).collect();

        let expressions: Vec<_> = r
            .expressions
            .iter()
            .map(|c| self.print_expression(c))
            .collect();

        let e = if expressions.is_empty() {
            String::new()
        } else if preds.is_empty() {
            expressions.join(", ")
        } else {
            format!(", {}", expressions.join(", "))
        };

        let scopes = if r.scopes.is_empty() {
            String::new()
        } else {
            let s: Vec<_> = r
                .scopes
                .iter()
                .map(|scope| match scope {
                    crate::token::Scope::Authority => "authority".to_string(),
                    crate::token::Scope::Previous => "previous".to_string(),
                    crate::token::Scope::PublicKey(key_id) => {
                        match self.public_keys.get_key(*key_id) {
                            Some(key) => key.print(),
                            None => "<unknown public key id>".to_string(),
                        }
                    }
                })
                .collect();
            format!(" trusting {}", s.join(", "))
        };

        format!("{}{}{}", preds.join(", "), e, scopes)
    }

    pub fn print_rule(&self, r: &Rule) -> String {
        let res = self.print_predicate(&r.head);

        format!("{} <- {}", res, self.print_rule_body(r))
    }

    pub fn print_check(&self, c: &Check) -> String {
        let queries = c
            .queries
            .iter()
            .map(|r| self.print_rule_body(r))
            .collect::<Vec<_>>();

        format!(
            "{} {}",
            match c.kind {
                crate::builder::CheckKind::One => "check if",
                crate::builder::CheckKind::All => "check all",
                crate::builder::CheckKind::Reject => "reject if",
            },
            queries.join(" or ")
        )
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        default_symbol_table()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemporarySymbolTable<'a> {
    base: &'a SymbolTable,
    offset: usize,
    symbols: Vec<String>,
}

impl<'a> TemporarySymbolTable<'a> {
    pub fn new(base: &'a SymbolTable) -> Self {
        let offset = OFFSET + base.current_offset();

        TemporarySymbolTable {
            base,
            offset,
            symbols: vec![],
        }
    }

    pub fn get_symbol(&self, i: SymbolIndex) -> Option<&str> {
        if i as usize >= self.offset {
            self.symbols
                .get(i as usize - self.offset)
                .map(|s| s.as_str())
        } else {
            self.base.get_symbol(i)
        }
    }

    pub fn insert(&mut self, s: &str) -> SymbolIndex {
        if let Some(index) = self.base.get(s) {
            return index;
        }

        match self.symbols.iter().position(|sym| sym.as_str() == s) {
            Some(index) => (self.offset + index) as u64,
            None => {
                self.symbols.push(s.to_string());
                (self.offset + (self.symbols.len() - 1)) as u64
            }
        }
    }
}
