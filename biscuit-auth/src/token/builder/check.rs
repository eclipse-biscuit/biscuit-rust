/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{convert::TryFrom, fmt, str::FromStr};

use nom::Finish;

use crate::{
    datalog::{self, SymbolTable},
    error, PublicKey,
};

use super::{display_rule_body, Convert, Rule, Term};

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub queries: Vec<Rule>,
    pub kind: CheckKind,
}

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    One,
    All,
    Reject,
}

impl Check {
    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        self.set_inner(name, term)
    }

    fn set_inner(&mut self, name: &str, term: Term) -> Result<(), error::Token> {
        let mut found = false;
        for query in &mut self.queries {
            if query.set(name, term.clone()).is_ok() {
                found = true;
            }
        }

        if found {
            Ok(())
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
        }
    }

    /// replace a scope parameter with the pubkey argument
    pub fn set_scope(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        let mut found = false;
        for query in &mut self.queries {
            if query.set_scope(name, pubkey).is_ok() {
                found = true;
            }
        }

        if found {
            Ok(())
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
        }
    }

    /// replace a parameter with the term argument, without raising an error if the
    /// parameter is not present in the check
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        for query in &mut self.queries {
            query.set_lenient(name, term.clone())?;
        }
        Ok(())
    }

    /// replace a scope parameter with the term argument, without raising an error if the
    /// parameter is not present in the check
    pub fn set_scope_lenient(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        for query in &mut self.queries {
            query.set_scope_lenient(name, pubkey)?;
        }
        Ok(())
    }

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: Into<Term>>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        self.set_lenient(name, param.into())
    }

    // TODO maybe introduce a conversion trait to support refs, multiple values, non-pk scopes
    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_scope_param(
        &mut self,
        name: &str,
        param: PublicKey,
    ) -> Result<(), error::Token> {
        self.set_scope_lenient(name, param)
    }

    pub fn validate_parameters(&self) -> Result<(), error::Token> {
        for rule in &self.queries {
            rule.validate_parameters()?;
        }

        Ok(())
    }

    pub(super) fn apply_parameters(&mut self) {
        for rule in self.queries.iter_mut() {
            rule.apply_parameters();
        }
    }
}

impl Convert<datalog::Check> for Check {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Check {
        let mut queries = vec![];
        for q in self.queries.iter() {
            queries.push(q.convert(symbols));
        }

        datalog::Check {
            queries,
            kind: self.kind.clone(),
        }
    }

    fn convert_from(r: &datalog::Check, symbols: &SymbolTable) -> Result<Self, error::Format> {
        let mut queries = vec![];
        for q in r.queries.iter() {
            queries.push(Rule::convert_from(q, symbols)?);
        }

        Ok(Check {
            queries,
            kind: r.kind.clone(),
        })
    }
}

impl TryFrom<Rule> for Check {
    type Error = error::Token;

    fn try_from(value: Rule) -> Result<Self, Self::Error> {
        Ok(Check {
            queries: vec![value],
            kind: CheckKind::One,
        })
    }
}

impl TryFrom<&[Rule]> for Check {
    type Error = error::Token;

    fn try_from(values: &[Rule]) -> Result<Self, Self::Error> {
        Ok(Check {
            queries: values.to_vec(),
            kind: CheckKind::One,
        })
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            CheckKind::One => write!(f, "check if ")?,
            CheckKind::All => write!(f, "check all ")?,
            CheckKind::Reject => write!(f, "reject if ")?,
        };

        if !self.queries.is_empty() {
            let mut q0 = self.queries[0].clone();
            q0.apply_parameters();
            display_rule_body(&q0, f)?;

            if self.queries.len() > 1 {
                for i in 1..self.queries.len() {
                    write!(f, " or ")?;
                    let mut qn = self.queries[i].clone();
                    qn.apply_parameters();
                    display_rule_body(&qn, f)?;
                }
            }
        }

        Ok(())
    }
}

impl From<biscuit_parser::builder::Check> for Check {
    fn from(c: biscuit_parser::builder::Check) -> Self {
        Check {
            queries: c.queries.into_iter().map(|q| q.into()).collect(),
            kind: match c.kind {
                biscuit_parser::builder::CheckKind::One => CheckKind::One,
                biscuit_parser::builder::CheckKind::All => CheckKind::All,
                biscuit_parser::builder::CheckKind::Reject => CheckKind::Reject,
            },
        }
    }
}

impl TryFrom<&str> for Check {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::check(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Check {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::check(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}
