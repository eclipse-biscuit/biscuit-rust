/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{convert::TryFrom, fmt, str::FromStr};

use nom::Finish;

use crate::{error, PublicKey};

#[cfg(feature = "datalog-macro")]
use super::ToAnyParam;
use super::{display_rule_body, Rule, Term};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyKind {
    Allow,
    Deny,
}

/// Builder for a Biscuit policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub queries: Vec<Rule>,
    pub kind: PolicyKind,
}

impl Policy {
    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        self.set_inner(name, term)
    }

    pub fn set_inner(&mut self, name: &str, term: Term) -> Result<(), error::Token> {
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

    /// replace a parameter with the term argument, ignoring unknown parameters
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        let term = term.into();
        for query in &mut self.queries {
            query.set_lenient(name, term.clone())?;
        }
        Ok(())
    }

    /// replace a scope parameter with the pubkey argument, ignoring unknown parameters
    pub fn set_scope_lenient(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        for query in &mut self.queries {
            query.set_scope_lenient(name, pubkey)?;
        }
        Ok(())
    }

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: ToAnyParam>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        use super::AnyParam;

        match param.to_any_param() {
            AnyParam::Term(t) => self.set_lenient(name, t),
            AnyParam::PublicKey(p) => self.set_scope_lenient(name, p),
        }
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
        for query in &self.queries {
            query.validate_parameters()?;
        }

        Ok(())
    }

    pub fn apply_parameters(&mut self) {
        for rule in self.queries.iter_mut() {
            rule.apply_parameters();
        }
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.queries.is_empty() {
            match self.kind {
                PolicyKind::Allow => write!(f, "allow if ")?,
                PolicyKind::Deny => write!(f, "deny if ")?,
            }

            if !self.queries.is_empty() {
                display_rule_body(&self.queries[0], f)?;

                if self.queries.len() > 1 {
                    for i in 1..self.queries.len() {
                        write!(f, " or ")?;
                        display_rule_body(&self.queries[i], f)?;
                    }
                }
            }
        } else {
            match self.kind {
                PolicyKind::Allow => write!(f, "allow")?,
                PolicyKind::Deny => write!(f, "deny")?,
            }
        }

        Ok(())
    }
}

impl From<biscuit_parser::builder::Policy> for Policy {
    fn from(p: biscuit_parser::builder::Policy) -> Self {
        Policy {
            queries: p.queries.into_iter().map(|q| q.into()).collect(),
            kind: match p.kind {
                biscuit_parser::builder::PolicyKind::Allow => PolicyKind::Allow,
                biscuit_parser::builder::PolicyKind::Deny => PolicyKind::Deny,
            },
        }
    }
}

impl TryFrom<&str> for Policy {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::policy(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Policy {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::policy(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}
