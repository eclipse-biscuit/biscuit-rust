/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{collections::HashMap, convert::TryFrom, fmt, str::FromStr};

use nom::Finish;

use crate::{
    datalog::{self, SymbolTable},
    error, PublicKey,
};

#[cfg(feature = "datalog-macro")]
use super::ToAnyParam;
use super::{Convert, Expression, Predicate, Scope, Term};

/// Builder for a Datalog rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub head: Predicate,
    pub body: Vec<Predicate>,
    pub expressions: Vec<Expression>,
    pub parameters: Option<HashMap<String, Option<Term>>>,
    pub scopes: Vec<Scope>,
    pub scope_parameters: Option<HashMap<String, Option<PublicKey>>>,
}

impl Rule {
    pub fn new(
        head: Predicate,
        body: Vec<Predicate>,
        expressions: Vec<Expression>,
        scopes: Vec<Scope>,
    ) -> Rule {
        let mut parameters = HashMap::new();
        let mut scope_parameters = HashMap::new();
        for term in &head.terms {
            term.extract_parameters(&mut parameters);
        }

        for predicate in &body {
            for term in &predicate.terms {
                term.extract_parameters(&mut parameters);
            }
        }

        for expression in &expressions {
            for op in &expression.ops {
                op.collect_parameters(&mut parameters);
            }
        }

        for scope in &scopes {
            if let Scope::Parameter(name) = &scope {
                scope_parameters.insert(name.to_string(), None);
            }
        }

        Rule {
            head,
            body,
            expressions,
            parameters: Some(parameters),
            scopes,
            scope_parameters: Some(scope_parameters),
        }
    }

    pub fn validate_parameters(&self) -> Result<(), error::Token> {
        let mut invalid_parameters = match &self.parameters {
            None => vec![],
            Some(parameters) => parameters
                .iter()
                .filter_map(
                    |(name, opt_term)| {
                        if opt_term.is_none() {
                            Some(name)
                        } else {
                            None
                        }
                    },
                )
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        };
        let mut invalid_scope_parameters = match &self.scope_parameters {
            None => vec![],
            Some(parameters) => parameters
                .iter()
                .filter_map(
                    |(name, opt_key)| {
                        if opt_key.is_none() {
                            Some(name)
                        } else {
                            None
                        }
                    },
                )
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
        };
        let mut all_invalid_parameters = vec![];
        all_invalid_parameters.append(&mut invalid_parameters);
        all_invalid_parameters.append(&mut invalid_scope_parameters);

        if all_invalid_parameters.is_empty() {
            Ok(())
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: all_invalid_parameters,
                    unused_parameters: vec![],
                },
            ))
        }
    }

    pub fn validate_variables(&self) -> Result<(), String> {
        let mut head_variables: std::collections::HashSet<String> = self
            .head
            .terms
            .iter()
            .filter_map(|term| match term {
                Term::Variable(s) => Some(s.to_string()),
                _ => None,
            })
            .collect();

        for predicate in self.body.iter() {
            for term in predicate.terms.iter() {
                if let Term::Variable(v) = term {
                    head_variables.remove(v);
                    if head_variables.is_empty() {
                        return Ok(());
                    }
                }
            }
        }

        if head_variables.is_empty() {
            Ok(())
        } else {
            Err(format!(
                    "rule head contains variables that are not used in predicates of the rule's body: {}",
                    head_variables
                    .iter()
                    .map(|s| format!("${}", s))
                    .collect::<Vec<_>>()
                    .join(", ")
                    ))
        }
    }

    /// replace a parameter with the term argument
    pub fn set<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(
                    biscuit_parser::error::LanguageError::Parameters {
                        missing_parameters: vec![],
                        unused_parameters: vec![name.to_string()],
                    },
                )),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
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
    /// parameter is not present in the rule
    pub fn set_lenient<T: Into<Term>>(&mut self, name: &str, term: T) -> Result<(), error::Token> {
        if let Some(parameters) = self.parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Ok(()),
                Some(v) => {
                    *v = Some(term.into());
                    Ok(())
                }
            }
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
        if let Some(parameters) = self.scope_parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Err(error::Token::Language(
                    biscuit_parser::error::LanguageError::Parameters {
                        missing_parameters: vec![],
                        unused_parameters: vec![name.to_string()],
                    },
                )),
                Some(v) => {
                    *v = Some(pubkey);
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
        }
    }

    /// replace a scope parameter with the public key argument, without raising an error if the
    /// parameter is not present in the rule scope
    pub fn set_scope_lenient(&mut self, name: &str, pubkey: PublicKey) -> Result<(), error::Token> {
        if let Some(parameters) = self.scope_parameters.as_mut() {
            match parameters.get_mut(name) {
                None => Ok(()),
                Some(v) => {
                    *v = Some(pubkey);
                    Ok(())
                }
            }
        } else {
            Err(error::Token::Language(
                biscuit_parser::error::LanguageError::Parameters {
                    missing_parameters: vec![],
                    unused_parameters: vec![name.to_string()],
                },
            ))
        }
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
            AnyParam::PublicKey(pubkey) => self.set_scope_lenient(name, pubkey),
        }
    }

    pub(super) fn apply_parameters(&mut self) {
        if let Some(parameters) = self.parameters.clone() {
            self.head.terms = self
                .head
                .terms
                .drain(..)
                .map(|t| {
                    if let Term::Parameter(name) = &t {
                        if let Some(Some(term)) = parameters.get(name) {
                            return term.clone();
                        }
                    }
                    t
                })
                .collect();

            for predicate in &mut self.body {
                predicate.terms = predicate
                    .terms
                    .drain(..)
                    .map(|t| {
                        if let Term::Parameter(name) = &t {
                            if let Some(Some(term)) = parameters.get(name) {
                                return term.clone();
                            }
                        }
                        t
                    })
                    .collect();
            }

            for expression in &mut self.expressions {
                expression.ops = expression
                    .ops
                    .drain(..)
                    .map(|op| op.apply_parameters(&parameters))
                    .collect();
            }
        }

        if let Some(parameters) = self.scope_parameters.clone() {
            self.scopes = self
                .scopes
                .drain(..)
                .map(|scope| {
                    if let Scope::Parameter(name) = &scope {
                        if let Some(Some(pubkey)) = parameters.get(name) {
                            return Scope::PublicKey(*pubkey);
                        }
                    }
                    scope
                })
                .collect();
        }
    }
}

impl Convert<datalog::Rule> for Rule {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Rule {
        let mut r = self.clone();
        r.apply_parameters();

        let head = r.head.convert(symbols);
        let mut body = vec![];
        let mut expressions = vec![];
        let mut scopes = vec![];

        for p in r.body.iter() {
            body.push(p.convert(symbols));
        }

        for c in r.expressions.iter() {
            expressions.push(c.convert(symbols));
        }

        for scope in r.scopes.iter() {
            scopes.push(match scope {
                Scope::Authority => crate::token::Scope::Authority,
                Scope::Previous => crate::token::Scope::Previous,
                Scope::PublicKey(key) => {
                    crate::token::Scope::PublicKey(symbols.public_keys.insert(key))
                }
                // The error is caught in the `add_xxx` functions, so this should
                // not happen™
                Scope::Parameter(s) => panic!("Remaining parameter {}", &s),
            })
        }
        datalog::Rule {
            head,
            body,
            expressions,
            scopes,
        }
    }

    fn convert_from(r: &datalog::Rule, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Rule {
            head: Predicate::convert_from(&r.head, symbols)?,
            body: r
                .body
                .iter()
                .map(|p| Predicate::convert_from(p, symbols))
                .collect::<Result<Vec<Predicate>, error::Format>>()?,
            expressions: r
                .expressions
                .iter()
                .map(|c| Expression::convert_from(c, symbols))
                .collect::<Result<Vec<_>, error::Format>>()?,
            parameters: None,
            scopes: r
                .scopes
                .iter()
                .map(|scope| Scope::convert_from(scope, symbols))
                .collect::<Result<Vec<Scope>, error::Format>>()?,
            scope_parameters: None,
        })
    }
}

pub(super) fn display_rule_body(r: &Rule, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut rule = r.clone();
    rule.apply_parameters();
    if !rule.body.is_empty() {
        write!(f, "{}", rule.body[0])?;

        if rule.body.len() > 1 {
            for i in 1..rule.body.len() {
                write!(f, ", {}", rule.body[i])?;
            }
        }
    }

    if !rule.expressions.is_empty() {
        if !rule.body.is_empty() {
            write!(f, ", ")?;
        }

        write!(f, "{}", rule.expressions[0])?;

        if rule.expressions.len() > 1 {
            for i in 1..rule.expressions.len() {
                write!(f, ", {}", rule.expressions[i])?;
            }
        }
    }

    if !rule.scopes.is_empty() {
        write!(f, " trusting {}", rule.scopes[0])?;
        if rule.scopes.len() > 1 {
            for i in 1..rule.scopes.len() {
                write!(f, ", {}", rule.scopes[i])?;
            }
        }
    }

    Ok(())
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut r = self.clone();
        r.apply_parameters();

        write!(f, "{} <- ", r.head)?;

        display_rule_body(&r, f)
    }
}

impl From<biscuit_parser::builder::Rule> for Rule {
    fn from(r: biscuit_parser::builder::Rule) -> Self {
        Rule {
            head: r.head.into(),
            body: r.body.into_iter().map(|p| p.into()).collect(),
            expressions: r.expressions.into_iter().map(|e| e.into()).collect(),
            parameters: r.parameters.map(|h| {
                h.into_iter()
                    .map(|(k, v)| (k, v.map(|term| term.into())))
                    .collect()
            }),
            scopes: r.scopes.into_iter().map(|s| s.into()).collect(),
            scope_parameters: r.scope_parameters.map(|h| {
                h.into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            v.map(|pk| {
                                PublicKey::from_bytes(&pk.key, pk.algorithm.into())
                                    .expect("invalid public key")
                            }),
                        )
                    })
                    .collect()
            }),
        }
    }
}

impl TryFrom<&str> for Rule {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::rule(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Rule {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::rule(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}
