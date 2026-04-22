/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{collections::HashMap, convert::TryFrom, fmt, str::FromStr};

use nom::Finish;

use crate::{
    datalog::{self, SymbolTable},
    error,
};

use super::{Convert, Predicate, Term};

/// Builder for a Datalog fact
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub predicate: Predicate,
    pub parameters: Option<HashMap<String, Option<Term>>>,
}

impl Fact {
    pub fn new<T: Into<Vec<Term>>>(name: String, terms: T) -> Fact {
        let mut parameters = HashMap::new();
        let terms: Vec<Term> = terms.into();

        for term in &terms {
            term.extract_parameters(&mut parameters);
        }
        Fact {
            predicate: Predicate::new(name, terms),
            parameters: Some(parameters),
        }
    }

    pub fn validate(&self) -> Result<(), error::Token> {
        match &self.parameters {
            None => Ok(()),
            Some(parameters) => {
                let invalid_parameters = parameters
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
                    .collect::<Vec<_>>();

                if invalid_parameters.is_empty() {
                    Ok(())
                } else {
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters: invalid_parameters,
                            unused_parameters: vec![],
                        },
                    ))
                }
            }
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

    /// replace a parameter with the term argument, without raising an error
    /// if the parameter is not present in the fact description
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

    #[cfg(feature = "datalog-macro")]
    pub fn set_macro_param<T: Into<Term>>(
        &mut self,
        name: &str,
        param: T,
    ) -> Result<(), error::Token> {
        self.set_lenient(name, param.into())
    }

    pub(super) fn apply_parameters(&mut self) {
        if let Some(parameters) = self.parameters.clone() {
            self.predicate.terms = self
                .predicate
                .terms
                .drain(..)
                .map(|t| t.apply_parameters(&parameters))
                .collect();
        }
    }
}

impl Convert<datalog::Fact> for Fact {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Fact {
        let mut fact = self.clone();
        fact.apply_parameters();

        datalog::Fact {
            predicate: fact.predicate.convert(symbols),
        }
    }

    fn convert_from(f: &datalog::Fact, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Fact {
            predicate: Predicate::convert_from(&f.predicate, symbols)?,
            parameters: None,
        })
    }
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fact = self.clone();
        fact.apply_parameters();

        fact.predicate.fmt(f)
    }
}

impl From<biscuit_parser::builder::Fact> for Fact {
    fn from(f: biscuit_parser::builder::Fact) -> Self {
        Fact {
            predicate: f.predicate.into(),
            //    pub parameters: Option<HashMap<String, Option<Term>>>,
            parameters: f.parameters.map(|h| {
                h.into_iter()
                    .map(|(k, v)| (k, v.map(|term| term.into())))
                    .collect()
            }),
        }
    }
}

impl TryFrom<&str> for Fact {
    type Error = error::Token;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(biscuit_parser::parser::fact(value)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}

impl FromStr for Fact {
    type Err = error::Token;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(biscuit_parser::parser::fact(s)
            .finish()
            .map(|(_, o)| o.into())
            .map_err(biscuit_parser::error::LanguageError::from)?)
    }
}
