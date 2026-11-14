/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use thiserror::Error;

#[derive(Error, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-types", derive(serde::Serialize, serde::Deserialize))]
pub enum LanguageError {
    #[error("datalog parsing error: {0:?}")]
    ParseError(ParseErrors),
    #[error("datalog parameters must all be bound, provided values must all be used.\nMissing parameters: {missing_parameters:?}\nUnused parameters: {unused_parameters:?}")]
    Parameters {
        missing_parameters: Vec<String>,
        unused_parameters: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-types", derive(serde::Serialize, serde::Deserialize))]
pub struct ParseErrors {
    pub errors: Vec<ParseError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde-types", derive(serde::Serialize, serde::Deserialize))]
pub struct ParseError {
    pub input: String,
    pub message: Option<String>,
}

impl<'a> From<crate::parser::Error<'a>> for ParseError {
    fn from(e: crate::parser::Error<'a>) -> Self {
        ParseError {
            input: e.input.to_string(),
            message: e.message,
        }
    }
}

impl<'a> From<crate::parser::Error<'a>> for ParseErrors {
    fn from(error: crate::parser::Error<'a>) -> Self {
        ParseErrors {
            errors: vec![error.into()],
        }
    }
}

impl<'a> From<Vec<crate::parser::Error<'a>>> for ParseErrors {
    fn from(errors: Vec<crate::parser::Error<'a>>) -> Self {
        ParseErrors {
            errors: errors.into_iter().map(|e| e.into()).collect(),
        }
    }
}

impl<'a> From<crate::parser::Error<'a>> for LanguageError {
    fn from(e: crate::parser::Error<'a>) -> Self {
        LanguageError::ParseError(e.into())
    }
}

impl<'a> From<Vec<crate::parser::Error<'a>>> for LanguageError {
    fn from(e: Vec<crate::parser::Error<'a>>) -> Self {
        LanguageError::ParseError(e.into())
    }
}
