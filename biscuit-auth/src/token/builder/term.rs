/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::{TryFrom, TryInto},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    datalog::{self, SymbolTable, TemporarySymbolTable},
    error,
};

use super::{set, Convert, Fact};
#[cfg(feature = "datalog-macro")]
use super::{AnyParam, ToAnyParam};

/// Builder for a Datalog value
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    Variable(String),
    Integer(i64),
    Str(String),
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Set(BTreeSet<Term>),
    Parameter(String),
    Null,
    Array(Vec<Term>),
    Map(BTreeMap<MapKey, Term>),
}

impl Term {
    pub(super) fn extract_parameters(&self, parameters: &mut HashMap<String, Option<Term>>) {
        match self {
            Term::Parameter(name) => {
                parameters.insert(name.to_string(), None);
            }
            Term::Set(s) => {
                for term in s {
                    term.extract_parameters(parameters);
                }
            }
            Term::Array(a) => {
                for term in a {
                    term.extract_parameters(parameters);
                }
            }
            Term::Map(m) => {
                for (key, term) in m {
                    if let MapKey::Parameter(name) = key {
                        parameters.insert(name.to_string(), None);
                    }
                    term.extract_parameters(parameters);
                }
            }
            _ => {}
        }
    }

    pub(super) fn apply_parameters(self, parameters: &HashMap<String, Option<Term>>) -> Term {
        match self {
            Term::Parameter(name) => {
                if let Some(Some(term)) = parameters.get(&name) {
                    term.clone()
                } else {
                    Term::Parameter(name)
                }
            }
            Term::Map(m) => Term::Map(
                m.into_iter()
                    .map(|(key, term)| {
                        (
                            match key {
                                MapKey::Parameter(name) => {
                                    if let Some(Some(key_term)) = parameters.get(&name) {
                                        match key_term {
                                            Term::Integer(i) => MapKey::Integer(*i),
                                            Term::Str(s) => MapKey::Str(s.clone()),
                                            //FIXME: we should return an error
                                            _ => MapKey::Parameter(name),
                                        }
                                    } else {
                                        MapKey::Parameter(name)
                                    }
                                }
                                _ => key,
                            },
                            term.apply_parameters(parameters),
                        )
                    })
                    .collect(),
            ),
            Term::Array(array) => Term::Array(
                array
                    .into_iter()
                    .map(|term| term.apply_parameters(parameters))
                    .collect(),
            ),
            Term::Set(set) => Term::Set(
                set.into_iter()
                    .map(|term| term.apply_parameters(parameters))
                    .collect(),
            ),
            _ => self,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MapKey {
    Integer(i64),
    Str(String),
    Parameter(String),
}

impl Term {
    pub fn to_datalog(self, symbols: &mut TemporarySymbolTable) -> datalog::Term {
        match self {
            Term::Variable(s) => datalog::Term::Variable(symbols.insert(&s) as u32),
            Term::Integer(i) => datalog::Term::Integer(i),
            Term::Str(s) => datalog::Term::Str(symbols.insert(&s)),
            Term::Date(d) => datalog::Term::Date(d),
            Term::Bytes(s) => datalog::Term::Bytes(s),
            Term::Bool(b) => datalog::Term::Bool(b),
            Term::Set(s) => {
                datalog::Term::Set(s.into_iter().map(|i| i.to_datalog(symbols)).collect())
            }
            Term::Null => datalog::Term::Null,
            Term::Array(a) => {
                datalog::Term::Array(a.into_iter().map(|i| i.to_datalog(symbols)).collect())
            }
            Term::Map(m) => datalog::Term::Map(
                m.into_iter()
                    .map(|(k, i)| {
                        (
                            match k {
                                MapKey::Integer(i) => datalog::MapKey::Integer(i),
                                MapKey::Str(s) => datalog::MapKey::Str(symbols.insert(&s)),
                                // The error is caught in the `add_xxx` functions, so this should
                                // not happen™
                                MapKey::Parameter(s) => panic!("Remaining parameter {}", &s),
                            },
                            i.to_datalog(symbols),
                        )
                    })
                    .collect(),
            ),
            // The error is caught in the `add_xxx` functions, so this should
            // not happen™
            Term::Parameter(s) => panic!("Remaining parameter {}", &s),
        }
    }

    pub fn from_datalog(
        term: datalog::Term,
        symbols: &TemporarySymbolTable,
    ) -> Result<Self, error::Expression> {
        Ok(match term {
            datalog::Term::Variable(s) => Term::Variable(
                symbols
                    .get_symbol(s as u64)
                    .ok_or(error::Expression::UnknownVariable(s))?
                    .to_string(),
            ),
            datalog::Term::Integer(i) => Term::Integer(i),
            datalog::Term::Str(s) => Term::Str(
                symbols
                    .get_symbol(s)
                    .ok_or(error::Expression::UnknownSymbol(s))?
                    .to_string(),
            ),
            datalog::Term::Date(d) => Term::Date(d),
            datalog::Term::Bytes(s) => Term::Bytes(s),
            datalog::Term::Bool(b) => Term::Bool(b),
            datalog::Term::Set(s) => Term::Set(
                s.into_iter()
                    .map(|i| Self::from_datalog(i, symbols))
                    .collect::<Result<_, _>>()?,
            ),
            datalog::Term::Null => Term::Null,
            datalog::Term::Array(a) => Term::Array(
                a.into_iter()
                    .map(|i| Self::from_datalog(i, symbols))
                    .collect::<Result<_, _>>()?,
            ),
            datalog::Term::Map(m) => Term::Map(
                m.into_iter()
                    .map(|(k, i)| {
                        Ok((
                            match k {
                                datalog::MapKey::Integer(i) => MapKey::Integer(i),
                                datalog::MapKey::Str(s) => MapKey::Str(
                                    symbols
                                        .get_symbol(s)
                                        .ok_or(error::Expression::UnknownSymbol(s))?
                                        .to_string(),
                                ),
                            },
                            Self::from_datalog(i, symbols)?,
                        ))
                    })
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}

impl Convert<datalog::Term> for Term {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Term {
        match self {
            Term::Variable(s) => datalog::Term::Variable(symbols.insert(s) as u32),
            Term::Integer(i) => datalog::Term::Integer(*i),
            Term::Str(s) => datalog::Term::Str(symbols.insert(s)),
            Term::Date(d) => datalog::Term::Date(*d),
            Term::Bytes(s) => datalog::Term::Bytes(s.clone()),
            Term::Bool(b) => datalog::Term::Bool(*b),
            Term::Set(s) => datalog::Term::Set(s.iter().map(|i| i.convert(symbols)).collect()),
            Term::Null => datalog::Term::Null,
            // The error is caught in the `add_xxx` functions, so this should
            // not happen™
            Term::Parameter(s) => panic!("Remaining parameter {}", &s),
            Term::Array(a) => datalog::Term::Array(a.iter().map(|i| i.convert(symbols)).collect()),
            Term::Map(m) => datalog::Term::Map(
                m.iter()
                    .map(|(key, term)| {
                        let key = match key {
                            MapKey::Integer(i) => datalog::MapKey::Integer(*i),
                            MapKey::Str(s) => datalog::MapKey::Str(symbols.insert(s)),
                            MapKey::Parameter(s) => panic!("Remaining parameter {}", &s),
                        };

                        (key, term.convert(symbols))
                    })
                    .collect(),
            ),
        }
    }

    fn convert_from(f: &datalog::Term, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(match f {
            datalog::Term::Variable(s) => Term::Variable(symbols.print_symbol(*s as u64)?),
            datalog::Term::Integer(i) => Term::Integer(*i),
            datalog::Term::Str(s) => Term::Str(symbols.print_symbol(*s)?),
            datalog::Term::Date(d) => Term::Date(*d),
            datalog::Term::Bytes(s) => Term::Bytes(s.clone()),
            datalog::Term::Bool(b) => Term::Bool(*b),
            datalog::Term::Set(s) => Term::Set(
                s.iter()
                    .map(|i| Term::convert_from(i, symbols))
                    .collect::<Result<BTreeSet<_>, error::Format>>()?,
            ),
            datalog::Term::Null => Term::Null,
            datalog::Term::Array(a) => Term::Array(
                a.iter()
                    .map(|i| Term::convert_from(i, symbols))
                    .collect::<Result<Vec<_>, error::Format>>()?,
            ),
            datalog::Term::Map(m) => Term::Map(
                m.iter()
                    .map(|(key, term)| {
                        let key = match key {
                            datalog::MapKey::Integer(i) => Ok(MapKey::Integer(*i)),
                            datalog::MapKey::Str(s) => symbols.print_symbol(*s).map(MapKey::Str),
                        };

                        key.and_then(|k| Term::convert_from(term, symbols).map(|term| (k, term)))
                    })
                    .collect::<Result<BTreeMap<_, _>, error::Format>>()?,
            ),
        })
    }
}

impl From<&Term> for Term {
    fn from(i: &Term) -> Self {
        match i {
            Term::Variable(ref v) => Term::Variable(v.clone()),
            Term::Integer(ref i) => Term::Integer(*i),
            Term::Str(ref s) => Term::Str(s.clone()),
            Term::Date(ref d) => Term::Date(*d),
            Term::Bytes(ref s) => Term::Bytes(s.clone()),
            Term::Bool(b) => Term::Bool(*b),
            Term::Set(ref s) => Term::Set(s.clone()),
            Term::Parameter(ref p) => Term::Parameter(p.clone()),
            Term::Null => Term::Null,
            Term::Array(ref a) => Term::Array(a.clone()),
            Term::Map(m) => Term::Map(m.clone()),
        }
    }
}

impl From<biscuit_parser::builder::Term> for Term {
    fn from(t: biscuit_parser::builder::Term) -> Self {
        match t {
            biscuit_parser::builder::Term::Variable(v) => Term::Variable(v),
            biscuit_parser::builder::Term::Integer(i) => Term::Integer(i),
            biscuit_parser::builder::Term::Str(s) => Term::Str(s),
            biscuit_parser::builder::Term::Date(d) => Term::Date(d),
            biscuit_parser::builder::Term::Bytes(s) => Term::Bytes(s),
            biscuit_parser::builder::Term::Bool(b) => Term::Bool(b),
            biscuit_parser::builder::Term::Set(s) => {
                Term::Set(s.into_iter().map(|t| t.into()).collect())
            }
            biscuit_parser::builder::Term::Null => Term::Null,
            biscuit_parser::builder::Term::Parameter(ref p) => Term::Parameter(p.clone()),
            biscuit_parser::builder::Term::Array(a) => {
                Term::Array(a.into_iter().map(|t| t.into()).collect())
            }
            biscuit_parser::builder::Term::Map(a) => Term::Map(
                a.into_iter()
                    .map(|(key, term)| {
                        (
                            match key {
                                biscuit_parser::builder::MapKey::Parameter(s) => {
                                    MapKey::Parameter(s)
                                }
                                biscuit_parser::builder::MapKey::Integer(i) => MapKey::Integer(i),
                                biscuit_parser::builder::MapKey::Str(s) => MapKey::Str(s),
                            },
                            term.into(),
                        )
                    })
                    .collect(),
            ),
        }
    }
}

impl AsRef<Term> for Term {
    fn as_ref(&self) -> &Term {
        self
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Variable(i) => write!(f, "${}", i),
            Term::Integer(i) => write!(f, "{}", i),
            Term::Str(s) => write!(f, "\"{}\"", s),
            Term::Date(d) => {
                let date = time::OffsetDateTime::from_unix_timestamp(*d as i64)
                    .ok()
                    .and_then(|t| {
                        t.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    })
                    .unwrap_or_else(|| "<invalid date>".to_string());

                write!(f, "{}", date)
            }
            Term::Bytes(s) => write!(f, "hex:{}", hex::encode(s)),
            Term::Bool(b) => {
                if *b {
                    write!(f, "true")
                } else {
                    write!(f, "false")
                }
            }
            Term::Set(s) => {
                if s.is_empty() {
                    write!(f, "{{,}}")
                } else {
                    let terms = s.iter().map(|term| term.to_string()).collect::<Vec<_>>();
                    write!(f, "{{{}}}", terms.join(", "))
                }
            }
            Term::Parameter(s) => {
                write!(f, "{{{}}}", s)
            }
            Term::Null => write!(f, "null"),
            Term::Array(a) => {
                let terms = a.iter().map(|term| term.to_string()).collect::<Vec<_>>();
                write!(f, "[{}]", terms.join(", "))
            }
            Term::Map(m) => {
                let terms = m
                    .iter()
                    .map(|(key, term)| match key {
                        MapKey::Integer(i) => format!("{i}: {}", term),
                        MapKey::Str(s) => format!("\"{s}\": {}", term),
                        MapKey::Parameter(s) => format!("{{{s}}}: {}", term),
                    })
                    .collect::<Vec<_>>();
                write!(f, "{{{}}}", terms.join(", "))
            }
        }
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for Term {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(self.clone())
    }
}

impl From<i64> for Term {
    fn from(i: i64) -> Self {
        Term::Integer(i)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for i64 {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((*self).into())
    }
}

impl TryFrom<Term> for i64 {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Integer(i) => Ok(i),
            _ => Err(error::Token::ConversionError(format!(
                "expected integer, got {:?}",
                value
            ))),
        }
    }
}

impl From<bool> for Term {
    fn from(b: bool) -> Self {
        Term::Bool(b)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for bool {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((*self).into())
    }
}

impl TryFrom<Term> for bool {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Bool(b) => Ok(b),
            _ => Err(error::Token::ConversionError(format!(
                "expected boolean, got {:?}",
                value
            ))),
        }
    }
}

impl From<String> for Term {
    fn from(s: String) -> Self {
        Term::Str(s)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for String {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl From<&str> for Term {
    fn from(s: &str) -> Self {
        Term::Str(s.into())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for &str {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(self.to_string().into())
    }
}

impl TryFrom<Term> for String {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Str(s) => Ok(s),
            _ => Err(error::Token::ConversionError(format!(
                "expected string or symbol, got {:?}",
                value
            ))),
        }
    }
}

impl From<Vec<u8>> for Term {
    fn from(v: Vec<u8>) -> Self {
        Term::Bytes(v)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for Vec<u8> {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl TryFrom<Term> for Vec<u8> {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Bytes(b) => Ok(b),
            _ => Err(error::Token::ConversionError(format!(
                "expected byte array, got {:?}",
                value
            ))),
        }
    }
}

impl From<&[u8]> for Term {
    fn from(v: &[u8]) -> Self {
        Term::Bytes(v.into())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for [u8] {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(self.into())
    }
}

#[cfg(all(feature = "uuid", feature = "datalog-macro"))]
impl ToAnyParam for uuid::Uuid {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term(Term::Bytes(self.as_bytes().to_vec()))
    }
}

impl From<SystemTime> for Term {
    fn from(t: SystemTime) -> Self {
        let dur = t.duration_since(UNIX_EPOCH).unwrap();
        Term::Date(dur.as_secs())
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for SystemTime {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((*self).into())
    }
}

impl TryFrom<Term> for SystemTime {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Date(d) => Ok(UNIX_EPOCH + Duration::from_secs(d)),
            _ => Err(error::Token::ConversionError(format!(
                "expected date, got {:?}",
                value
            ))),
        }
    }
}

impl From<BTreeSet<Term>> for Term {
    fn from(value: BTreeSet<Term>) -> Term {
        set(value)
    }
}

#[cfg(feature = "datalog-macro")]
impl ToAnyParam for BTreeSet<Term> {
    fn to_any_param(&self) -> AnyParam {
        AnyParam::Term((self.clone()).into())
    }
}

impl<T: Ord + TryFrom<Term, Error = error::Token>> TryFrom<Term> for BTreeSet<T> {
    type Error = error::Token;
    fn try_from(value: Term) -> Result<Self, Self::Error> {
        match value {
            Term::Set(d) => d.iter().cloned().map(TryFrom::try_from).collect(),
            _ => Err(error::Token::ConversionError(format!(
                "expected set, got {:?}",
                value
            ))),
        }
    }
}

// TODO: From and ToAnyParam for arrays and maps
impl TryFrom<serde_json::Value> for Term {
    type Error = &'static str;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::Null => Ok(Term::Null),
            serde_json::Value::Bool(b) => Ok(Term::Bool(b)),
            serde_json::Value::Number(i) => match i.as_i64() {
                Some(i) => Ok(Term::Integer(i)),
                None => Err("Biscuit values do not support floating point numbers"),
            },
            serde_json::Value::String(s) => Ok(Term::Str(s)),
            serde_json::Value::Array(array) => Ok(Term::Array(
                array
                    .into_iter()
                    .map(|v| v.try_into())
                    .collect::<Result<_, _>>()?,
            )),
            serde_json::Value::Object(o) => Ok(Term::Map(
                o.into_iter()
                    .map(|(key, value)| {
                        let value: Term = value.try_into()?;
                        Ok::<_, &'static str>((MapKey::Str(key), value))
                    })
                    .collect::<Result<_, _>>()?,
            )),
        }
    }
}

macro_rules! tuple_try_from(
    ($ty1:ident, $ty2:ident, $($ty:ident),*) => (
        tuple_try_from!(__impl $ty1, $ty2; $($ty),*);
        );
    (__impl $($ty: ident),+; $ty1:ident, $($ty2:ident),*) => (
        tuple_try_from_impl!($($ty),+);
        tuple_try_from!(__impl $($ty),+ , $ty1; $($ty2),*);
        );
    (__impl $($ty: ident),+; $ty1:ident) => (
        tuple_try_from_impl!($($ty),+);
        tuple_try_from_impl!($($ty),+, $ty1);
        );
    );

impl<A: TryFrom<Term, Error = error::Token>> TryFrom<Fact> for (A,) {
    type Error = error::Token;
    fn try_from(fact: Fact) -> Result<Self, Self::Error> {
        let mut terms = fact.predicate.terms;
        let mut it = terms.drain(..);

        Ok((it
            .next()
            .ok_or_else(|| error::Token::ConversionError("not enough terms in fact".to_string()))
            .and_then(A::try_from)?,))
    }
}

macro_rules! tuple_try_from_impl(
    ($($ty: ident),+) => (
        impl<$($ty: TryFrom<Term, Error = error::Token>),+> TryFrom<Fact> for ($($ty),+) {
            type Error = error::Token;
            fn try_from(fact: Fact) -> Result<Self, Self::Error> {
                let mut terms = fact.predicate.terms;
                let mut it = terms.drain(..);

                Ok((
                        $(
                            it.next().ok_or(error::Token::ConversionError("not enough terms in fact".to_string())).and_then($ty::try_from)?
                         ),+
                   ))

            }
        }
        );
    );

tuple_try_from!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U);
