/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::{collections::HashMap, fmt};

use crate::{
    datalog::{self, SymbolTable},
    error,
    token::default_symbol_table,
};

use super::{Convert, Term};

/// Builder for a unary operation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unary {
    Negate,
    Parens,
    Length,
    TypeOf,
    Ffi(String),
}

/// Builder for a binary operation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Binary {
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    Contains,
    Prefix,
    Suffix,
    Regex,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Intersection,
    Union,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    NotEqual,
    HeterogeneousEqual,
    HeterogeneousNotEqual,
    LazyAnd,
    LazyOr,
    All,
    Any,
    Get,
    Ffi(String),
    TryOr,
}

/// Builder for a Datalog expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expression {
    pub ops: Vec<Op>,
}
// todo track parameters

impl Convert<datalog::Expression> for Expression {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Expression {
        datalog::Expression {
            ops: self.ops.iter().map(|op| op.convert(symbols)).collect(),
        }
    }

    fn convert_from(e: &datalog::Expression, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(Expression {
            ops: e
                .ops
                .iter()
                .map(|op| Op::convert_from(op, symbols))
                .collect::<Result<Vec<_>, error::Format>>()?,
        })
    }
}

impl AsRef<Expression> for Expression {
    fn as_ref(&self) -> &Expression {
        self
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut syms = default_symbol_table();
        let expr = self.convert(&mut syms);
        let s = expr.print(&syms).unwrap();
        write!(f, "{s}")
    }
}

impl From<biscuit_parser::builder::Expression> for Expression {
    fn from(e: biscuit_parser::builder::Expression) -> Self {
        Expression {
            ops: e.ops.into_iter().map(|op| op.into()).collect(),
        }
    }
}

/// Builder for an expression operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Value(Term),
    Unary(Unary),
    Binary(Binary),
    Closure(Vec<String>, Vec<Op>),
}

impl Op {
    pub(super) fn collect_parameters(&self, parameters: &mut HashMap<String, Option<Term>>) {
        match self {
            Op::Value(Term::Parameter(ref name)) => {
                parameters.insert(name.to_owned(), None);
            }
            Op::Closure(_, ops) => {
                for op in ops {
                    op.collect_parameters(parameters);
                }
            }
            _ => {}
        }
    }

    pub(super) fn apply_parameters(self, parameters: &HashMap<String, Option<Term>>) -> Self {
        match self {
            Op::Value(Term::Parameter(ref name)) => {
                if let Some(Some(t)) = parameters.get(name) {
                    Op::Value(t.clone())
                } else {
                    self
                }
            }
            Op::Value(_) => self,
            Op::Unary(_) => self,
            Op::Binary(_) => self,
            Op::Closure(args, mut ops) => Op::Closure(
                args,
                ops.drain(..)
                    .map(|op| op.apply_parameters(parameters))
                    .collect(),
            ),
        }
    }
}

impl Convert<datalog::Op> for Op {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Op {
        match self {
            Op::Value(t) => datalog::Op::Value(t.convert(symbols)),
            Op::Unary(u) => datalog::Op::Unary(u.convert(symbols)),
            Op::Binary(b) => datalog::Op::Binary(b.convert(symbols)),
            Op::Closure(ps, os) => datalog::Op::Closure(
                ps.iter().map(|p| symbols.insert(p) as u32).collect(),
                os.iter().map(|o| o.convert(symbols)).collect(),
            ),
        }
    }

    fn convert_from(op: &datalog::Op, symbols: &SymbolTable) -> Result<Self, error::Format> {
        Ok(match op {
            datalog::Op::Value(t) => Op::Value(Term::convert_from(t, symbols)?),
            datalog::Op::Unary(u) => Op::Unary(Unary::convert_from(u, symbols)?),
            datalog::Op::Binary(b) => Op::Binary(Binary::convert_from(b, symbols)?),
            datalog::Op::Closure(ps, os) => Op::Closure(
                ps.iter()
                    .map(|p| symbols.print_symbol(*p as u64))
                    .collect::<Result<_, _>>()?,
                os.iter()
                    .map(|o| Op::convert_from(o, symbols))
                    .collect::<Result<_, _>>()?,
            ),
        })
    }
}

impl From<biscuit_parser::builder::Op> for Op {
    fn from(op: biscuit_parser::builder::Op) -> Self {
        match op {
            biscuit_parser::builder::Op::Value(t) => Op::Value(t.into()),
            biscuit_parser::builder::Op::Unary(u) => Op::Unary(u.into()),
            biscuit_parser::builder::Op::Binary(b) => Op::Binary(b.into()),
            biscuit_parser::builder::Op::Closure(ps, os) => {
                Op::Closure(ps, os.into_iter().map(|o| o.into()).collect())
            }
        }
    }
}

impl Convert<datalog::Unary> for Unary {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Unary {
        match self {
            Unary::Negate => datalog::Unary::Negate,
            Unary::Parens => datalog::Unary::Parens,
            Unary::Length => datalog::Unary::Length,
            Unary::TypeOf => datalog::Unary::TypeOf,
            Unary::Ffi(n) => datalog::Unary::Ffi(symbols.insert(n)),
        }
    }

    fn convert_from(f: &datalog::Unary, symbols: &SymbolTable) -> Result<Self, error::Format> {
        match f {
            datalog::Unary::Negate => Ok(Unary::Negate),
            datalog::Unary::Parens => Ok(Unary::Parens),
            datalog::Unary::Length => Ok(Unary::Length),
            datalog::Unary::TypeOf => Ok(Unary::TypeOf),
            datalog::Unary::Ffi(i) => Ok(Unary::Ffi(symbols.print_symbol(*i)?)),
        }
    }
}

impl From<biscuit_parser::builder::Unary> for Unary {
    fn from(unary: biscuit_parser::builder::Unary) -> Self {
        match unary {
            biscuit_parser::builder::Unary::Negate => Unary::Negate,
            biscuit_parser::builder::Unary::Parens => Unary::Parens,
            biscuit_parser::builder::Unary::Length => Unary::Length,
            biscuit_parser::builder::Unary::TypeOf => Unary::TypeOf,
            biscuit_parser::builder::Unary::Ffi(name) => Unary::Ffi(name),
        }
    }
}

impl Convert<datalog::Binary> for Binary {
    fn convert(&self, symbols: &mut SymbolTable) -> datalog::Binary {
        match self {
            Binary::LessThan => datalog::Binary::LessThan,
            Binary::GreaterThan => datalog::Binary::GreaterThan,
            Binary::LessOrEqual => datalog::Binary::LessOrEqual,
            Binary::GreaterOrEqual => datalog::Binary::GreaterOrEqual,
            Binary::Equal => datalog::Binary::Equal,
            Binary::Contains => datalog::Binary::Contains,
            Binary::Prefix => datalog::Binary::Prefix,
            Binary::Suffix => datalog::Binary::Suffix,
            Binary::Regex => datalog::Binary::Regex,
            Binary::Add => datalog::Binary::Add,
            Binary::Sub => datalog::Binary::Sub,
            Binary::Mul => datalog::Binary::Mul,
            Binary::Div => datalog::Binary::Div,
            Binary::And => datalog::Binary::And,
            Binary::Or => datalog::Binary::Or,
            Binary::Intersection => datalog::Binary::Intersection,
            Binary::Union => datalog::Binary::Union,
            Binary::BitwiseAnd => datalog::Binary::BitwiseAnd,
            Binary::BitwiseOr => datalog::Binary::BitwiseOr,
            Binary::BitwiseXor => datalog::Binary::BitwiseXor,
            Binary::NotEqual => datalog::Binary::NotEqual,
            Binary::HeterogeneousEqual => datalog::Binary::HeterogeneousEqual,
            Binary::HeterogeneousNotEqual => datalog::Binary::HeterogeneousNotEqual,
            Binary::LazyAnd => datalog::Binary::LazyAnd,
            Binary::LazyOr => datalog::Binary::LazyOr,
            Binary::All => datalog::Binary::All,
            Binary::Any => datalog::Binary::Any,
            Binary::Get => datalog::Binary::Get,
            Binary::Ffi(n) => datalog::Binary::Ffi(symbols.insert(n)),
            Binary::TryOr => datalog::Binary::TryOr,
        }
    }

    fn convert_from(f: &datalog::Binary, symbols: &SymbolTable) -> Result<Self, error::Format> {
        match f {
            datalog::Binary::LessThan => Ok(Binary::LessThan),
            datalog::Binary::GreaterThan => Ok(Binary::GreaterThan),
            datalog::Binary::LessOrEqual => Ok(Binary::LessOrEqual),
            datalog::Binary::GreaterOrEqual => Ok(Binary::GreaterOrEqual),
            datalog::Binary::Equal => Ok(Binary::Equal),
            datalog::Binary::Contains => Ok(Binary::Contains),
            datalog::Binary::Prefix => Ok(Binary::Prefix),
            datalog::Binary::Suffix => Ok(Binary::Suffix),
            datalog::Binary::Regex => Ok(Binary::Regex),
            datalog::Binary::Add => Ok(Binary::Add),
            datalog::Binary::Sub => Ok(Binary::Sub),
            datalog::Binary::Mul => Ok(Binary::Mul),
            datalog::Binary::Div => Ok(Binary::Div),
            datalog::Binary::And => Ok(Binary::And),
            datalog::Binary::Or => Ok(Binary::Or),
            datalog::Binary::Intersection => Ok(Binary::Intersection),
            datalog::Binary::Union => Ok(Binary::Union),
            datalog::Binary::BitwiseAnd => Ok(Binary::BitwiseAnd),
            datalog::Binary::BitwiseOr => Ok(Binary::BitwiseOr),
            datalog::Binary::BitwiseXor => Ok(Binary::BitwiseXor),
            datalog::Binary::NotEqual => Ok(Binary::NotEqual),
            datalog::Binary::HeterogeneousEqual => Ok(Binary::HeterogeneousEqual),
            datalog::Binary::HeterogeneousNotEqual => Ok(Binary::HeterogeneousNotEqual),
            datalog::Binary::LazyAnd => Ok(Binary::LazyAnd),
            datalog::Binary::LazyOr => Ok(Binary::LazyOr),
            datalog::Binary::All => Ok(Binary::All),
            datalog::Binary::Any => Ok(Binary::Any),
            datalog::Binary::Get => Ok(Binary::Get),
            datalog::Binary::Ffi(i) => Ok(Binary::Ffi(symbols.print_symbol(*i)?)),
            datalog::Binary::TryOr => Ok(Binary::TryOr),
        }
    }
}

impl From<biscuit_parser::builder::Binary> for Binary {
    fn from(binary: biscuit_parser::builder::Binary) -> Self {
        match binary {
            biscuit_parser::builder::Binary::LessThan => Binary::LessThan,
            biscuit_parser::builder::Binary::GreaterThan => Binary::GreaterThan,
            biscuit_parser::builder::Binary::LessOrEqual => Binary::LessOrEqual,
            biscuit_parser::builder::Binary::GreaterOrEqual => Binary::GreaterOrEqual,
            biscuit_parser::builder::Binary::Equal => Binary::Equal,
            biscuit_parser::builder::Binary::Contains => Binary::Contains,
            biscuit_parser::builder::Binary::Prefix => Binary::Prefix,
            biscuit_parser::builder::Binary::Suffix => Binary::Suffix,
            biscuit_parser::builder::Binary::Regex => Binary::Regex,
            biscuit_parser::builder::Binary::Add => Binary::Add,
            biscuit_parser::builder::Binary::Sub => Binary::Sub,
            biscuit_parser::builder::Binary::Mul => Binary::Mul,
            biscuit_parser::builder::Binary::Div => Binary::Div,
            biscuit_parser::builder::Binary::And => Binary::And,
            biscuit_parser::builder::Binary::Or => Binary::Or,
            biscuit_parser::builder::Binary::Intersection => Binary::Intersection,
            biscuit_parser::builder::Binary::Union => Binary::Union,
            biscuit_parser::builder::Binary::BitwiseAnd => Binary::BitwiseAnd,
            biscuit_parser::builder::Binary::BitwiseOr => Binary::BitwiseOr,
            biscuit_parser::builder::Binary::BitwiseXor => Binary::BitwiseXor,
            biscuit_parser::builder::Binary::NotEqual => Binary::NotEqual,
            biscuit_parser::builder::Binary::HeterogeneousEqual => Binary::HeterogeneousEqual,
            biscuit_parser::builder::Binary::HeterogeneousNotEqual => Binary::HeterogeneousNotEqual,
            biscuit_parser::builder::Binary::LazyAnd => Binary::LazyAnd,
            biscuit_parser::builder::Binary::LazyOr => Binary::LazyOr,
            biscuit_parser::builder::Binary::All => Binary::All,
            biscuit_parser::builder::Binary::Any => Binary::Any,
            biscuit_parser::builder::Binary::Get => Binary::Get,
            biscuit_parser::builder::Binary::Ffi(name) => Binary::Ffi(name),
            biscuit_parser::builder::Binary::TryOr => Binary::TryOr,
        }
    }
}
