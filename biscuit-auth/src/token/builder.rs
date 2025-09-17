/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! helper functions and structure to create tokens and blocks

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

// reexport those because the builder uses the same definitions
use super::Block;
use crate::crypto::PublicKey;
use crate::datalog::SymbolTable;
pub use crate::datalog::{
    Binary as DatalogBinary, Expression as DatalogExpression, Op as DatalogOp,
    Unary as DatalogUnary,
};
use crate::error;

mod algorithm;
mod authorizer;
mod biscuit;
mod block;
mod check;
mod expression;
mod fact;
mod policy;
mod predicate;
mod rule;
mod scope;
mod term;

pub use algorithm::*;
pub use authorizer::*;
pub use biscuit::*;
pub use block::*;
pub use check::*;
pub use expression::*;
pub use fact::*;
pub use policy::*;
pub use predicate::*;
pub use rule::*;
pub use scope::*;
pub use term::*;

pub trait Convert<T>: Sized {
    fn convert(&self, symbols: &mut SymbolTable) -> T;
    fn convert_from(f: &T, symbols: &SymbolTable) -> Result<Self, error::Format>;
    fn translate(
        f: &T,
        from_symbols: &SymbolTable,
        to_symbols: &mut SymbolTable,
    ) -> Result<T, error::Format> {
        Ok(Self::convert_from(f, from_symbols)?.convert(to_symbols))
    }
}

/// creates a new fact
pub fn fact<I: AsRef<Term>>(name: &str, terms: &[I]) -> Fact {
    let pred = pred(name, terms);
    Fact::new(pred.name, pred.terms)
}

/// creates a predicate
pub fn pred<I: AsRef<Term>>(name: &str, terms: &[I]) -> Predicate {
    Predicate {
        name: name.to_string(),
        terms: terms.iter().map(|term| term.as_ref().clone()).collect(),
    }
}

/// creates a rule
pub fn rule<T: AsRef<Term>, P: AsRef<Predicate>>(
    head_name: &str,
    head_terms: &[T],
    predicates: &[P],
) -> Rule {
    Rule::new(
        pred(head_name, head_terms),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        Vec::new(),
        vec![],
    )
}

/// creates a rule with constraints
pub fn constrained_rule<T: AsRef<Term>, P: AsRef<Predicate>, E: AsRef<Expression>>(
    head_name: &str,
    head_terms: &[T],
    predicates: &[P],
    expressions: &[E],
) -> Rule {
    Rule::new(
        pred(head_name, head_terms),
        predicates.iter().map(|p| p.as_ref().clone()).collect(),
        expressions.iter().map(|c| c.as_ref().clone()).collect(),
        vec![],
    )
}

/// creates a check
pub fn check<P: AsRef<Predicate>>(predicates: &[P], kind: CheckKind) -> Check {
    let empty_terms: &[Term] = &[];
    Check {
        queries: vec![Rule::new(
            pred("query", empty_terms),
            predicates.iter().map(|p| p.as_ref().clone()).collect(),
            vec![],
            vec![],
        )],
        kind,
    }
}

/// creates an integer value
pub fn int(i: i64) -> Term {
    Term::Integer(i)
}

/// creates a string
pub fn string(s: &str) -> Term {
    Term::Str(s.to_string())
}

/// creates a date
///
/// internally the date will be stored as seconds since UNIX_EPOCH
pub fn date(t: &SystemTime) -> Term {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    Term::Date(dur.as_secs())
}

/// creates a variable for a rule
pub fn var(s: &str) -> Term {
    Term::Variable(s.to_string())
}

/// creates a variable for a rule
pub fn variable(s: &str) -> Term {
    Term::Variable(s.to_string())
}

/// creates a byte array
pub fn bytes(s: &[u8]) -> Term {
    Term::Bytes(s.to_vec())
}

/// creates a boolean
pub fn boolean(b: bool) -> Term {
    Term::Bool(b)
}

/// creates a set
pub fn set(s: BTreeSet<Term>) -> Term {
    Term::Set(s)
}

/// creates a parameter
pub fn parameter(p: &str) -> Term {
    Term::Parameter(p.to_string())
}

#[cfg(feature = "datalog-macro")]
pub enum AnyParam {
    Term(Term),
    PublicKey(PublicKey),
}

#[cfg(feature = "datalog-macro")]
pub trait ToAnyParam {
    fn to_any_param(&self) -> AnyParam;
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, convert::TryFrom};

    use super::*;

    #[test]
    fn set_rule_parameters() {
        let mut rule = Rule::try_from(
            "fact($var1, {p2}, {p5}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        rule.set("p4", 0i64).unwrap();
        rule.set("p4", 1i64).unwrap();

        let mut term_set = BTreeSet::new();
        term_set.insert(int(0i64));
        rule.set("p5", term_set).unwrap();

        let s = rule.to_string();
        assert_eq!(s, "fact($var1, \"hello\", {0}) <- f1($var1, $var3), f2(\"hello\", $var3, 1), $var3.starts_with(\"hello\")");
    }

    #[test]
    fn set_closure_parameters() {
        let mut rule = Rule::try_from("fact(true) <- false || {p1}").unwrap();
        rule.set_lenient("p1", true).unwrap();
        println!("{rule:?}");
        let s = rule.to_string();
        assert_eq!(s, "fact(true) <- false || true");

        let mut rule = Rule::try_from("fact(true) <- false || {p1}").unwrap();
        rule.set("p1", true).unwrap();
        let s = rule.to_string();
        assert_eq!(s, "fact(true) <- false || true");
    }

    #[test]
    fn set_rule_scope_parameters() {
        let pubkey = PublicKey::from_bytes(
            &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                .unwrap(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2}) trusting {pk}",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        rule.set("p4", 0i64).unwrap();
        rule.set("p4", 1i64).unwrap();
        rule.set_scope("pk", pubkey).unwrap();

        let s = rule.to_string();
        assert_eq!(s, "fact($var1, \"hello\") <- f1($var1, $var3), f2(\"hello\", $var3, 1), $var3.starts_with(\"hello\") trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db");
    }

    #[test]
    fn set_code_parameters() {
        let mut builder = BlockBuilder::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "hello".into());
        params.insert("p2".to_string(), 1i64.into());
        params.insert("p3".to_string(), true.into());
        params.insert("p4".to_string(), "this will be ignored".into());
        let pubkey = PublicKey::from_bytes(
            &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                .unwrap(),
            Algorithm::Ed25519,
        )
        .unwrap();
        let mut scope_params = HashMap::new();
        scope_params.insert("pk".to_string(), pubkey);
        builder = builder
            .code_with_params(
                r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0 trusting {pk};
             check if {p3} trusting {pk};
            "#,
                params,
                scope_params,
            )
            .unwrap();
        assert_eq!(
            format!("{}", &builder),
            r#"fact("hello", "value");
rule($head_var) <- f1($head_var), 1 > 0 trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
"#
        );
    }

    #[test]
    fn forbid_unbound_parameters() {
        let builder = BlockBuilder::new();

        let mut fact = Fact::try_from("fact({p1}, {p4})").unwrap();
        fact.set("p1", "hello").unwrap();
        let res = builder.clone().fact(fact);
        assert_eq!(
            res.unwrap_err(),
            error::Token::Language(biscuit_parser::error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            })
        );
        let mut rule = Rule::try_from(
            "fact($var1, {p2}) <- f1($var1, $var3), f2({p2}, $var3, {p4}), $var3.starts_with({p2})",
        )
        .unwrap();
        rule.set("p2", "hello").unwrap();
        let res = builder.clone().rule(rule);
        assert_eq!(
            res.unwrap_err(),
            error::Token::Language(biscuit_parser::error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            })
        );
        let mut check = Check::try_from("check if {p4}, {p3}").unwrap();
        check.set("p3", true).unwrap();
        let res = builder.clone().check(check);
        assert_eq!(
            res.unwrap_err(),
            error::Token::Language(biscuit_parser::error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            })
        );
    }

    #[test]
    fn forbid_unbound_parameters_in_set_code() {
        let builder = BlockBuilder::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "hello".into());
        params.insert("p2".to_string(), 1i64.into());
        params.insert("p4".to_string(), "this will be ignored".into());
        let res = builder.code_with_params(
            r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0;
             check if {p3};
            "#,
            params,
            HashMap::new(),
        );

        assert_eq!(
            res.unwrap_err(),
            error::Token::Language(biscuit_parser::error::LanguageError::Parameters {
                missing_parameters: vec!["p3".to_string()],
                unused_parameters: vec![],
            })
        );
    }
    #[test]
    fn empty_set_display() {
        assert_eq!(Term::Set(BTreeSet::new()).to_string(), "{,}");
    }
}
