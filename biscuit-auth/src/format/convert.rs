/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! helper functions for conversion between internal structures and Protobuf

use super::schema;
use crate::builder::Convert;
use crate::crypto::PublicKey;
use crate::datalog::*;
use crate::error;
use crate::format::schema::Empty;
use crate::format::schema::MapEntry;
use crate::token::public_keys::PublicKeys;
use crate::token::Scope;
use crate::token::{authorizer::AuthorizerPolicies, Block};
use crate::token::{DATALOG_3_1, DATALOG_3_2, DATALOG_3_3, MAX_SCHEMA_VERSION, MIN_SCHEMA_VERSION};

use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub fn token_block_to_proto_block(input: &Block) -> schema::Block {
    schema::Block {
        symbols: input.symbols.strings(),
        context: input.context.clone(),
        version: Some(input.version),
        facts: input.facts.iter().map(token_fact_to_proto_fact).collect(),
        rules: input.rules.iter().map(token_rule_to_proto_rule).collect(),
        checks: input
            .checks
            .iter()
            .map(token_check_to_proto_check)
            .collect(),
        scope: input
            .scopes
            .iter()
            .map(token_scope_to_proto_scope)
            .collect(),
        public_keys: input
            .public_keys
            .keys
            .iter()
            .map(|key| key.to_proto())
            .collect(),
    }
}

pub fn proto_block_to_token_block(
    input: &schema::Block,
    external_key: Option<PublicKey>,
) -> Result<Block, error::Format> {
    let version = input.version.unwrap_or(0);
    if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
        return Err(error::Format::Version {
            minimum: crate::token::MIN_SCHEMA_VERSION,
            maximum: crate::token::MAX_SCHEMA_VERSION,
            actual: version,
        });
    }

    let mut facts = vec![];
    let mut rules = vec![];
    let mut checks = vec![];
    let mut scopes = vec![];
    for fact in input.facts.iter() {
        facts.push(proto_fact_to_token_fact(fact)?);
    }

    for rule in input.rules.iter() {
        rules.push(proto_rule_to_token_rule(rule, version)?.0);
    }

    if version < MAX_SCHEMA_VERSION {
        for c in input.checks.iter() {
            if version < DATALOG_3_1 && c.kind.is_some() {
                return Err(error::Format::DeserializationError(
                    "deserialization error: check kinds are only supported on datalog v3.1+ blocks"
                        .to_string(),
                ));
            } else if version < DATALOG_3_3 && c.kind == Some(schema::check::Kind::Reject as i32) {
                return Err(error::Format::DeserializationError(
                    "deserialization error: reject if is only supported in datalog v3.3+"
                        .to_string(),
                ));
            }
        }
    }

    if version < DATALOG_3_2 && external_key.is_some() {
        return Err(error::Format::DeserializationError(
            "deserialization error: third-party blocks are only supported in datalog v3.2+"
                .to_string(),
        ));
    }

    for check in input.checks.iter() {
        checks.push(proto_check_to_token_check(check, version)?);
    }
    for scope in input.scope.iter() {
        scopes.push(proto_scope_to_token_scope(scope)?);
    }

    let context = input.context.clone();

    let mut public_keys = PublicKeys::new();
    for pk in &input.public_keys {
        public_keys.insert_fallible(&PublicKey::from_proto(pk)?)?;
    }
    let symbols =
        SymbolTable::from_symbols_and_public_keys(input.symbols.clone(), public_keys.keys.clone())?;

    let detected_schema_version = get_schema_version(&facts, &rules, &checks, &scopes);

    detected_schema_version.check_compatibility(version)?;

    Ok(Block {
        symbols,
        facts,
        rules,
        checks,
        context,
        version,
        external_key,
        public_keys,
        scopes,
    })
}

pub fn token_block_to_proto_snapshot_block(input: &Block) -> schema::SnapshotBlock {
    schema::SnapshotBlock {
        context: input.context.clone(),
        version: Some(input.version),
        facts: input.facts.iter().map(token_fact_to_proto_fact).collect(),
        rules: input.rules.iter().map(token_rule_to_proto_rule).collect(),
        checks: input
            .checks
            .iter()
            .map(token_check_to_proto_check)
            .collect(),
        scope: input
            .scopes
            .iter()
            .map(token_scope_to_proto_scope)
            .collect(),
        external_key: input.external_key.map(|key| key.to_proto()),
    }
}

pub fn proto_snapshot_block_to_token_block(
    input: &schema::SnapshotBlock,
) -> Result<Block, error::Format> {
    let version = input.version.unwrap_or(0);
    if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
        return Err(error::Format::Version {
            minimum: crate::token::MIN_SCHEMA_VERSION,
            maximum: crate::token::MAX_SCHEMA_VERSION,
            actual: version,
        });
    }

    let mut facts = vec![];
    let mut rules = vec![];
    let mut checks = vec![];
    let mut scopes = vec![];
    for fact in input.facts.iter() {
        facts.push(proto_fact_to_token_fact(fact)?);
    }

    for rule in input.rules.iter() {
        rules.push(proto_rule_to_token_rule(rule, version)?.0);
    }

    if version == MIN_SCHEMA_VERSION && input.checks.iter().any(|c| c.kind.is_some()) {
        return Err(error::Format::DeserializationError(
            "deserialization error: v3 blocks must not contain a check kind".to_string(),
        ));
    }

    for check in input.checks.iter() {
        checks.push(proto_check_to_token_check(check, version)?);
    }
    for scope in input.scope.iter() {
        scopes.push(proto_scope_to_token_scope(scope)?);
    }

    let context = input.context.clone();

    let detected_schema_version = get_schema_version(&facts, &rules, &checks, &scopes);

    detected_schema_version.check_compatibility(version)?;

    let external_key = match &input.external_key {
        None => None,
        Some(key) => Some(PublicKey::from_proto(key)?),
    };

    Ok(Block {
        symbols: SymbolTable::new(),
        facts,
        rules,
        checks,
        context,
        version,
        external_key,
        public_keys: PublicKeys::default(),
        scopes,
    })
}
pub fn authorizer_to_proto_authorizer(input: &AuthorizerPolicies) -> schema::AuthorizerPolicies {
    let mut symbols = SymbolTable::default();

    let facts = input
        .facts
        .iter()
        .map(|f| f.convert(&mut symbols))
        .map(|f| token_fact_to_proto_fact(&f))
        .collect();

    let rules = input
        .rules
        .iter()
        .map(|r| r.convert(&mut symbols))
        .map(|r| token_rule_to_proto_rule(&r))
        .collect();

    let checks = input
        .checks
        .iter()
        .map(|c| c.convert(&mut symbols))
        .map(|c| token_check_to_proto_check(&c))
        .collect();

    let policies = input
        .policies
        .iter()
        .map(|p| policy_to_proto_policy(p, &mut symbols))
        .collect();

    schema::AuthorizerPolicies {
        symbols: symbols.strings(),
        version: Some(input.version),
        facts,
        rules,
        checks,
        policies,
    }
}

pub fn proto_authorizer_to_authorizer(
    input: &schema::AuthorizerPolicies,
) -> Result<AuthorizerPolicies, error::Format> {
    let version = input.version.unwrap_or(0);
    if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
        return Err(error::Format::Version {
            minimum: crate::token::MIN_SCHEMA_VERSION,
            maximum: crate::token::MAX_SCHEMA_VERSION,
            actual: version,
        });
    }

    let symbols = SymbolTable::from(input.symbols.clone())?;

    let mut facts = vec![];
    let mut rules = vec![];
    let mut checks = vec![];
    let mut policies = vec![];

    for fact in input.facts.iter() {
        facts.push(crate::builder::Fact::convert_from(
            &proto_fact_to_token_fact(fact)?,
            &symbols,
        )?);
    }

    for rule in input.rules.iter() {
        rules.push(crate::builder::Rule::convert_from(
            &proto_rule_to_token_rule(rule, version)?.0,
            &symbols,
        )?);
    }

    for check in input.checks.iter() {
        checks.push(crate::builder::Check::convert_from(
            &proto_check_to_token_check(check, version)?,
            &symbols,
        )?);
    }

    for policy in input.policies.iter() {
        policies.push(proto_policy_to_policy(policy, &symbols, version)?);
    }

    Ok(AuthorizerPolicies {
        version,
        facts,
        rules,
        checks,
        policies,
    })
}

pub fn token_fact_to_proto_fact(input: &Fact) -> schema::Fact {
    schema::Fact {
        predicate: token_predicate_to_proto_predicate(&input.predicate),
    }
}

pub fn proto_fact_to_token_fact(input: &schema::Fact) -> Result<Fact, error::Format> {
    Ok(Fact {
        predicate: proto_predicate_to_token_predicate(&input.predicate)?,
    })
}

pub fn token_check_to_proto_check(input: &Check) -> schema::Check {
    use schema::check::Kind;

    schema::Check {
        queries: input.queries.iter().map(token_rule_to_proto_rule).collect(),
        kind: match input.kind {
            crate::token::builder::CheckKind::One => None,
            crate::token::builder::CheckKind::All => Some(Kind::All as i32),
            crate::token::builder::CheckKind::Reject => Some(Kind::Reject as i32),
        },
    }
}

pub fn proto_check_to_token_check(
    input: &schema::Check,
    version: u32,
) -> Result<Check, error::Format> {
    let mut queries = vec![];

    for q in input.queries.iter() {
        queries.push(proto_rule_to_token_rule(q, version)?.0);
    }

    let kind = match input.kind {
        None | Some(0) => crate::token::builder::CheckKind::One,
        Some(1) => crate::token::builder::CheckKind::All,
        Some(2) => crate::token::builder::CheckKind::Reject,
        _ => {
            return Err(error::Format::DeserializationError(
                "deserialization error: invalid check kind".to_string(),
            ))
        }
    };

    Ok(Check { queries, kind })
}

pub fn policy_to_proto_policy(
    input: &crate::token::builder::Policy,
    symbols: &mut SymbolTable,
) -> schema::Policy {
    schema::Policy {
        queries: input
            .queries
            .iter()
            .map(|q| q.convert(symbols))
            .map(|r| token_rule_to_proto_rule(&r))
            .collect(),
        kind: match input.kind {
            crate::token::builder::PolicyKind::Allow => schema::policy::Kind::Allow as i32,
            crate::token::builder::PolicyKind::Deny => schema::policy::Kind::Deny as i32,
        },
    }
}

pub fn proto_policy_to_policy(
    input: &schema::Policy,
    symbols: &SymbolTable,
    version: u32,
) -> Result<crate::token::builder::Policy, error::Format> {
    use schema::policy::Kind;
    let mut queries = vec![];

    for q in input.queries.iter() {
        let (c, _scopes) = proto_rule_to_token_rule(q, version)?;
        let c = crate::token::builder::Rule::convert_from(&c, symbols)?;
        queries.push(c);
    }

    let kind = if let Some(i) = Kind::from_i32(input.kind) {
        i
    } else {
        return Err(error::Format::DeserializationError(
            "deserialization error: invalid policy kind".to_string(),
        ));
    };

    let kind = match kind {
        Kind::Allow => crate::token::builder::PolicyKind::Allow,
        Kind::Deny => crate::token::builder::PolicyKind::Deny,
    };

    Ok(crate::token::builder::Policy { queries, kind })
}

pub fn token_rule_to_proto_rule(input: &Rule) -> schema::Rule {
    schema::Rule {
        head: token_predicate_to_proto_predicate(&input.head),
        body: input
            .body
            .iter()
            .map(token_predicate_to_proto_predicate)
            .collect(),
        expressions: input
            .expressions
            .iter()
            .map(token_expression_to_proto_expression)
            .collect(),
        scope: input
            .scopes
            .iter()
            .map(token_scope_to_proto_scope)
            .collect(),
    }
}

pub fn proto_rule_to_token_rule(
    input: &schema::Rule,
    version: u32,
) -> Result<(Rule, Vec<Scope>), error::Format> {
    let mut body = vec![];

    for p in input.body.iter() {
        body.push(proto_predicate_to_token_predicate(p)?);
    }

    let mut expressions = vec![];

    for c in input.expressions.iter() {
        expressions.push(proto_expression_to_token_expression(c)?);
    }

    if version < DATALOG_3_1 && !input.scope.is_empty() {
        return Err(error::Format::DeserializationError(
            "deserialization error: scopes are only supported in datalog v3.1+".to_string(),
        ));
    }

    let scopes: Result<Vec<_>, _> = input.scope.iter().map(proto_scope_to_token_scope).collect();
    let scopes = scopes?;

    Ok((
        Rule {
            head: proto_predicate_to_token_predicate(&input.head)?,
            body,
            expressions,
            scopes: scopes.clone(),
        },
        scopes,
    ))
}

pub fn token_predicate_to_proto_predicate(input: &Predicate) -> schema::Predicate {
    schema::Predicate {
        name: input.name,
        terms: input.terms.iter().map(token_term_to_proto_id).collect(),
    }
}

pub fn proto_predicate_to_token_predicate(
    input: &schema::Predicate,
) -> Result<Predicate, error::Format> {
    let mut terms = vec![];

    for term in input.terms.iter() {
        terms.push(proto_id_to_token_term(term)?);
    }

    Ok(Predicate {
        name: input.name,
        terms,
    })
}

pub fn token_term_to_proto_id(input: &Term) -> schema::Term {
    use schema::term::Content;

    match input {
        Term::Variable(v) => schema::Term {
            content: Some(Content::Variable(*v)),
        },
        Term::Integer(i) => schema::Term {
            content: Some(Content::Integer(*i)),
        },
        Term::Str(s) => schema::Term {
            content: Some(Content::String(*s)),
        },
        Term::Date(d) => schema::Term {
            content: Some(Content::Date(*d)),
        },
        Term::Bytes(s) => schema::Term {
            content: Some(Content::Bytes(s.clone())),
        },
        Term::Bool(b) => schema::Term {
            content: Some(Content::Bool(*b)),
        },
        Term::Set(s) => schema::Term {
            content: Some(Content::Set(schema::TermSet {
                set: s.iter().map(token_term_to_proto_id).collect(),
            })),
        },
        Term::Null => schema::Term {
            content: Some(Content::Null(Empty {})),
        },
        Term::Array(a) => schema::Term {
            content: Some(Content::Array(schema::Array {
                array: a.iter().map(token_term_to_proto_id).collect(),
            })),
        },
        Term::Map(m) => schema::Term {
            content: Some(Content::Map(schema::Map {
                entries: m
                    .iter()
                    .map(|(key, term)| {
                        let key = match key {
                            MapKey::Integer(i) => schema::MapKey {
                                content: Some(schema::map_key::Content::Integer(*i)),
                            },
                            MapKey::Str(s) => schema::MapKey {
                                content: Some(schema::map_key::Content::String(*s)),
                            },
                        };
                        schema::MapEntry {
                            key,
                            value: token_term_to_proto_id(term),
                        }
                    })
                    .collect(),
            })),
        },
    }
}

pub fn proto_id_to_token_term(input: &schema::Term) -> Result<Term, error::Format> {
    use schema::term::Content;

    match &input.content {
        None => Err(error::Format::DeserializationError(
            "deserialization error: ID content enum is empty".to_string(),
        )),
        Some(Content::Variable(i)) => Ok(Term::Variable(*i)),
        Some(Content::Integer(i)) => Ok(Term::Integer(*i)),
        Some(Content::String(s)) => Ok(Term::Str(*s)),
        Some(Content::Date(i)) => Ok(Term::Date(*i)),
        Some(Content::Bytes(s)) => Ok(Term::Bytes(s.clone())),
        Some(Content::Bool(b)) => Ok(Term::Bool(*b)),
        Some(Content::Set(s)) => {
            let mut kind: Option<u8> = None;
            let mut set = BTreeSet::new();

            for i in s.set.iter() {
                let index = match i.content {
                    Some(Content::Variable(_)) => {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: sets cannot contain variables".to_string(),
                        ));
                    }
                    Some(Content::Integer(_)) => 2,
                    Some(Content::String(_)) => 3,
                    Some(Content::Date(_)) => 4,
                    Some(Content::Bytes(_)) => 5,
                    Some(Content::Bool(_)) => 6,
                    Some(Content::Set(_)) => {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: sets cannot contain other sets".to_string(),
                        ));
                    }
                    Some(Content::Null(_)) => 8,
                    Some(Content::Array(_)) => 9,
                    Some(Content::Map(_)) => 10,
                    None => {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: ID content enum is empty".to_string(),
                        ))
                    }
                };

                if let Some(k) = kind.as_ref() {
                    if *k != index {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: sets elements must have the same type"
                                .to_string(),
                        ));
                    }
                } else {
                    kind = Some(index);
                }

                set.insert(proto_id_to_token_term(i)?);
            }

            Ok(Term::Set(set))
        }
        Some(Content::Null(_)) => Ok(Term::Null),
        Some(Content::Array(a)) => {
            let array = a
                .array
                .iter()
                .map(proto_id_to_token_term)
                .collect::<Result<_, _>>()?;

            Ok(Term::Array(array))
        }
        Some(Content::Map(m)) => {
            let mut map = BTreeMap::new();

            for MapEntry { key, value } in m.entries.iter() {
                let key = match key.content {
                    Some(schema::map_key::Content::Integer(i)) => MapKey::Integer(i),
                    Some(schema::map_key::Content::String(s)) => MapKey::Str(s),
                    None => {
                        return Err(error::Format::DeserializationError(
                            "deserialization error: ID content enum is empty".to_string(),
                        ))
                    }
                };

                map.insert(key, proto_id_to_token_term(&value)?);
            }

            Ok(Term::Map(map))
        }
    }
}

fn token_op_to_proto_op(op: &Op) -> schema::Op {
    let content = match op {
        Op::Value(i) => schema::op::Content::Value(token_term_to_proto_id(i)),
        Op::Unary(u) => {
            use schema::op_unary::Kind;

            schema::op::Content::Unary(schema::OpUnary {
                kind: match u {
                    Unary::Negate => Kind::Negate,
                    Unary::Parens => Kind::Parens,
                    Unary::Length => Kind::Length,
                    Unary::TypeOf => Kind::TypeOf,
                    Unary::Ffi(_) => Kind::Ffi,
                } as i32,
                ffi_name: match u {
                    Unary::Ffi(name) => Some(name.to_owned()),
                    _ => None,
                },
            })
        }
        Op::Binary(b) => {
            use schema::op_binary::Kind;

            schema::op::Content::Binary(schema::OpBinary {
                kind: match b {
                    Binary::LessThan => Kind::LessThan,
                    Binary::GreaterThan => Kind::GreaterThan,
                    Binary::LessOrEqual => Kind::LessOrEqual,
                    Binary::GreaterOrEqual => Kind::GreaterOrEqual,
                    Binary::Equal => Kind::Equal,
                    Binary::Contains => Kind::Contains,
                    Binary::Prefix => Kind::Prefix,
                    Binary::Suffix => Kind::Suffix,
                    Binary::Regex => Kind::Regex,
                    Binary::Add => Kind::Add,
                    Binary::Sub => Kind::Sub,
                    Binary::Mul => Kind::Mul,
                    Binary::Div => Kind::Div,
                    Binary::And => Kind::And,
                    Binary::Or => Kind::Or,
                    Binary::Intersection => Kind::Intersection,
                    Binary::Union => Kind::Union,
                    Binary::BitwiseAnd => Kind::BitwiseAnd,
                    Binary::BitwiseOr => Kind::BitwiseOr,
                    Binary::BitwiseXor => Kind::BitwiseXor,
                    Binary::NotEqual => Kind::NotEqual,
                    Binary::HeterogeneousEqual => Kind::HeterogeneousEqual,
                    Binary::HeterogeneousNotEqual => Kind::HeterogeneousNotEqual,
                    Binary::LazyAnd => Kind::LazyAnd,
                    Binary::LazyOr => Kind::LazyOr,
                    Binary::All => Kind::All,
                    Binary::Any => Kind::Any,
                    Binary::Get => Kind::Get,
                    Binary::Ffi(_) => Kind::Ffi,
                    Binary::TryOr => Kind::TryOr,
                } as i32,
                ffi_name: match b {
                    Binary::Ffi(name) => Some(name.to_owned()),
                    _ => None,
                },
            })
        }
        Op::Closure(params, ops) => schema::op::Content::Closure(schema::OpClosure {
            params: params.clone(),
            ops: ops.iter().map(token_op_to_proto_op).collect(),
        }),
    };

    schema::Op {
        content: Some(content),
    }
}

pub fn token_expression_to_proto_expression(input: &Expression) -> schema::Expression {
    schema::Expression {
        ops: input.ops.iter().map(token_op_to_proto_op).collect(),
    }
}

fn proto_op_to_token_op(op: &schema::Op) -> Result<Op, error::Format> {
    use schema::{op, op_binary, op_unary};
    Ok(match op.content.as_ref() {
        Some(op::Content::Value(id)) => Op::Value(proto_id_to_token_term(id)?),
        Some(op::Content::Unary(u)) => {
            match (op_unary::Kind::from_i32(u.kind), u.ffi_name.as_ref()) {
                (Some(op_unary::Kind::Negate), None) => Op::Unary(Unary::Negate),
                (Some(op_unary::Kind::Parens), None) => Op::Unary(Unary::Parens),
                (Some(op_unary::Kind::Length), None) => Op::Unary(Unary::Length),
                (Some(op_unary::Kind::TypeOf), None) => Op::Unary(Unary::TypeOf),
                (Some(op_unary::Kind::Ffi), Some(n)) => Op::Unary(Unary::Ffi(*n)),
                (Some(op_unary::Kind::Ffi), None) => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: missing ffi name".to_string(),
                    ))
                }
                (Some(_), Some(_)) => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: ffi name set on a regular unary operation"
                            .to_string(),
                    ))
                }
                (None, _) => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: unary operation is empty".to_string(),
                    ))
                }
            }
        }
        Some(op::Content::Binary(b)) => {
            match (op_binary::Kind::from_i32(b.kind), b.ffi_name.as_ref()) {
                (Some(op_binary::Kind::LessThan), None) => Op::Binary(Binary::LessThan),
                (Some(op_binary::Kind::GreaterThan), None) => Op::Binary(Binary::GreaterThan),
                (Some(op_binary::Kind::LessOrEqual), None) => Op::Binary(Binary::LessOrEqual),
                (Some(op_binary::Kind::GreaterOrEqual), None) => Op::Binary(Binary::GreaterOrEqual),
                (Some(op_binary::Kind::Equal), None) => Op::Binary(Binary::Equal),
                (Some(op_binary::Kind::Contains), None) => Op::Binary(Binary::Contains),
                (Some(op_binary::Kind::Prefix), None) => Op::Binary(Binary::Prefix),
                (Some(op_binary::Kind::Suffix), None) => Op::Binary(Binary::Suffix),
                (Some(op_binary::Kind::Regex), None) => Op::Binary(Binary::Regex),
                (Some(op_binary::Kind::Add), None) => Op::Binary(Binary::Add),
                (Some(op_binary::Kind::Sub), None) => Op::Binary(Binary::Sub),
                (Some(op_binary::Kind::Mul), None) => Op::Binary(Binary::Mul),
                (Some(op_binary::Kind::Div), None) => Op::Binary(Binary::Div),
                (Some(op_binary::Kind::And), None) => Op::Binary(Binary::And),
                (Some(op_binary::Kind::Or), None) => Op::Binary(Binary::Or),
                (Some(op_binary::Kind::Intersection), None) => Op::Binary(Binary::Intersection),
                (Some(op_binary::Kind::Union), None) => Op::Binary(Binary::Union),
                (Some(op_binary::Kind::BitwiseAnd), None) => Op::Binary(Binary::BitwiseAnd),
                (Some(op_binary::Kind::BitwiseOr), None) => Op::Binary(Binary::BitwiseOr),
                (Some(op_binary::Kind::BitwiseXor), None) => Op::Binary(Binary::BitwiseXor),
                (Some(op_binary::Kind::NotEqual), None) => Op::Binary(Binary::NotEqual),
                (Some(op_binary::Kind::HeterogeneousEqual), None) => {
                    Op::Binary(Binary::HeterogeneousEqual)
                }
                (Some(op_binary::Kind::HeterogeneousNotEqual), None) => {
                    Op::Binary(Binary::HeterogeneousNotEqual)
                }
                (Some(op_binary::Kind::LazyAnd), None) => Op::Binary(Binary::LazyAnd),
                (Some(op_binary::Kind::LazyOr), None) => Op::Binary(Binary::LazyOr),
                (Some(op_binary::Kind::All), None) => Op::Binary(Binary::All),
                (Some(op_binary::Kind::Any), None) => Op::Binary(Binary::Any),
                (Some(op_binary::Kind::Get), None) => Op::Binary(Binary::Get),
                (Some(op_binary::Kind::Ffi), Some(n)) => Op::Binary(Binary::Ffi(*n)),
                (Some(op_binary::Kind::Ffi), None) => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: missing ffi name".to_string(),
                    ))
                }
                (Some(_), Some(_)) => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: ffi name set on a regular binary operation"
                            .to_string(),
                    ))
                }
                (Some(op_binary::Kind::TryOr), None) => Op::Binary(Binary::TryOr),
                (None, _) => {
                    return Err(error::Format::DeserializationError(
                        "deserialization error: binary operation is empty".to_string(),
                    ))
                }
            }
        }
        Some(op::Content::Closure(op_closure)) => Op::Closure(
            op_closure.params.clone(),
            op_closure
                .ops
                .iter()
                .map(proto_op_to_token_op)
                .collect::<Result<_, _>>()?,
        ),
        None => {
            return Err(error::Format::DeserializationError(
                "deserialization error: operation is empty".to_string(),
            ))
        }
    })
}

pub fn proto_expression_to_token_expression(
    input: &schema::Expression,
) -> Result<Expression, error::Format> {
    let mut ops = Vec::new();

    for op in input.ops.iter() {
        ops.push(proto_op_to_token_op(op)?);
    }

    Ok(Expression { ops })
}

pub fn token_scope_to_proto_scope(input: &Scope) -> schema::Scope {
    schema::Scope {
        content: Some(match input {
            crate::token::Scope::Authority => {
                schema::scope::Content::ScopeType(schema::scope::ScopeType::Authority as i32)
            }
            crate::token::Scope::Previous => {
                schema::scope::Content::ScopeType(schema::scope::ScopeType::Previous as i32)
            }
            crate::token::Scope::PublicKey(i) => schema::scope::Content::PublicKey(*i as i64),
        }),
    }
}

pub fn proto_scope_to_token_scope(input: &schema::Scope) -> Result<Scope, error::Format> {
    //FIXME: check that the referenced public key index exists in the public key table
    match input.content.as_ref() {
        Some(content) => match content {
            schema::scope::Content::ScopeType(i) => {
                if *i == schema::scope::ScopeType::Authority as i32 {
                    Ok(Scope::Authority)
                } else if *i == schema::scope::ScopeType::Previous as i32 {
                    Ok(Scope::Previous)
                } else {
                    Err(error::Format::DeserializationError(format!(
                        "deserialization error: unexpected value `{}` for scope type",
                        i
                    )))
                }
            }
            schema::scope::Content::PublicKey(i) => Ok(Scope::PublicKey(*i as u64)),
        },
        None => Err(error::Format::DeserializationError(
            "deserialization error: expected `content` field in Scope".to_string(),
        )),
    }
}
