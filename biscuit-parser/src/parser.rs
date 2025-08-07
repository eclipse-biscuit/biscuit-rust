/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */

// This warning makes all parser signatures extremely verbose
#![allow(mismatched_lifetime_syntaxes)]
use crate::builder::{self, CheckKind, PublicKey};
use nom::{
    branch::alt,
    bytes::complete::{escaped_transform, tag, tag_no_case, take_until, take_while, take_while1},
    character::{
        complete::{char, digit1, multispace0 as space0, satisfy},
        is_alphabetic, is_alphanumeric,
    },
    combinator::{consumed, cut, eof, map, map_res, opt, recognize, value},
    error::{ErrorKind, FromExternalError, ParseError},
    multi::{many0, separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult, Offset, Parser,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
};
use thiserror::Error;

/// parse a Datalog fact
pub fn fact(i: &str) -> IResult<&str, builder::Fact, Error> {
    let (i, fact) = fact_inner(i)?;

    let (i, _) = error(
        preceded(space0, eof),
        |input| format!("unexpected trailing data after fact: '{}'", input),
        " ,\n",
    )(i)?;

    Ok((i, fact))
}

pub fn fact_inner(i: &str) -> IResult<&str, builder::Fact, Error> {
    let (i, _) = space0(i)?;
    let (i, fact_name) = name(i)?;

    let (i, _) = space0(i)?;
    let (i, terms) = delimited(
        char('('),
        cut(separated_list1(
            preceded(space0, char(',')),
            cut(term_in_fact),
        )),
        preceded(space0, char(')')),
    )(i)?;

    Ok((i, builder::Fact::new(fact_name.to_string(), terms)))
}

/// parse a Datalog check
pub fn check(i: &str) -> IResult<&str, builder::Check, Error> {
    let (i, check) = check_inner(i)?;

    let (i, _) = error(
        preceded(space0, eof),
        |input| {
            match input.chars().next() {
            Some(')') => "unexpected parens".to_string(),
            _ => format!("expected either the next term after ',' or the next check variant after 'or', but got '{}'",
                     input)
        }
        },
        " ,\n",
    )(i)?;

    Ok((i, check))
}

fn check_inner(i: &str) -> IResult<&str, builder::Check, Error> {
    let (i, _) = space0(i)?;

    let (i, kind) = alt((
        map(tag_no_case("check if"), |_| CheckKind::One),
        map(tag_no_case("check all"), |_| CheckKind::All),
        map(tag_no_case("reject if"), |_| CheckKind::Reject),
    ))(i)?;

    let (i, queries) = cut(check_body)(i)?;
    Ok((i, builder::Check { queries, kind }))
}

/// parse an allow or deny rule
pub fn policy(i: &str) -> IResult<&str, builder::Policy, Error> {
    let (i, policy) = policy_inner(i)?;

    let (i, _) = error(
        preceded(space0, eof),
        |input| {
            match input.chars().next() {
            Some(')') => "unexpected parens".to_string(),
            _ => format!("expected either the next term after ',' or the next policy variant after 'or', but got '{}'",
                     input)
        }
        },
        " ,\n",
    )(i)?;

    Ok((i, policy))
}

fn policy_inner(i: &str) -> IResult<&str, builder::Policy, Error> {
    alt((allow, deny))(i)
}

/// parse an allow rule
pub fn allow(i: &str) -> IResult<&str, builder::Policy, Error> {
    let (i, _) = space0(i)?;

    let (i, _) = tag_no_case("allow if")(i)?;

    let (i, queries) = cut(check_body)(i)?;
    Ok((
        i,
        builder::Policy {
            queries,
            kind: builder::PolicyKind::Allow,
        },
    ))
}

/// parse a deny rule
pub fn deny(i: &str) -> IResult<&str, builder::Policy, Error> {
    let (i, _) = space0(i)?;

    let (i, _) = tag_no_case("deny if")(i)?;

    let (i, queries) = cut(check_body)(i)?;
    Ok((
        i,
        builder::Policy {
            queries,
            kind: builder::PolicyKind::Deny,
        },
    ))
}

/// parse a Datalog check body
pub fn check_body(i: &str) -> IResult<&str, Vec<builder::Rule>, Error> {
    let (i, mut queries) = separated_list1(
        preceded(space0, tag_no_case("or")),
        preceded(space0, cut(rule_body)),
    )(i)?;

    let queries = queries
        .drain(..)
        .map(|(predicates, expressions, scopes)| {
            builder::Rule::new(
                builder::Predicate {
                    name: "query".to_string(),
                    terms: Vec::new(),
                },
                predicates,
                expressions,
                scopes,
            )
        })
        .collect();
    Ok((i, queries))
}

/// parse a Datalog rule
pub fn rule(i: &str) -> IResult<&str, builder::Rule, Error> {
    let (i, rule) = rule_inner(i)?;

    let (i, _) = error(
        preceded(space0, eof),
        |input| match input.chars().next() {
            Some(')') => "unexpected parens".to_string(),
            _ => format!(
                "expected the next term or expression after ',', but got '{}'",
                input
            ),
        },
        " ,\n",
    )(i)?;

    Ok((i, rule))
}

pub fn rule_inner(i: &str) -> IResult<&str, builder::Rule, Error> {
    let (i, (input, (head, body, expressions, scopes))) = consumed(|i| {
        let (i, head) = rule_head(i)?;
        let (i, _) = space0(i)?;

        let (i, _) = tag("<-")(i)?;

        let (i, (body, expressions, scopes)) = cut(rule_body)(i)?;

        Ok((i, (head, body, expressions, scopes)))
    })(i)?;

    let rule = builder::Rule::new(head, body, expressions, scopes);

    if let Err(message) = rule.validate_variables() {
        return Err(nom::Err::Failure(Error {
            input,
            code: ErrorKind::Satisfy,
            message: Some(message),
        }));
    }

    Ok((i, rule))
}

fn predicate(i: &str) -> IResult<&str, builder::Predicate, Error> {
    let (i, _) = space0(i)?;
    let (i, fact_name) = name(i)?;

    let (i, _) = space0(i)?;
    let (i, terms) = delimited(
        char('('),
        cut(separated_list1(preceded(space0, char(',')), cut(term))),
        preceded(space0, char(')')),
    )(i)?;

    Ok((
        i,
        builder::Predicate {
            name: fact_name.to_string(),
            terms,
        },
    ))
}

fn rule_head(i: &str) -> IResult<&str, builder::Predicate, Error> {
    let (i, _) = space0(i)?;
    let (i, fact_name) = name(i)?;

    let (i, _) = space0(i)?;
    let (i, terms) = delimited(
        char('('),
        cut(separated_list0(preceded(space0, char(',')), cut(term))),
        preceded(space0, char(')')),
    )(i)?;

    Ok((
        i,
        builder::Predicate {
            name: fact_name.to_string(),
            terms,
        },
    ))
}

/// parse a Datalog rule body
pub fn rule_body(
    i: &str,
) -> IResult<
    &str,
    (
        Vec<builder::Predicate>,
        Vec<builder::Expression>,
        Vec<builder::Scope>,
    ),
    Error,
> {
    let (i, mut elements) = separated_list1(
        preceded(space0, char(',')),
        preceded(space0, cut(predicate_or_expression)),
    )(i)?;

    let mut predicates = Vec::new();
    let mut expressions = Vec::new();

    for el in elements.drain(..) {
        match el {
            PredOrExpr::P(predicate) => predicates.push(predicate),
            PredOrExpr::E(expression) => {
                let ops = expression.opcodes();
                let e = builder::Expression { ops };
                expressions.push(e);
            }
        }
    }

    let (i, scopes) = scopes(i)?;

    Ok((i, (predicates, expressions, scopes)))
}

enum PredOrExpr {
    P(builder::Predicate),
    E(Expr),
}

fn predicate_or_expression(i: &str) -> IResult<&str, PredOrExpr, Error> {
    reduce(
        alt((map(predicate, PredOrExpr::P), map(expr, PredOrExpr::E))),
        ",;",
    )(i)
}

fn scopes(i: &str) -> IResult<&str, Vec<builder::Scope>, Error> {
    if let Ok((i, _)) = preceded(space0, tag::<_, _, ()>("trusting"))(i) {
        separated_list1(preceded(space0, char(',')), preceded(space0, cut(scope)))(i)
    } else {
        Ok((i, vec![]))
    }
}

fn scope(i: &str) -> IResult<&str, builder::Scope, Error> {
    alt((
        map(tag("authority"), |_| builder::Scope::Authority),
        map(tag("previous"), |_| builder::Scope::Previous),
        map(public_key, builder::Scope::PublicKey),
        map(delimited(char('{'), name, char('}')), |n| {
            builder::Scope::Parameter(n.to_string())
        }),
    ))(i)
}

pub fn public_key(i: &str) -> IResult<&str, builder::PublicKey, Error> {
    alt((
        preceded(tag("ed25519/"), parse_hex).map(|key| PublicKey {
            key,
            algorithm: builder::Algorithm::Ed25519,
        }),
        preceded(tag("secp256r1/"), parse_hex).map(|key| PublicKey {
            key,
            algorithm: builder::Algorithm::Secp256r1,
        }),
    ))(i)
}

#[derive(Debug, PartialEq)]
pub enum Expr {
    Value(builder::Term),
    Unary(builder::Op, Box<Expr>),
    Binary(builder::Op, Box<Expr>, Box<Expr>),
    Closure(Vec<String>, Box<Expr>),
}

impl Expr {
    pub fn opcodes(self) -> Vec<builder::Op> {
        let mut v = Vec::new();
        self.into_opcodes(&mut v);
        v
    }

    fn into_opcodes(self, v: &mut Vec<builder::Op>) {
        match self {
            Expr::Value(t) => v.push(builder::Op::Value(t)),
            Expr::Unary(op, expr) => {
                expr.into_opcodes(v);
                v.push(op);
            }
            Expr::Binary(op, left, right) => {
                left.into_opcodes(v);
                right.into_opcodes(v);
                v.push(op);
            }
            Expr::Closure(params, expr) => {
                let mut ops = vec![];
                expr.into_opcodes(&mut ops);
                v.push(builder::Op::Closure(params, ops))
            }
        }
    }
}

fn unary_negate(i: &str) -> IResult<&str, Expr, Error> {
    let (i, _) = space0(i)?;
    let (i, _) = tag("!")(i)?;
    let (i, _) = space0(i)?;
    let (i, value) = expr6(i)?;

    Ok((
        i,
        Expr::Unary(builder::Op::Unary(builder::Unary::Negate), Box::new(value)),
    ))
}

fn unary_parens(i: &str) -> IResult<&str, Expr, Error> {
    let (i, _) = space0(i)?;
    let (i, _) = tag("(")(i)?;
    let (i, _) = space0(i)?;
    let (i, value) = expr(i)?;
    let (i, _) = space0(i)?;
    let (i, _) = tag(")")(i)?;

    Ok((
        i,
        Expr::Unary(builder::Op::Unary(builder::Unary::Parens), Box::new(value)),
    ))
}

fn binary_op_0(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    value(Binary::LazyOr, tag("||"))(i)
}

fn binary_op_1(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    value(Binary::LazyAnd, tag("&&"))(i)
}

fn binary_op_2(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    alt((
        value(Binary::LessOrEqual, tag("<=")),
        value(Binary::GreaterOrEqual, tag(">=")),
        value(Binary::LessThan, tag("<")),
        value(Binary::GreaterThan, tag(">")),
        value(Binary::Equal, tag("===")),
        value(Binary::NotEqual, tag("!==")),
        value(Binary::HeterogeneousEqual, tag("==")),
        value(Binary::HeterogeneousNotEqual, tag("!=")),
    ))(i)
}

fn binary_op_3(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    value(Binary::BitwiseXor, tag("^"))(i)
}

fn binary_op_4(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    value(Binary::BitwiseOr, tag("|"))(i)
}

fn binary_op_5(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    value(Binary::BitwiseAnd, tag("&"))(i)
}

fn binary_op_6(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    alt((value(Binary::Add, tag("+")), value(Binary::Sub, tag("-"))))(i)
}

fn binary_op_7(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;
    alt((value(Binary::Mul, tag("*")), value(Binary::Div, tag("/"))))(i)
}

fn extern_un(i: &str) -> IResult<&str, builder::Unary, Error> {
    let (i, func) = preceded(tag("extern::"), name)(i)?;
    Ok((i, builder::Unary::Ffi(func.to_string())))
}

fn extern_bin(i: &str) -> IResult<&str, builder::Binary, Error> {
    let (i, func) = preceded(tag("extern::"), name)(i)?;
    Ok((i, builder::Binary::Ffi(func.to_string())))
}

fn binary_op_8(i: &str) -> IResult<&str, builder::Binary, Error> {
    use builder::Binary;

    alt((
        value(Binary::Contains, tag("contains")),
        value(Binary::Prefix, tag("starts_with")),
        value(Binary::Suffix, tag("ends_with")),
        value(Binary::Regex, tag("matches")),
        value(Binary::Intersection, tag("intersection")),
        value(Binary::Union, tag("union")),
        value(Binary::All, tag("all")),
        value(Binary::Any, tag("any")),
        value(Binary::Get, tag("get")),
        value(Binary::TryOr, tag("try_or")),
        extern_bin,
    ))(i)
}

/// Innermost parser for an expression: either a parenthesised expression,
/// or a single term.
fn expr_term(i: &str) -> IResult<&str, Expr, Error> {
    alt((unary_parens, reduce(map(term, Expr::Value), " ,\n);")))(i)
}

fn fold_exprs(initial: Expr, remainder: Vec<(builder::Binary, Expr)>) -> Expr {
    remainder.into_iter().fold(initial, |acc, pair| {
        let (op, expr) = pair;
        match op {
            builder::Binary::LazyAnd | builder::Binary::LazyOr => Expr::Binary(
                builder::Op::Binary(op),
                Box::new(acc),
                Box::new(Expr::Closure(vec![], Box::new(expr))),
            ),
            _ => Expr::Binary(builder::Op::Binary(op), Box::new(acc), Box::new(expr)),
        }
    })
}

/// Top-lever parser for an expression. Expression parsers are layered in
/// order to support operator precedence (see <https://en.wikipedia.org/wiki/Operator-precedence_parser>).
///
/// See <https://github.com/biscuit-auth/biscuit/blob/master/SPECIFICATIONS.md#grammar>
/// for the precedence order of operators in biscuit datalog.
///
/// The operators with the lowest precedence are parsed at the outer level,
/// and their operands delegate to parsers that progressively handle more
/// tightly binding operators.
///
/// This level handles the last operator in the precedence list: `||`
/// `||` is left associative, so multiple `||` expressions can be combined:
/// `a || b || c <=> (a || b) || c`
pub fn expr(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr1(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_0), expr1)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles `&&`
/// `&&` is left associative, so multiple `&&` expressions can be combined:
/// `a && b && c <=> (a && b) && c`
fn expr1(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr2(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_1), expr2)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles comparison operators (`==`, `>`, `>=`, `<`, `<=`).
/// Those operators are _not_ associative and require explicit grouping
/// with parentheses.
fn expr2(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr3(i)?;

    if let Ok((i, (op, remainder))) = tuple((preceded(space0, binary_op_2), expr3))(i) {
        Ok((
            i,
            Expr::Binary(
                builder::Op::Binary(op),
                Box::new(initial),
                Box::new(remainder),
            ),
        ))
    } else {
        Ok((i, initial))
    }
}

/// This level handles `|`.
/// It is left associative, so multiple expressions can be combined:
/// `a | b | c <=> (a | b) | c`
fn expr3(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr4(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_3), expr4)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles `^`.
/// It is left associative, so multiple expressions can be combined:
/// `a ^ b ^ c <=> (a ^ b) ^ c`
fn expr4(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr5(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_4), expr5)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles `&`.
/// It is left associative, so multiple expressions can be combined:
/// `a & b & c <=> (a & b) & c`
fn expr5(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr6(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_5), expr6)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles `+` and `-`.
/// They are left associative, so multiple expressions can be combined:
/// `a + b - c <=> (a + b) - c`
fn expr6(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr7(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_6), expr7)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles `*` and `/`.
/// They are left associative, so multiple expressions can be combined:
/// `a * b / c <=> (a * b) / c`
fn expr7(i: &str) -> IResult<&str, Expr, Error> {
    let (i, initial) = expr8(i)?;

    let (i, remainder) = many0(tuple((preceded(space0, binary_op_7), expr8)))(i)?;

    Ok((i, fold_exprs(initial, remainder)))
}

/// This level handles `!` (prefix negation)
fn expr8(i: &str) -> IResult<&str, Expr, Error> {
    alt((unary_negate, expr9))(i)
}

/// This level handles methods. Methods can take either zero or one
/// argument in addition to the expression they are called on.
/// The name of the method decides its arity.
fn expr9(i: &str) -> IResult<&str, Expr, Error> {
    let (mut input, mut initial) = expr_term(i)?;

    loop {
        if let Ok((i, _)) = char::<_, ()>('.')(input) {
            let bin_result = binary_method(i);
            let un_result = unary_method(i);
            match (bin_result, un_result) {
                (Ok((i, (op, params, arg))), _) => {
                    input = i;
                    match (params, &op) {
                        (_, builder::Binary::TryOr) => {
                            initial = Expr::Binary(
                                builder::Op::Binary(op),
                                Box::new(Expr::Closure(vec![], Box::new(initial))),
                                Box::new(arg),
                            );
                        }
                        (Some(params), _) => {
                            initial = Expr::Binary(
                                builder::Op::Binary(op),
                                Box::new(initial),
                                Box::new(Expr::Closure(params, Box::new(arg))),
                            );
                        }
                        (None, _) => {
                            initial = Expr::Binary(
                                builder::Op::Binary(op),
                                Box::new(initial),
                                Box::new(arg),
                            );
                        }
                    }
                }
                (_, Ok((i, op))) => {
                    input = i;

                    initial = Expr::Unary(builder::Op::Unary(op), Box::new(initial));
                }
                (_, Err(e)) => return Err(e),
            }
        } else {
            return Ok((input, initial));
        }
    }
}

fn binary_method(i: &str) -> IResult<&str, (builder::Binary, Option<Vec<String>>, Expr), Error> {
    let (i, op) = binary_op_8(i)?;

    let (i, _) = char('(')(i)?;
    let (i, _) = space0(i)?;
    // we only support a single argument for now
    match op {
        builder::Binary::All | builder::Binary::Any => {
            let (i, param) = preceded(char('$'), name)(i)?;
            let (i, _) = space0(i)?;
            let (i, _) = tag("->")(i)?;
            let (i, _) = space0(i)?;
            let (i, arg) = expr(i)?;
            let (i, _) = space0(i)?;
            let (i, _) = char(')')(i)?;
            Ok((i, (op, Some(vec![param.to_owned()]), arg)))
        }
        _ => {
            let (i, arg) = expr(i)?;
            let (i, _) = space0(i)?;
            let (i, _) = char(')')(i)?;

            Ok((i, (op, None, arg)))
        }
    }
}

fn unary_method(i: &str) -> IResult<&str, builder::Unary, Error> {
    use builder::Unary;
    let (i, op) = alt((
        value(Unary::Length, tag("length")),
        value(Unary::TypeOf, tag("type")),
        extern_un,
    ))(i)?;

    let (i, _) = char('(')(i)?;
    let (i, _) = space0(i)?;
    let (i, _) = char(')')(i)?;

    Ok((i, op))
}

fn name(i: &str) -> IResult<&str, &str, Error> {
    let is_name_char = |c: char| is_alphanumeric(c as u8) || c == '_' || c == ':';

    reduce(take_while1(is_name_char), " ,:(\n;")(i)
}

fn parameter_name(i: &str) -> IResult<&str, &str, Error> {
    let is_name_char = |c: char| is_alphanumeric(c as u8) || c == '_' || c == ':';

    error(
        recognize(preceded(
            satisfy(|c: char| is_alphabetic(c as u8)),
            take_while(is_name_char),
        )),
        |_| {
            "invalid parameter name: it must start with an alphabetic character, followed by alphanumeric characters, underscores or colons".to_string()
        },
        " ,:(\n;",
    )(i)
}

fn printable(i: &str) -> IResult<&str, &str, Error> {
    take_while1(|c: char| c != '\\' && c != '"')(i)
}

fn parse_string_internal(i: &str) -> IResult<&str, String, Error> {
    escaped_transform(
        printable,
        '\\',
        alt((
            map(char('\\'), |_| "\\"),
            map(char('"'), |_| "\""),
            map(char('n'), |_| "\n"),
        )),
    )(i)
}

fn parse_string(i: &str) -> IResult<&str, String, Error> {
    alt((
        value("".to_string(), tag("\"\"")),
        delimited(char('"'), parse_string_internal, char('"')),
    ))(i)
}

fn string(i: &str) -> IResult<&str, builder::Term, Error> {
    parse_string(i).map(|(i, s)| (i, builder::Term::Str(s)))
}

fn parse_integer(i: &str) -> IResult<&str, i64, Error> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| s.parse())(i)
}

fn integer(i: &str) -> IResult<&str, builder::Term, Error> {
    parse_integer(i).map(|(i, n)| (i, builder::int(n)))
}

fn parse_date(i: &str) -> IResult<&str, u64, Error> {
    map_res(
        map_res(
            take_while1(|c: char| {
                c != ',' && c != ' ' && c != ')' && c != ']' && c != ';' && c != '}'
            }),
            |s| time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339),
        ),
        |t| t.unix_timestamp().try_into(),
    )(i)
}

fn date(i: &str) -> IResult<&str, builder::Term, Error> {
    parse_date(i).map(|(i, t)| (i, builder::Term::Date(t)))
}

fn parse_bytes(i: &str) -> IResult<&str, Vec<u8>, Error> {
    preceded(tag("hex:"), parse_hex)(i)
}

fn parse_hex(i: &str) -> IResult<&str, Vec<u8>, Error> {
    map_res(
        take_while1(|c| {
            let c = c as u8;
            c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || (b'A'..=b'F').contains(&c)
        }),
        hex::decode,
    )(i)
}

fn bytes(i: &str) -> IResult<&str, builder::Term, Error> {
    parse_bytes(i).map(|(i, s)| (i, builder::Term::Bytes(s)))
}

fn variable(i: &str) -> IResult<&str, builder::Term, Error> {
    map(preceded(char('$'), name), builder::variable)(i)
}

fn parameter(i: &str) -> IResult<&str, builder::Term, Error> {
    map(
        delimited(char('{'), parameter_name, char('}')),
        builder::parameter,
    )(i)
}

fn parse_bool(i: &str) -> IResult<&str, bool, Error> {
    alt((value(true, tag("true")), value(false, tag("false"))))(i)
}

fn boolean(i: &str) -> IResult<&str, builder::Term, Error> {
    parse_bool(i).map(|(i, b)| (i, builder::boolean(b)))
}

fn null(i: &str) -> IResult<&str, builder::Term, Error> {
    tag("null")(i).map(|(i, _)| (i, builder::null()))
}

fn set(i: &str) -> IResult<&str, builder::Term, Error> {
    alt((empty_set, non_empty_set))(i)
}

fn empty_set(i: &str) -> IResult<&str, builder::Term, Error> {
    tag("{,}")(i).map(|(i, _)| (i, builder::set(BTreeSet::new())))
}

fn non_empty_set(i: &str) -> IResult<&str, builder::Term, Error> {
    let (i, _) = preceded(space0, char('{'))(i)?;
    let (i, mut list) = cut(separated_list1(preceded(space0, char(',')), term_in_set))(i)?;

    let mut set = BTreeSet::new();

    let mut kind: Option<u8> = None;
    for term in list.drain(..) {
        let index = match term {
            builder::Term::Variable(_) => {
                return Err(nom::Err::Failure(Error {
                    input: i,
                    code: ErrorKind::Fail,
                    message: Some("variables are not permitted in sets".to_string()),
                }))
            }
            builder::Term::Integer(_) => 2,
            builder::Term::Str(_) => 3,
            builder::Term::Date(_) => 4,
            builder::Term::Bytes(_) => 5,
            builder::Term::Bool(_) => 6,
            builder::Term::Set(_) => {
                return Err(nom::Err::Failure(Error {
                    input: i,
                    code: ErrorKind::Fail,
                    message: Some("sets cannot contain other sets".to_string()),
                }))
            }
            builder::Term::Parameter(_) => 7,
            builder::Term::Null => 8,
            builder::Term::Array(_) => 9,
            builder::Term::Map(_) => 10,
        };

        if let Some(k) = kind {
            if k != index {
                return Err(nom::Err::Failure(Error {
                    input: i,
                    code: ErrorKind::Fail,
                    message: Some("set elements must have the same type".to_string()),
                }));
            }
        } else {
            kind = Some(index);
        }

        set.insert(term);
    }

    let (i, _) = preceded(space0, char('}'))(i)?;

    Ok((i, builder::set(set)))
}

fn array(i: &str) -> IResult<&str, builder::Term, Error> {
    let (i, _) = preceded(space0, char('['))(i)?;
    let (i, array) = cut(separated_list0(preceded(space0, char(',')), term_in_fact))(i)?;
    let (i, _) = preceded(space0, char(']'))(i)?;

    Ok((i, builder::array(array)))
}

fn parse_map(i: &str) -> IResult<&str, builder::Term, Error> {
    let (i, _) = preceded(space0, char('{'))(i)?;
    let (i, mut list) = cut(separated_list0(
        preceded(space0, char(',')),
        separated_pair(map_key, preceded(space0, char(':')), term_in_fact),
    ))(i)?;

    let mut map = BTreeMap::new();

    for (key, term) in list.drain(..) {
        map.insert(key, term);
    }

    let (i, _) = preceded(space0, char('}'))(i)?;

    Ok((i, builder::map(map)))
}

fn map_key(i: &str) -> IResult<&str, builder::MapKey, Error> {
    preceded(
        space0,
        alt((
            map(delimited(char('{'), parameter_name, char('}')), |s| {
                builder::MapKey::Parameter(s.to_string())
            }),
            map(parse_string, |s| builder::MapKey::Str(s.to_string())),
            map(parse_integer, builder::MapKey::Integer),
        )),
    )(i)
}

fn term(i: &str) -> IResult<&str, builder::Term, Error> {
    preceded(
        space0,
        alt((
            parameter, string, date, variable, integer, bytes, boolean, null, array, parse_map, set,
        )),
    )(i)
}

fn term_in_fact(i: &str) -> IResult<&str, builder::Term, Error> {
    preceded(
        space0,
        error(
            alt((
                parameter, string, date, integer, bytes, boolean, null, set, array, parse_map,
            )),
            |input| match input.chars().next() {
                None | Some(',') | Some(')') => "missing term".to_string(),
                Some('$') => "variables are not allowed in facts".to_string(),
                _ => "expected a valid term".to_string(),
            },
            " ,)\n;",
        ),
    )(i)
}

fn term_in_set(i: &str) -> IResult<&str, builder::Term, Error> {
    preceded(
        space0,
        error(
            alt((
                parameter, string, date, integer, bytes, boolean, null, parse_map,
            )),
            |input| match input.chars().next() {
                None | Some(',') | Some('}') => "missing term".to_string(),
                Some('$') => "variables are not allowed in sets".to_string(),
                _ => "expected a valid term".to_string(),
            },
            " ,}\n;",
        ),
    )(i)
}

fn line_comment(i: &str) -> IResult<&str, (), Error> {
    let (i, _) = space0(i)?;
    let (i, _) = tag("//")(i)?;
    let (i, _) = take_while(|c| c != '\r' && c != '\n')(i)?;
    let (i, _) = alt((tag("\n"), tag("\r\n"), eof))(i)?;

    Ok((i, ()))
}

fn multiline_comment(i: &str) -> IResult<&str, (), Error> {
    let (i, _) = space0(i)?;
    let (i, _) = tag("/*")(i)?;
    let (i, _) = take_until("*/")(i)?;
    let (i, _) = tag("*/")(i)?;

    Ok((i, ()))
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SourceResult<'a> {
    pub scopes: Vec<builder::Scope>,
    pub facts: Vec<(&'a str, builder::Fact)>,
    pub rules: Vec<(&'a str, builder::Rule)>,
    pub checks: Vec<(&'a str, builder::Check)>,
    pub policies: Vec<(&'a str, builder::Policy)>,
}

enum SourceElement<'a> {
    Fact(&'a str, builder::Fact),
    Rule(&'a str, builder::Rule),
    Check(&'a str, builder::Check),
    Policy(&'a str, builder::Policy),
    Comment,
}

pub fn sep(i: &str) -> IResult<&str, &str, Error> {
    let (i, _) = space0(i)?;
    alt((tag(";"), eof))(i)
}

pub fn parse_source(mut i: &str) -> Result<SourceResult, Vec<Error>> {
    let mut result = SourceResult::default();
    let mut errors = Vec::new();

    loop {
        if i.is_empty() {
            if errors.is_empty() {
                return Ok(result);
            } else {
                return Err(errors);
            }
        }

        match terminated(
            alt((
                map(terminated(consumed(rule_inner), sep), |(i, r)| {
                    SourceElement::Rule(i, r)
                }),
                map(terminated(consumed(fact_inner), sep), |(i, f)| {
                    SourceElement::Fact(i, f)
                }),
                map(terminated(consumed(check_inner), sep), |(i, c)| {
                    SourceElement::Check(i, c)
                }),
                map(terminated(consumed(policy_inner), sep), |(i, p)| {
                    SourceElement::Policy(i, p)
                }),
                map(line_comment, |_| SourceElement::Comment),
                map(multiline_comment, |_| SourceElement::Comment),
            )),
            space0,
        )(i)
        {
            Ok((i2, o)) => {
                match o {
                    SourceElement::Fact(i, f) => result.facts.push((i, f)),
                    SourceElement::Rule(i, r) => result.rules.push((i, r)),
                    SourceElement::Check(i, c) => result.checks.push((i, c)),
                    SourceElement::Policy(i, p) => result.policies.push((i, p)),
                    SourceElement::Comment => {}
                }

                i = i2;
            }
            Err(nom::Err::Incomplete(_)) => panic!(),
            Err(nom::Err::Error(mut e)) => {
                if let Some(index) = e.input.find(|c| c == ';') {
                    e.input = &(e.input)[..index];
                }

                let offset = i.offset(e.input);
                if let Some(index) = &i[offset..].find(|c| c == ';') {
                    i = &i[offset + index + 1..];
                } else {
                    i = &i[i.len()..];
                }

                errors.push(e);
            }
            Err(nom::Err::Failure(mut e)) => {
                if let Some(index) = e.input.find(|c| c == ';') {
                    e.input = &(e.input)[..index];
                }

                let offset = i.offset(e.input);
                if let Some(index) = &i[offset..].find(|c| c == ';') {
                    i = &i[offset + index + 1..];
                } else {
                    i = &i[i.len()..];
                }

                errors.push(e);
            }
        }
    }
}

pub fn parse_block_source(mut i: &str) -> Result<SourceResult, Vec<Error>> {
    let mut result = SourceResult::default();
    let mut errors = Vec::new();

    match opt(terminated(consumed(scopes), sep))(i) {
        Ok((i2, opt_scopes)) => {
            if let Some((_, scopes)) = opt_scopes {
                i = i2;
                result.scopes = scopes;
            }
        }
        Err(nom::Err::Incomplete(_)) => panic!(),
        Err(nom::Err::Error(mut e)) => {
            if let Some(index) = e.input.find(|c| c == ';') {
                e.input = &(e.input)[..index];
            }

            let offset = i.offset(e.input);
            if let Some(index) = &i[offset..].find(|c| c == ';') {
                i = &i[offset + index + 1..];
            } else {
                i = &i[i.len()..];
            }

            errors.push(e);
        }
        Err(nom::Err::Failure(mut e)) => {
            if let Some(index) = e.input.find(|c| c == ';') {
                e.input = &(e.input)[..index];
            }

            let offset = i.offset(e.input);
            if let Some(index) = &i[offset..].find(|c| c == ';') {
                i = &i[offset + index + 1..];
            } else {
                i = &i[i.len()..];
            }

            errors.push(e);
        }
    }

    loop {
        if i.is_empty() {
            if errors.is_empty() {
                return Ok(result);
            } else {
                return Err(errors);
            }
        }

        match terminated(
            alt((
                map(terminated(consumed(rule_inner), sep), |(i, r)| {
                    SourceElement::Rule(i, r)
                }),
                map(terminated(consumed(fact_inner), sep), |(i, f)| {
                    SourceElement::Fact(i, f)
                }),
                map(terminated(consumed(check_inner), sep), |(i, c)| {
                    SourceElement::Check(i, c)
                }),
                map(line_comment, |_| SourceElement::Comment),
                map(multiline_comment, |_| SourceElement::Comment),
            )),
            space0,
        )(i)
        {
            Ok((i2, o)) => {
                match o {
                    SourceElement::Fact(i, f) => result.facts.push((i, f)),
                    SourceElement::Rule(i, r) => result.rules.push((i, r)),
                    SourceElement::Check(i, c) => result.checks.push((i, c)),
                    SourceElement::Policy(_, _) => {}
                    SourceElement::Comment => {}
                }

                i = i2;
            }
            Err(nom::Err::Incomplete(_)) => panic!(),
            Err(nom::Err::Error(mut e)) => {
                if let Some(index) = e.input.find(|c| c == ';') {
                    e.input = &(e.input)[..index];
                }

                let offset = i.offset(e.input);
                if let Some(index) = &i[offset..].find(|c| c == ';') {
                    i = &i[offset + index + 1..];
                } else {
                    i = &i[i.len()..];
                }

                errors.push(e);
            }
            Err(nom::Err::Failure(mut e)) => {
                if let Some(index) = e.input.find(|c| c == ';') {
                    e.input = &(e.input)[..index];
                }

                let offset = i.offset(e.input);
                if let Some(index) = &i[offset..].find(|c| c == ';') {
                    i = &i[offset + index + 1..];
                } else {
                    i = &i[i.len()..];
                }

                errors.push(e);
            }
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
#[error("Parse error on input: {input}. Message: {message:?}")]
pub struct Error<'a> {
    pub input: &'a str,
    pub code: ErrorKind,
    pub message: Option<String>,
}

impl<'a> ParseError<&'a str> for Error<'a> {
    fn from_error_kind(input: &'a str, kind: ErrorKind) -> Self {
        Self {
            input,
            code: kind,
            message: None,
        }
    }

    fn append(_: &'a str, _: ErrorKind, other: Self) -> Self {
        other
    }
}

//FIXME: properly handle other errors
impl<'a, E> FromExternalError<&'a str, E> for Error<'a> {
    fn from_external_error(input: &'a str, kind: ErrorKind, _e: E) -> Self {
        Self {
            input,
            code: kind,
            message: None,
        }
    }
}

fn error<'a, F, O, P>(
    mut parser: P,
    context: F,
    reducer: &'static str,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, Error<'a>>
where
    P: nom::Parser<&'a str, O, Error<'a>>,
    F: Fn(&'a str) -> String,
{
    move |i: &str| match parser.parse(i) {
        Ok(res) => Ok(res),
        Err(nom::Err::Incomplete(i)) => Err(nom::Err::Incomplete(i)),
        Err(nom::Err::Error(mut e)) => {
            if let Some(index) = e.input.find(|c| reducer.contains(c)) {
                e.input = &(e.input)[..index];
            }

            if e.message.is_none() {
                e.message = Some(context(e.input));
            }

            Err(nom::Err::Error(e))
        }
        Err(nom::Err::Failure(mut e)) => {
            if let Some(index) = e.input.find(|c| reducer.contains(c)) {
                e.input = &(e.input)[..index];
            }

            if e.message.is_none() {
                e.message = Some(context(e.input));
            }

            Err(nom::Err::Failure(e))
        }
    }
}

fn reduce<'a, O, P>(
    mut parser: P,
    reducer: &'static str,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, Error<'a>>
where
    P: nom::Parser<&'a str, O, Error<'a>>,
{
    move |i: &str| match parser.parse(i) {
        Ok(res) => Ok(res),
        Err(nom::Err::Incomplete(i)) => Err(nom::Err::Incomplete(i)),
        Err(nom::Err::Error(mut e)) => {
            if let Some(index) = e.input.find(|c| reducer.contains(c)) {
                e.input = &(e.input)[..index];
            }

            Err(nom::Err::Error(e))
        }
        Err(nom::Err::Failure(mut e)) => {
            if let Some(index) = e.input.find(|c| reducer.contains(c)) {
                e.input = &(e.input)[..index];
            }

            Err(nom::Err::Failure(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use nom::error::ErrorKind;

    use crate::{
        builder::{self, array, int, var, Binary, CheckKind, Op, Unary},
        parser::Error,
    };

    #[test]
    fn name() {
        assert_eq!(
            super::name("operation(\"read\")"),
            Ok(("(\"read\")", "operation"))
        );
    }

    #[test]
    fn string() {
        assert_eq!(
            super::string("\"file1 a hello - 123_\""),
            Ok(("", builder::string("file1 a hello - 123_")))
        );
    }

    #[test]
    fn empty_string() {
        assert_eq!(super::string("\"\""), Ok(("", builder::string(""))));
    }

    #[test]
    fn integer() {
        assert_eq!(super::integer("123"), Ok(("", builder::int(123))));
        assert_eq!(super::integer("-42"), Ok(("", builder::int(-42))));
    }

    #[test]
    fn date() {
        assert_eq!(
            super::date("2019-12-02T13:49:53Z"),
            Ok(("", builder::Term::Date(1575294593)))
        );
    }

    #[test]
    fn variable() {
        assert_eq!(super::variable("$1"), Ok(("", builder::variable("1"))));
    }

    #[test]
    fn parameter() {
        assert_eq!(
            super::parameter("{param}"),
            Ok(("", builder::parameter("param")))
        );

        assert_eq!(
            super::parameter("{1param}"),
            Err(nom::Err::Error(crate::parser::Error {
                input: "1param}",
                code: nom::error::ErrorKind::Satisfy,
                message:  Some("invalid parameter name: it must start with an alphabetic character, followed by alphanumeric characters, underscores or colons".to_string())
            }))
        );

        assert_eq!(super::parameter("{p}"), Ok(("", builder::parameter("p"))));
    }

    #[test]
    fn constraint() {
        use builder::{boolean, date, int, set, string, var, Binary, Op, Unary};
        use std::collections::BTreeSet;
        use std::time::{Duration, SystemTime};

        assert_eq!(
            super::expr("$0 <= 2030-12-31T12:59:59+00:00").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(date(
                        &(SystemTime::UNIX_EPOCH + Duration::from_secs(1924952399))
                    )),
                    Op::Binary(Binary::LessOrEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 >= 2030-12-31T12:59:59+00:00").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(date(
                        &(SystemTime::UNIX_EPOCH + Duration::from_secs(1924952399))
                    )),
                    Op::Binary(Binary::GreaterOrEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 < 1234").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1234)),
                    Op::Binary(Binary::LessThan),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 > 1234").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1234)),
                    Op::Binary(Binary::GreaterThan),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 <= 1234").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1234)),
                    Op::Binary(Binary::LessOrEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 >= -1234").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(-1234)),
                    Op::Binary(Binary::GreaterOrEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 === 1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1)),
                    Op::Binary(Binary::Equal),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 == 1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1)),
                    Op::Binary(Binary::HeterogeneousEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 !== 1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1)),
                    Op::Binary(Binary::NotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 != 1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(int(1)),
                    Op::Binary(Binary::HeterogeneousNotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.length() === $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Length),
                    Op::Value(var("1")),
                    Op::Binary(Binary::Equal),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.length() == $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Length),
                    Op::Value(var("1")),
                    Op::Binary(Binary::HeterogeneousEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.length() !== $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Length),
                    Op::Value(var("1")),
                    Op::Binary(Binary::NotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.length() != $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Length),
                    Op::Value(var("1")),
                    Op::Binary(Binary::HeterogeneousNotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("!$0 === $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Negate),
                    Op::Value(var("1")),
                    Op::Binary(Binary::Equal),
                ],
            ))
        );

        assert_eq!(
            super::expr("!$0 == $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Negate),
                    Op::Value(var("1")),
                    Op::Binary(Binary::HeterogeneousEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("!$0 !== $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Negate),
                    Op::Value(var("1")),
                    Op::Binary(Binary::NotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("!$0 != $1").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Unary(Unary::Negate),
                    Op::Value(var("1")),
                    Op::Binary(Binary::HeterogeneousNotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("!false && true").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(boolean(false)),
                    Op::Unary(Unary::Negate),
                    Op::Closure(vec![], vec![Op::Value(boolean(true)),]),
                    Op::Binary(Binary::LazyAnd),
                ],
            ))
        );

        assert_eq!(
            super::expr("true || true && true").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(boolean(true)),
                    Op::Closure(
                        vec![],
                        vec![
                            Op::Value(boolean(true)),
                            Op::Closure(vec![], vec![Op::Value(boolean(true)),]),
                            Op::Binary(Binary::LazyAnd),
                        ]
                    ),
                    Op::Binary(Binary::LazyOr),
                ],
            ))
        );

        assert_eq!(
            super::expr("(1 > 2) === 3").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::GreaterThan),
                    Op::Unary(Unary::Parens),
                    Op::Value(int(3)),
                    Op::Binary(Binary::Equal),
                ]
            ))
        );

        assert_eq!(
            super::expr("(1 > 2) == 3").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::GreaterThan),
                    Op::Unary(Unary::Parens),
                    Op::Value(int(3)),
                    Op::Binary(Binary::HeterogeneousEqual),
                ]
            ))
        );

        assert_eq!(
            super::expr("(1 > 2) !== 3").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::GreaterThan),
                    Op::Unary(Unary::Parens),
                    Op::Value(int(3)),
                    Op::Binary(Binary::NotEqual),
                ]
            ))
        );

        assert_eq!(
            super::expr("(1 > 2) != 3").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::GreaterThan),
                    Op::Unary(Unary::Parens),
                    Op::Value(int(3)),
                    Op::Binary(Binary::HeterogeneousNotEqual),
                ]
            ))
        );

        assert_eq!(
            super::expr("1 > 2 + 3").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Value(int(3)),
                    Op::Binary(Binary::Add),
                    Op::Binary(Binary::GreaterThan),
                ]
            ))
        );

        assert_eq!(
            super::expr("1 > 2 == 3").map(|(i, o)| (i, o.opcodes())),
            Ok((
                " == 3",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::GreaterThan),
                ]
            ))
        );

        let h = [int(1), int(2)].iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            super::expr("{1, 2}.contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h.clone())),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                ],
            ))
        );

        assert_eq!(
            super::expr("!{ 1, 2}.contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h)),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                    Op::Unary(Unary::Negate),
                ],
            ))
        );

        let h = [
            builder::Term::Date(1575452801),
            builder::Term::Date(1607075201),
        ]
        .iter()
        .cloned()
        .collect::<BTreeSet<builder::Term>>();
        assert_eq!(
            super::expr("{2020-12-04T09:46:41+00:00, 2019-12-04T09:46:41+00:00}.contains(2020-12-04T09:46:41+00:00)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h)),
                    Op::Value(builder::Term::Date(1607075201)),
                    Op::Binary(Binary::Contains),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 === \"abc\"").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc")),
                    Op::Binary(Binary::Equal),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 == \"abc\"").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc")),
                    Op::Binary(Binary::HeterogeneousEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 !== \"abc\"").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc")),
                    Op::Binary(Binary::NotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0 != \"abc\"").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc")),
                    Op::Binary(Binary::HeterogeneousNotEqual),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.ends_with(\"abc\")").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc")),
                    Op::Binary(Binary::Suffix),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.starts_with(\"abc\")").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc")),
                    Op::Binary(Binary::Prefix),
                ],
            ))
        );

        assert_eq!(
            super::expr("$0.matches(\"abc[0-9]+\")").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(var("0")),
                    Op::Value(string("abc[0-9]+")),
                    Op::Binary(Binary::Regex),
                ],
            ))
        );

        let h = [string("abc"), string("def")]
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            super::expr("{\"abc\", \"def\"}.contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h.clone())),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                ],
            ))
        );

        assert_eq!(
            super::expr("!{\"abc\", \"def\"}.contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h.clone())),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                    Op::Unary(Unary::Negate),
                ],
            ))
        );

        let h = [string("abc"), string("def")]
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            super::expr("{\"abc\", \"def\"}.contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h.clone())),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                ],
            ))
        );

        assert_eq!(
            super::expr("!{\"abc\", \"def\"}.contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set(h.clone())),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                    Op::Unary(Unary::Negate),
                ],
            ))
        );

        assert_eq!(
            super::expr("1 + 2 | 4 * 3 & 4").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::Add),
                    Op::Value(int(4)),
                    Op::Value(int(3)),
                    Op::Binary(Binary::Mul),
                    Op::Value(int(4)),
                    Op::Binary(Binary::BitwiseAnd),
                    Op::Binary(Binary::BitwiseOr),
                ],
            ))
        );
    }

    #[test]
    fn fact() {
        assert_eq!(
            super::fact("right( \"file1\", \"read\" )"),
            Ok((
                "",
                builder::fact(
                    "right",
                    &[builder::string("file1"), builder::string("read")]
                )
            ))
        );
    }

    #[test]
    fn fact_with_variable() {
        use nom::error::ErrorKind;
        assert_eq!(
            super::fact("right( \"file1\", $operation )"),
            Err(nom::Err::Failure(super::Error {
                code: ErrorKind::Char,
                input: "$operation",
                message: Some("variables are not allowed in facts".to_string()),
            }))
        );
    }

    #[test]
    fn fact_with_date() {
        assert_eq!(
            super::fact("date(2019-12-02T13:49:53Z)"),
            Ok((
                "",
                builder::fact("date", &[builder::Term::Date(1575294593)])
            ))
        );
    }

    #[test]
    fn rule() {
        assert_eq!(
            super::rule("right($0, \"read\") <- resource( $0), operation(\"read\")"),
            Ok((
                "",
                builder::rule(
                    "right",
                    &[builder::variable("0"), builder::string("read"),],
                    &[
                        builder::pred("resource", &[builder::variable("0")]),
                        builder::pred("operation", &[builder::string("read")]),
                    ],
                )
            ))
        );
    }

    #[test]
    fn constrained_rule() {
        use builder::{date, var, Binary, Expression, Op};
        use std::time::{Duration, SystemTime};

        assert_eq!(
            super::rule("valid_date(\"file1\") <- time($0 ), resource(\"file1\"), $0 <= 2019-12-04T09:46:41+00:00"),
            Ok((
                "",
                builder::constrained_rule(
                    "valid_date",
                    &[builder::string("file1")],
                    &[
                        builder::pred("time", &[builder::variable("0")]),
                        builder::pred("resource", &[builder::string("file1")]),
                    ],
                    &[Expression {
                        ops: vec![
                            Op::Value(var("0")),
                            Op::Value(date(&(SystemTime::UNIX_EPOCH + Duration::from_secs(1575452801)))),
                            Op::Binary(Binary::LessOrEqual),
                        ]
                    }],
                )
            ))
        );
    }

    #[test]
    fn constrained_rule_ordering() {
        use builder::{date, var, Binary, Expression, Op};
        use std::time::{Duration, SystemTime};

        assert_eq!(
            super::rule("valid_date(\"file1\") <- time( $0 ), $0 <= 2019-12-04T09:46:41+00:00, resource(\"file1\")"),
            Ok((
                "",
                builder::constrained_rule(
                    "valid_date",
                    &[
                        builder::string("file1"),
                    ],
                    &[
                        builder::pred("time", &[builder::variable("0")]),
                        builder::pred("resource", &[builder::string("file1")]),
                    ],
                    &[Expression {
                        ops: vec![
                            Op::Value(var("0")),
                            Op::Value(date(&(SystemTime::UNIX_EPOCH + Duration::from_secs(1575452801)))),
                            Op::Binary(Binary::LessOrEqual),
                        ]
                    }],
                )
            ))
        );
    }

    #[test]
    fn rule_with_unused_head_variables() {
        assert_eq!(
            super::rule("right($0, $test) <- resource($0), operation(\"read\")"),
            Err( nom::Err::Failure(Error {
                input: "right($0, $test) <- resource($0), operation(\"read\")",
                code: ErrorKind::Satisfy,
                message: Some("the rule contains variables that are not bound by predicates in the rule's body: $test".to_string()),
            }))
        );
    }

    #[test]
    fn check() {
        let empty: &[builder::Term] = &[];
        assert_eq!(
            super::check("check if resource( $0), operation(\"read\") or admin(\"authority\")"),
            Ok((
                "",
                builder::Check {
                    kind: builder::CheckKind::One,
                    queries: vec![
                        builder::rule(
                            "query",
                            empty,
                            &[
                                builder::pred("resource", &[builder::variable("0")]),
                                builder::pred("operation", &[builder::string("read")]),
                            ]
                        ),
                        builder::rule(
                            "query",
                            empty,
                            &[builder::pred("admin", &[builder::string("authority")]),]
                        ),
                    ]
                }
            ))
        );
    }

    #[test]
    fn invalid_check() {
        assert_eq!(
            super::check(
                "check if resource($0) and operation(\"read\") or admin(\"authority\")"
            ),
            Err( nom::Err::Error(Error {
                input: "and",
                code: ErrorKind::Eof,
                message: Some("expected either the next term after ',' or the next check variant after 'or', but got 'and'".to_string()),
            }))
        );

        assert_eq!(
            super::check("check if resource(\"{}\"), operation(\"write\")) or operation(\"read\")"),
            Err(nom::Err::Error(Error {
                input: ")",
                code: ErrorKind::Eof,
                message: Some("unexpected parens".to_string()),
            }))
        );

        assert_eq!(
            super::check(
                "check if resource(\"{}\") && operation(\"write\")) || operation(\"read\")"
            ),
            Err( nom::Err::Error(Error {
                input: "&&",
                code: ErrorKind::Eof,
                message: Some("expected either the next term after ',' or the next check variant after 'or', but got '&&'".to_string()),
            }))
        );
    }

    #[test]
    fn expression() {
        use super::Expr;
        use builder::{date, int, string, var, Binary, Op, Term};
        use std::time::{Duration, SystemTime};

        let input = " -1 ";
        println!("parsing: {}", input);
        let res = super::expr(input);
        assert_eq!(res, Ok((" ", Expr::Value(Term::Integer(-1)))));

        let ops = res.unwrap().1.opcodes();
        println!("ops: {:#?}", ops);

        let input = " $0 <= 2019-12-04T09:46:41+00:00";
        println!("parsing: {}", input);
        let res = super::expr(input);
        assert_eq!(
            res,
            Ok((
                "",
                Expr::Binary(
                    Op::Binary(Binary::LessOrEqual),
                    Box::new(Expr::Value(var("0"))),
                    Box::new(Expr::Value(date(
                        &(SystemTime::UNIX_EPOCH + Duration::from_secs(1575452801))
                    )))
                )
            ))
        );

        let ops = res.unwrap().1.opcodes();
        println!("ops: {:#?}", ops);
        let input = " 1 < $test + 2 ";
        println!("parsing: {}", input);
        let res = super::expr(input);
        assert_eq!(
            res,
            Ok((
                " ",
                Expr::Binary(
                    Op::Binary(Binary::LessThan),
                    Box::new(Expr::Value(int(1))),
                    Box::new(Expr::Binary(
                        Op::Binary(Binary::Add),
                        Box::new(Expr::Value(var("test"))),
                        Box::new(Expr::Value(int(2))),
                    ))
                )
            ))
        );

        let ops = res.unwrap().1.opcodes();
        println!("ops: {:#?}", ops);

        let input = " 2 < $test && $var2.starts_with(\"test\") && true ";
        println!("parsing: {}", input);
        let res = super::expr(input);
        assert_eq!(
            res,
            Ok((
                " ",
                Expr::Binary(
                    Op::Binary(Binary::LazyAnd),
                    Box::new(Expr::Binary(
                        Op::Binary(Binary::LazyAnd),
                        Box::new(Expr::Binary(
                            Op::Binary(Binary::LessThan),
                            Box::new(Expr::Value(int(2))),
                            Box::new(Expr::Value(var("test"))),
                        )),
                        Box::new(Expr::Closure(
                            vec![],
                            Box::new(Expr::Binary(
                                Op::Binary(Binary::Prefix),
                                Box::new(Expr::Value(var("var2"))),
                                Box::new(Expr::Value(string("test"))),
                            ))
                        )),
                    )),
                    Box::new(Expr::Closure(
                        vec![],
                        Box::new(Expr::Value(Term::Bool(true))),
                    ))
                )
            ))
        );
        let ops = res.unwrap().1.opcodes();
        println!("ops: {:#?}", ops);
    }

    #[test]
    fn parens() {
        use builder::{int, Binary, Op, Unary};

        let input = " 1 + 2 * 3 ";
        println!("parsing: {}", input);
        let (_, res) = super::expr(input).unwrap();

        let ops = res.opcodes();
        println!("ops: {:#?}", ops);

        assert_eq!(
            ops,
            vec![
                Op::Value(int(1)),
                Op::Value(int(2)),
                Op::Value(int(3)),
                Op::Binary(Binary::Mul),
                Op::Binary(Binary::Add),
            ]
        );

        let input = " (1 + 2) * 3 ";
        println!("parsing: {}", input);
        let (_, res) = super::expr(input).unwrap();

        let ops = res.opcodes();
        println!("ops: {:#?}", ops);

        assert_eq!(
            ops,
            vec![
                Op::Value(int(1)),
                Op::Value(int(2)),
                Op::Binary(Binary::Add),
                Op::Unary(Unary::Parens),
                Op::Value(int(3)),
                Op::Binary(Binary::Mul),
            ]
        );
    }

    #[test]
    fn source_file() {
        use builder::{
            boolean, constrained_rule, fact, int, pred, rule, string, var, Binary, Check,
            Expression, Op, Policy, PolicyKind,
        };
        use std::time::{Duration, SystemTime};

        let input = r#"
          fact("string");
          fact2(1234);

          rule_head($var0) <- fact($var0, $var1), 1 < 2;

          // line comment
          check if 1 === 2;

          allow if rule_head("string");

          /*
           other comment
          */
    check if
              fact(5678)
              or fact(1234), "test".starts_with("abc");

          check if 2021-01-01T00:00:00Z <= 2021-01-01T00:00:00Z;

          deny if true;
        "#;

        let res = super::parse_source(input);
        println!("parse_source res:\n{:#?}", res);

        let empty_terms: &[builder::Term] = &[];
        let empty_preds: &[builder::Predicate] = &[];

        let expected_facts = vec![
            fact("fact", &[string("string")]),
            fact("fact2", &[int(1234)]),
        ];

        let expected_rules = vec![constrained_rule(
            "rule_head",
            &[var("var0")],
            &[pred("fact", &[var("var0"), var("var1")])],
            &[Expression {
                ops: vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::LessThan),
                ],
            }],
        )];

        let expected_checks = vec![
            Check {
                kind: CheckKind::One,
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![
                            Op::Value(int(1)),
                            Op::Value(int(2)),
                            Op::Binary(Binary::Equal),
                        ],
                    }],
                )],
            },
            Check {
                kind: CheckKind::One,
                queries: vec![
                    rule("query", empty_terms, &[pred("fact", &[int(5678)])]),
                    constrained_rule(
                        "query",
                        empty_terms,
                        &[pred("fact", &[int(1234)])],
                        &[Expression {
                            ops: vec![
                                Op::Value(string("test")),
                                Op::Value(string("abc")),
                                Op::Binary(Binary::Prefix),
                            ],
                        }],
                    ),
                ],
            },
            Check {
                kind: CheckKind::One,
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![
                            Op::Value(builder::date(
                                &(SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200)),
                            )),
                            Op::Value(builder::date(
                                &(SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200)),
                            )),
                            Op::Binary(Binary::LessOrEqual),
                        ],
                    }],
                )],
            },
        ];

        let expected_policies = vec![
            Policy {
                kind: PolicyKind::Allow,
                queries: vec![rule(
                    "query",
                    empty_terms,
                    &[pred("rule_head", &[string("string")])],
                )],
            },
            Policy {
                kind: PolicyKind::Deny,
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![Op::Value(boolean(true))],
                    }],
                )],
            },
        ];

        let mut result = res.unwrap();
        assert_eq!(
            result.facts.drain(..).map(|(_, r)| r).collect::<Vec<_>>(),
            expected_facts
        );
        assert_eq!(
            result.rules.drain(..).map(|(_, r)| r).collect::<Vec<_>>(),
            expected_rules
        );
        assert_eq!(
            result.checks.drain(..).map(|(_, r)| r).collect::<Vec<_>>(),
            expected_checks
        );
        assert_eq!(
            result
                .policies
                .drain(..)
                .map(|(_, r)| r)
                .collect::<Vec<_>>(),
            expected_policies
        );
    }

    #[test]
    fn block_source_file() {
        use builder::{
            constrained_rule, fact, int, pred, rule, string, var, Binary, Check, Expression, Op,
        };
        use std::time::{Duration, SystemTime};

        let input = r#"
          fact("string");
          fact2(1234);

    rule_head($var0) <- fact($var0, $var1), 1 < 2; // line comment
    check if 1 === 2; /*
                      other comment
                     */
    check if
              fact(5678)
              or fact(1234), "test".starts_with("abc");

          check if 2021-01-01T00:00:00Z <= 2021-01-01T00:00:00Z;
        "#;

        let res = super::parse_block_source(input);
        println!("parse_block_source res:\n{:#?}", res);

        let empty_terms: &[builder::Term] = &[];
        let empty_preds: &[builder::Predicate] = &[];

        let expected_facts = vec![
            fact("fact", &[string("string")]),
            fact("fact2", &[int(1234)]),
        ];

        let expected_rules = vec![constrained_rule(
            "rule_head",
            &[var("var0")],
            &[pred("fact", &[var("var0"), var("var1")])],
            &[Expression {
                ops: vec![
                    Op::Value(int(1)),
                    Op::Value(int(2)),
                    Op::Binary(Binary::LessThan),
                ],
            }],
        )];

        let expected_checks = vec![
            Check {
                kind: CheckKind::One,
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![
                            Op::Value(int(1)),
                            Op::Value(int(2)),
                            Op::Binary(Binary::Equal),
                        ],
                    }],
                )],
            },
            Check {
                kind: CheckKind::One,
                queries: vec![
                    rule("query", empty_terms, &[pred("fact", &[int(5678)])]),
                    constrained_rule(
                        "query",
                        empty_terms,
                        &[pred("fact", &[int(1234)])],
                        &[Expression {
                            ops: vec![
                                Op::Value(string("test")),
                                Op::Value(string("abc")),
                                Op::Binary(Binary::Prefix),
                            ],
                        }],
                    ),
                ],
            },
            Check {
                kind: CheckKind::One,
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![
                            Op::Value(builder::date(
                                &(SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200)),
                            )),
                            Op::Value(builder::date(
                                &(SystemTime::UNIX_EPOCH + Duration::from_secs(1609459200)),
                            )),
                            Op::Binary(Binary::LessOrEqual),
                        ],
                    }],
                )],
            },
        ];

        let mut result = res.unwrap();
        assert_eq!(
            result.facts.drain(..).map(|(_, r)| r).collect::<Vec<_>>(),
            expected_facts
        );
        assert_eq!(
            result.rules.drain(..).map(|(_, r)| r).collect::<Vec<_>>(),
            expected_rules
        );
        assert_eq!(
            result.checks.drain(..).map(|(_, r)| r).collect::<Vec<_>>(),
            expected_checks
        );
    }

    #[test]
    fn chained_calls() {
        use builder::{int, set, Binary, Op};

        assert_eq!(
            super::expr("{1}.intersection({2}).contains(3)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set([int(1)].into_iter().collect())),
                    Op::Value(set([int(2)].into_iter().collect())),
                    Op::Binary(Binary::Intersection),
                    Op::Value(int(3)),
                    Op::Binary(Binary::Contains)
                ],
            ))
        );

        assert_eq!(
            super::expr("{1}.intersection({2}).union({3}).length()").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set([int(1)].into_iter().collect())),
                    Op::Value(set([int(2)].into_iter().collect())),
                    Op::Binary(Binary::Intersection),
                    Op::Value(set([int(3)].into_iter().collect())),
                    Op::Binary(Binary::Union),
                    Op::Unary(Unary::Length),
                ],
            ))
        );

        assert_eq!(
            super::expr("{1}.intersection({2}).length().union({3})").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(set([int(1)].into_iter().collect())),
                    Op::Value(set([int(2)].into_iter().collect())),
                    Op::Binary(Binary::Intersection),
                    Op::Unary(Unary::Length),
                    Op::Value(set([int(3)].into_iter().collect())),
                    Op::Binary(Binary::Union),
                ],
            ))
        );
    }

    #[test]
    fn arrays() {
        let h = vec![int(1), int(2)];
        assert_eq!(
            super::expr("[1, 2].contains($0)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(array(h.clone())),
                    Op::Value(var("0")),
                    Op::Binary(Binary::Contains),
                ]
            ))
        )
    }

    #[test]
    fn extern_funcs() {
        use builder::{int, Binary, Op};

        assert_eq!(
            super::expr("2.extern::toto()").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![Op::Value(int(2)), Op::Unary(Unary::Ffi("toto".to_string()))],
            ))
        );

        assert_eq!(
            super::expr("2.extern::toto(3)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Value(int(2)),
                    Op::Value(int(3)),
                    Op::Binary(Binary::Ffi("toto".to_string())),
                ],
            ))
        );
    }

    #[test]
    fn empty_set_map() {
        use builder::{map, set};

        assert_eq!(
            super::expr("{,}").map(|(i, o)| (i, o.opcodes())),
            Ok(("", vec![Op::Value(set(Default::default()))],))
        );
        assert_eq!(
            super::expr("{}").map(|(i, o)| (i, o.opcodes())),
            Ok(("", vec![Op::Value(map(Default::default()))],))
        );
    }

    #[test]
    fn try_expr() {
        use builder::{boolean, Binary, Op, Unary};
        assert_eq!(
            super::expr("true.length().try_or(false)").map(|(i, o)| (i, o.opcodes())),
            Ok((
                "",
                vec![
                    Op::Closure(
                        vec![],
                        vec![Op::Value(boolean(true)), Op::Unary(Unary::Length)]
                    ),
                    Op::Value(boolean(false)),
                    Op::Binary(Binary::TryOr)
                ],
            ))
        );
    }
}
