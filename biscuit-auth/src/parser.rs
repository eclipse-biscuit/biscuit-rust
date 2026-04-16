/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Datalog text format parsing
//!
//! all of the parsers are usable with [`std::convert::TryFrom`] so they can be used
//! as follows:
//!
//! ```rust
//! use std::convert::TryInto;
//! use biscuit_auth::builder::Fact;
//!
//! let f: Fact = "test(\"data\")".try_into().expect("parse error");
//! ```
//!
//! All of the methods in [BiscuitBuilder](`crate::token::builder::BiscuitBuilder`)
//! and [BlockBuilder](`crate::token::builder::BlockBuilder`) can take strings
//! as arguments too

pub use biscuit_parser::parser::*;

#[cfg(test)]
mod tests {
    use crate::{
        builder::{CheckKind, Convert},
        datalog,
        token::builder,
    };
    use biscuit_parser::parser::*;
    use nom::error::ErrorKind;

    #[derive(Debug, PartialEq)]
    enum Expr {
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
                Expr::Closure(params, body) => {
                    let mut ops = vec![];
                    body.into_opcodes(&mut ops);
                    v.push(builder::Op::Closure(params, ops));
                }
            }
        }
    }

    impl From<biscuit_parser::parser::Expr> for Expr {
        fn from(e: biscuit_parser::parser::Expr) -> Self {
            match e {
                biscuit_parser::parser::Expr::Value(v) => Expr::Value(v.into()),
                biscuit_parser::parser::Expr::Unary(op, expr) => {
                    Expr::Unary(op.into(), Box::new((*expr).into()))
                }
                biscuit_parser::parser::Expr::Binary(op, expr1, expr2) => Expr::Binary(
                    op.into(),
                    Box::new((*expr1).into()),
                    Box::new((*expr2).into()),
                ),
                biscuit_parser::parser::Expr::Closure(params, body) => {
                    Expr::Closure(params, Box::new((*body).into()))
                }
            }
        }
    }

    #[test]
    fn rule() {
        assert_eq!(
            biscuit_parser::parser::rule(
                "right($0, \"read\") <- resource( $0), operation(\"read\")"
            )
            .map(|(i, o)| (i, o.into())),
            Ok((
                "",
                builder::rule(
                    "right",
                    &[builder::variable("0"), builder::string("read"),],
                    &[
                        builder::pred("resource", &[builder::variable("0")]),
                        builder::pred("operation", &[builder::string("read")]),
                    ]
                )
            ))
        );
    }

    #[test]
    fn constrained_rule() {
        use builder::{date, var, Binary, Expression, Op};
        use std::time::{Duration, SystemTime};

        assert_eq!(
            biscuit_parser::parser::rule("valid_date(\"file1\") <- time($0 ), resource(\"file1\"), $0 <= 2019-12-04T09:46:41+00:00").map(|(i, o)| (i, o.into())),
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
    fn constrained_rule_ordering() {
        use builder::{date, var, Binary, Expression, Op};
        use std::time::{Duration, SystemTime};

        assert_eq!(
            biscuit_parser::parser::rule("valid_date(\"file1\") <- time( $0 ), $0 <= 2019-12-04T09:46:41+00:00, resource(\"file1\")").map(|(i, o)| (i, o.into())),
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
    fn rule_with_free_head_variables() {
        assert_eq!(
            biscuit_parser::parser::rule("right($0, $test) <- resource($0), operation(\"read\")"),
            Err( nom::Err::Failure(Error {
                input: "right($0, $test) <- resource($0), operation(\"read\")",
                code: ErrorKind::Satisfy,
                message: Some("the rule contains variables that are not bound by predicates in the rule's body: $test".to_string()),
            }))
        );
    }

    #[test]
    fn rule_with_free_expression_variables() {
        assert_eq!(
            biscuit_parser::parser::rule("right($0) <- resource($0), operation(\"read\"), $test"),
            Err( nom::Err::Failure(Error {
                input: "right($0) <- resource($0), operation(\"read\"), $test",
                code: ErrorKind::Satisfy,
                message: Some("the rule contains variables that are not bound by predicates in the rule's body: $test".to_string()),
            }))
        );
    }

    #[test]
    fn check() {
        let empty: &[builder::Term] = &[];
        assert_eq!(
            biscuit_parser::parser::check(
                "check if resource( $0), operation(\"read\") or admin(\"authority\")"
            )
            .map(|(i, o)| (i, o.into())),
            Ok((
                "",
                builder::Check {
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
                    ],
                    kind: CheckKind::One,
                }
            ))
        );
    }

    #[test]
    fn invalid_check() {
        assert_eq!(
            biscuit_parser::parser::check(
                "check if resource($0) and operation(\"read\") or admin(\"authority\")"
            ),
            Err( nom::Err::Error(Error {
                input: "and",
                code: ErrorKind::Eof,
                message: Some("expected either the next term after ',' or the next check variant after 'or', but got 'and'".to_string()),
            }))
        );

        assert_eq!(
            biscuit_parser::parser::check(
                "check if resource(\"{}\"), operation(\"write\")) or operation(\"read\")"
            ),
            Err(nom::Err::Error(Error {
                input: ")",
                code: ErrorKind::Eof,
                message: Some("unexpected parens".to_string()),
            }))
        );

        assert_eq!(
            biscuit_parser::parser::check(
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
        use crate::datalog::SymbolTable;
        //use biscuit_parser::parser::Expr;
        use builder::{date, int, string, var, Binary, Op, Term};
        use std::time::{Duration, SystemTime};

        let mut syms = SymbolTable::new();

        let input = " -1 ";
        println!("parsing: {input}");
        let res = biscuit_parser::parser::expr(input).map(|(i, o)| (i, o.into()));
        assert_eq!(res, Ok((" ", Expr::Value(Term::Integer(-1)))));

        let ops = res.unwrap().1.opcodes();
        println!("ops: {ops:#?}");
        let e = builder::Expression { ops }.convert(&mut syms);
        println!("print: {}", e.print(&syms).unwrap());

        let input = " $0 <= 2019-12-04T09:46:41+00:00";
        println!("parsing: {input}");
        let res = biscuit_parser::parser::expr(input).map(|(i, o)| (i, o.into()));
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
        println!("ops: {ops:#?}");
        let e = builder::Expression { ops }.convert(&mut syms);
        println!("print: {}", e.print(&syms).unwrap());

        let input = " 1 < $test + 2 ";
        println!("parsing: {input}");
        let res: Result<(&str, Expr), _> =
            biscuit_parser::parser::expr(input).map(|(i, o)| (i, o.into()));
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
        println!("ops: {ops:#?}");
        let e = builder::Expression { ops }.convert(&mut syms);
        println!("print: {}", e.print(&syms).unwrap());

        let input = " 2 < $test && $var2.starts_with(\"test\") && true ";
        println!("parsing: {input}");
        let res = biscuit_parser::parser::expr(input).map(|(i, o)| (i, o.into()));
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
                                Box::new(Expr::Value(string("test")))
                            ),)
                        ))
                    )),
                    Box::new(Expr::Closure(
                        vec![],
                        Box::new(Expr::Value(Term::Bool(true)))
                    )),
                ),
            ))
        );

        let ops = res.unwrap().1.opcodes();
        println!("ops: {ops:#?}");
        let e = builder::Expression { ops }.convert(&mut syms);
        println!("print: {}", e.print(&syms).unwrap());

        //panic!();
    }

    #[test]
    fn parens() {
        use crate::datalog::{SymbolTable, TemporarySymbolTable};
        use builder::{int, Binary, Op, Unary};
        use std::collections::HashMap;

        let mut syms = SymbolTable::new();

        let input = " 1 + 2 * 3 ";
        println!("parsing: {input}");
        let (_, res): (_, Expr) = biscuit_parser::parser::expr(input)
            .map(|(i, o)| (i, o.into()))
            .unwrap();

        let ops = res.opcodes();
        println!("ops: {ops:#?}");
        let e = builder::Expression { ops: ops.clone() }.convert(&mut syms);

        let printed = e.print(&syms).unwrap();
        println!("print: {}", e.print(&syms).unwrap());
        let h = HashMap::new();
        let result = e
            .evaluate(
                &h,
                &mut TemporarySymbolTable::new(&syms),
                &Default::default(),
            )
            .unwrap();
        println!("evaluates to: {result:?}");

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
        assert_eq!(&printed, "1 + 2 * 3");
        assert_eq!(result, datalog::Term::Integer(7));

        let input = " (1 + 2) * 3 ";
        println!("parsing: {input}");
        let (_, res): (_, Expr) = biscuit_parser::parser::expr(input)
            .map(|(i, o)| (i, o.into()))
            .unwrap();

        let ops = res.opcodes();
        println!("ops: {ops:#?}");
        let e = builder::Expression { ops: ops.clone() }.convert(&mut syms);

        let printed = e.print(&syms).unwrap();
        println!("print: {}", e.print(&syms).unwrap());
        let h = HashMap::new();
        let result = e
            .evaluate(
                &h,
                &mut TemporarySymbolTable::new(&syms),
                &Default::default(),
            )
            .unwrap();
        println!("evaluates to: {result:?}");

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
        assert_eq!(&printed, "(1 + 2) * 3");
        assert_eq!(result, datalog::Term::Integer(9));
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
          check if 1 == 2;

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

        let res = biscuit_parser::parser::parse_source(input);
        println!("parse_source res:\n{res:#?}");

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
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![
                            Op::Value(int(1)),
                            Op::Value(int(2)),
                            Op::Binary(Binary::HeterogeneousEqual),
                        ],
                    }],
                )],
                kind: CheckKind::One,
            },
            Check {
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
                kind: CheckKind::One,
            },
            Check {
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
                kind: CheckKind::One,
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
            result
                .facts
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Fact>>(),
            expected_facts
        );
        assert_eq!(
            result
                .rules
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Rule>>(),
            expected_rules
        );
        assert_eq!(
            result
                .checks
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Check>>(),
            expected_checks
        );
        assert_eq!(
            result
                .policies
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Policy>>(),
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
    check if 1 == 2; /*
                      other comment
                     */
    check if
              fact(5678)
              or fact(1234), "test".starts_with("abc");

          check if 2021-01-01T00:00:00Z <= 2021-01-01T00:00:00Z;
        "#;

        let res = biscuit_parser::parser::parse_block_source(input);
        println!("parse_block_source res:\n{res:#?}");

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
                queries: vec![constrained_rule(
                    "query",
                    empty_terms,
                    empty_preds,
                    &[Expression {
                        ops: vec![
                            Op::Value(int(1)),
                            Op::Value(int(2)),
                            Op::Binary(Binary::HeterogeneousEqual),
                        ],
                    }],
                )],
                kind: CheckKind::One,
            },
            Check {
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
                kind: CheckKind::One,
            },
            Check {
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
                kind: CheckKind::One,
            },
        ];

        let mut result = res.unwrap();
        assert_eq!(
            result
                .facts
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Fact>>(),
            expected_facts
        );
        assert_eq!(
            result
                .rules
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Rule>>(),
            expected_rules
        );
        assert_eq!(
            result
                .checks
                .drain(..)
                .map(|(_, r)| r.into())
                .collect::<Vec<builder::Check>>(),
            expected_checks
        );
    }
}
