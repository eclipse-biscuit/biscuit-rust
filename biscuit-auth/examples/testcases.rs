/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
#![cfg(feature = "serde-error")]
#![allow(unused_must_use)]
extern crate biscuit_auth as biscuit;

use biscuit::builder::BlockBuilder;
use biscuit::datalog::SymbolTable;
use biscuit::error;
use biscuit::format::convert;
use biscuit::macros::*;
use biscuit::{builder::*, builder_ext::*, Biscuit};
use biscuit::{KeyPair, PrivateKey, PublicKey};
use biscuit_auth::builder;
use biscuit_auth::builder::Algorithm;
use biscuit_auth::datalog::ExternFunc;
use biscuit_auth::datalog::RunLimits;
use prost::Message;
use rand::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Write,
    time::*,
};

fn main() {
    let mut args = std::env::args();
    args.next();
    let target = match args.next() {
        Some(arg) => arg,
        None => {
            println!("missing target directory argument");
            return;
        }
    };

    let mut test = false;
    let mut json = false;
    let mut root_key = None;

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some("--key") => root_key = args.next(),
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some("--key") => root_key = args.next(),
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    match args.next().as_deref() {
        Some("--test") => test = true,
        Some("--json") => json = true,
        Some("--key") => root_key = args.next(),
        Some(arg) => {
            println!("unknown argument: {}", arg);
            return;
        }
        None => {}
    };

    run(target, root_key, test, json);
}

fn run(target: String, root_key: Option<String>, test: bool, json: bool) {
    let root = if let Some(key) = root_key {
        KeyPair::from(&PrivateKey::from_bytes_hex(&key, Algorithm::Ed25519).unwrap())
    } else {
        let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
        KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng)
    };

    let mut results = Vec::new();

    add_test_result(&mut results, basic_token(&target, &root, test));

    add_test_result(&mut results, different_root_key(&target, &root, test));

    add_test_result(&mut results, invalid_signature_format(&target, &root, test));

    add_test_result(&mut results, random_block(&target, &root, test));

    add_test_result(&mut results, invalid_signature(&target, &root, test));

    add_test_result(&mut results, reordered_blocks(&target, &root, test));

    add_test_result(&mut results, scoped_rules(&target, &root, test));

    add_test_result(&mut results, scoped_checks(&target, &root, test));

    add_test_result(&mut results, expired_token(&target, &root, test));

    add_test_result(&mut results, authorizer_scope(&target, &root, test));

    add_test_result(
        &mut results,
        authorizer_authority_checks(&target, &root, test),
    );

    add_test_result(&mut results, authority_checks(&target, &root, test));

    add_test_result(&mut results, block_rules(&target, &root, test));

    add_test_result(&mut results, regex_constraint(&target, &root, test));

    add_test_result(&mut results, multi_queries_checks(&target, &root, test));

    add_test_result(&mut results, check_head_name(&target, &root, test));

    add_test_result(&mut results, expressions(&target, &root, test));

    add_test_result(
        &mut results,
        unbound_variables_in_rule(&target, &root, test),
    );

    add_test_result(
        &mut results,
        generating_ambient_from_variables(&target, &root, test),
    );

    add_test_result(&mut results, sealed_token(&target, &root, test));

    add_test_result(&mut results, parsing(&target, &root, test));

    add_test_result(&mut results, default_symbols(&target, &root, test));

    add_test_result(&mut results, execution_scope(&target, &root, test));

    add_test_result(&mut results, third_party(&target, &root, test));

    add_test_result(&mut results, check_all(&target, &root, test));

    add_test_result(&mut results, public_keys_interning(&target, &root, test));

    add_test_result(&mut results, integer_wraparound(&target, &root, test));

    add_test_result(&mut results, expressions_v4(&target, &root, test));

    add_test_result(&mut results, reject_if(&target, &root, test));

    add_test_result(&mut results, null(&target, &root, test));

    add_test_result(&mut results, heterogeneous_equal(&target, &root, test));

    add_test_result(&mut results, closures(&target, &root, test));

    add_test_result(&mut results, type_of(&target, &root, test));

    add_test_result(&mut results, array_map(&target, &root, test));

    add_test_result(&mut results, ffi(&target, &root, test));

    add_test_result(&mut results, secp256r1(&target, &root, test));

    add_test_result(&mut results, secp256r1_third_party(&target, &root, test));

    add_test_result(&mut results, try_op(&target, &root, test));

    if json {
        let s = serde_json::to_string_pretty(&TestCases {
            root_private_key: hex::encode(root.private().to_bytes()),
            root_public_key: hex::encode(root.public().to_bytes()),
            testcases: results,
        })
        .unwrap();

        println!("{}", s);
    } else {
        println!("# Biscuit samples and expected results\n");
        println!(
            "root secret key: {}",
            hex::encode(root.private().to_bytes())
        );
        println!("root public key: {}", hex::encode(root.public().to_bytes()));

        for result in results {
            println!("\n------------------------------\n");
            println!("{}", result.print());
        }
    }
}

#[derive(Debug, Serialize)]
struct TestCases {
    pub root_private_key: String,
    pub root_public_key: String,
    pub testcases: Vec<TestResult>,
}

#[derive(Debug, Serialize)]
struct TestResult {
    pub title: String,
    pub filename: String,
    pub token: Vec<BlockContent>,
    pub validations: BTreeMap<String, Validation>,
}

#[derive(Debug, Serialize)]
struct BlockContent {
    pub symbols: Vec<String>,
    pub public_keys: Vec<String>,
    pub external_key: Option<String>,
    pub code: String,
    pub version: u32,
}

#[derive(Debug, Serialize)]
struct Validation {
    world: Option<AuthorizerWorld>,
    result: AuthorizerResult,
    authorizer_code: String,
    revocation_ids: Vec<String>,
}

impl TestResult {
    fn print(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();

        writeln!(&mut s, "## {}: {}", self.title, self.filename);

        writeln!(&mut s, "### token\n");
        for (i, block) in self.token.iter().enumerate() {
            if i == 0 {
                writeln!(&mut s, "authority:");
            } else {
                writeln!(&mut s, "{}:", i);
            }

            writeln!(&mut s, "symbols: {:?}\n", block.symbols);
            writeln!(&mut s, "public keys: {:?}\n", block.public_keys);
            if let Some(key) = &block.external_key {
                writeln!(&mut s, "external signature by: {:?}\n", key);
            }
            writeln!(&mut s, "block version: {}\n", block.version);
            writeln!(&mut s, "```\n{}```\n", block.code);
        }

        for (name, validation) in &self.validations {
            if name.is_empty() {
                writeln!(&mut s, "### validation\n")
            } else {
                writeln!(&mut s, "### validation for \"{}\"\n", name)
            };

            if let Some(world) = &validation.world {
                writeln!(
                    &mut s,
                    "authorizer code:\n```\n{}```\n",
                    validation.authorizer_code
                );

                writeln!(&mut s, "revocation ids:");
                for id in &validation.revocation_ids {
                    writeln!(&mut s, "- `{}`", id);
                }
                writeln!(&mut s, "\nauthorizer world:\n```\nWorld {{\n  facts: {:#?}\n  rules: {:#?}\n  checks: {:#?}\n  policies: {:#?}\n}}\n```\n",
                         world.facts, world.rules, world.checks, world.policies);
            }

            writeln!(&mut s, "result: `{:?}`", validation.result);
        }

        s
    }
}

#[derive(Debug, Serialize)]
struct AuthorizerWorld {
    pub facts: Vec<Facts>,
    pub rules: Vec<Rules>,
    pub checks: Vec<Checks>,
    pub policies: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Facts {
    origin: BTreeSet<Option<usize>>,
    facts: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Rules {
    origin: Option<usize>,
    rules: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Checks {
    origin: Option<usize>,
    checks: Vec<String>,
}

#[derive(Debug, Serialize)]
enum AuthorizerResult {
    Ok(usize),
    Err(error::Token),
}

fn validate_token(root: &KeyPair, data: &[u8], authorizer_code: &str) -> Validation {
    validate_token_with_limits_and_external_functions(
        root,
        data,
        authorizer_code,
        RunLimits::default(),
        Default::default(),
    )
}

fn validate_token_with_limits_and_external_functions(
    root: &KeyPair,
    data: &[u8],
    authorizer_code: &str,
    run_limits: RunLimits,
    extern_funcs: HashMap<String, ExternFunc>,
) -> Validation {
    let token = match Biscuit::from(&data[..], &root.public()) {
        Ok(t) => t,
        Err(e) => {
            return Validation {
                world: None,
                authorizer_code: String::new(),
                result: AuthorizerResult::Err(e),
                revocation_ids: vec![],
            }
        }
    };

    let mut revocation_ids = vec![];

    for bytes in token.revocation_identifiers() {
        revocation_ids.push(hex::encode(&bytes));
    }

    let builder = AuthorizerBuilder::new()
        .set_extern_funcs(extern_funcs)
        .code(authorizer_code)
        .unwrap();
    let authorizer_code = builder.dump_code();

    let mut authorizer = match builder.build(&token) {
        Ok(v) => v,
        Err(e) => {
            return Validation {
                world: None,
                authorizer_code: String::new(),
                result: AuthorizerResult::Err(e),
                revocation_ids,
            }
        }
    };

    let res = authorizer.authorize_with_limits(run_limits);
    //println!("authorizer world:\n{}", authorizer.print_world());
    let (_, _, _, policies) = authorizer.dump();
    let snapshot = authorizer.snapshot().unwrap();

    let symbols = SymbolTable::from_symbols_and_public_keys(
        snapshot.world.symbols,
        snapshot
            .world
            .public_keys
            .iter()
            .map(|k| PublicKey::from_proto(k).unwrap())
            .collect(),
    )
    .unwrap();

    let mut authorizer_facts = Vec::new();
    let mut authorizer_rules = Vec::new();
    let mut authorizer_checks = Vec::new();
    for (i, block) in snapshot.world.blocks.iter().enumerate() {
        let mut rules: Vec<String> = Vec::new();
        for rule in block.rules.iter() {
            let r =
                convert::proto_rule_to_token_rule(&rule, snapshot.world.version.unwrap()).unwrap();
            rules.push(symbols.print_rule(&r.0));
        }
        if !rules.is_empty() {
            rules.sort();
            authorizer_rules.push(Rules {
                origin: Some(i),
                rules,
            });
        }

        let mut checks = Vec::new();
        for check in block.checks.iter() {
            let c = convert::proto_check_to_token_check(&check, snapshot.world.version.unwrap())
                .unwrap();
            checks.push(symbols.print_check(&c));
        }
        if !checks.is_empty() {
            checks.sort();
            authorizer_checks.push(Checks {
                origin: Some(i),
                checks,
            });
        }
    }

    let mut rules: Vec<String> = Vec::new();
    for rule in snapshot.world.authorizer_block.rules {
        let r = convert::proto_rule_to_token_rule(&rule, snapshot.world.version.unwrap()).unwrap();

        rules.push(symbols.print_rule(&r.0));
    }
    if !rules.is_empty() {
        rules.sort();
        authorizer_rules.push(Rules {
            origin: Some(usize::MAX),
            rules,
        });
    }

    let mut checks = Vec::new();
    for check in snapshot.world.authorizer_block.checks {
        let c =
            convert::proto_check_to_token_check(&check, snapshot.world.version.unwrap()).unwrap();
        checks.push(symbols.print_check(&c));
    }
    if !checks.is_empty() {
        checks.sort();
        authorizer_checks.push(Checks {
            origin: Some(usize::MAX),
            checks,
        });
    }

    for factset in snapshot.world.generated_facts {
        use biscuit_auth::format::schema::origin::Content;
        let mut origin = BTreeSet::new();

        for o in factset.origins {
            match o.content.unwrap() {
                Content::Authorizer(_) => origin.insert(None),
                Content::Origin(i) => origin.insert(Some(i as usize)),
            };
        }

        let mut facts = Vec::new();

        for fact in factset.facts {
            let f = convert::proto_fact_to_token_fact(&fact).unwrap();
            facts.push(symbols.print_fact(&f));
        }
        if !facts.is_empty() {
            facts.sort();
            authorizer_facts.push(Facts { origin, facts });
        }
    }
    authorizer_facts.sort();

    Validation {
        world: Some(AuthorizerWorld {
            facts: authorizer_facts,
            rules: authorizer_rules,
            checks: authorizer_checks,
            policies: policies.into_iter().map(|p| p.to_string()).collect(),
        }),
        result: match res {
            Ok(i) => AuthorizerResult::Ok(i),
            Err(e) => AuthorizerResult::Err(e),
        },
        authorizer_code,
        revocation_ids,
    }
}

fn add_test_result(results: &mut Vec<TestResult>, mut testcase: TestResult) {
    testcase.filename = format!("{}.bc", testcase.filename);
    results.push(testcase);
}

fn write_testcase(target: &str, name: &str, data: &[u8]) {
    //println!("written to: {}/{}", target, name);

    let mut file = File::create(&format!("{}/{}.bc", target, name)).unwrap();
    file.write_all(data).unwrap();
    file.flush().unwrap();
}

#[track_caller]
fn load_testcase(target: &str, name: &str) -> Vec<u8> {
    std::fs::read(&format!("{}/{}.bc", target, name)).unwrap()
}

fn print_diff(actual: &str, expected: &str) {
    if actual != expected {
        println!("{}", colored_diff::PrettyDifference { expected, actual })
    }
}

fn write_or_load_testcase(
    target: &str,
    filename: &str,
    root: &KeyPair,
    token: &Biscuit,
    test: bool,
) -> Vec<u8> {
    if test {
        let v = load_testcase(target, &filename);
        if let Ok(expected) = Biscuit::from(&v[..], root.public()) {
            print_diff(&token.print(), &expected.print());
        }
        v
    } else {
        let data = token.to_vec().unwrap();
        write_testcase(target, &filename, &data[..]);

        data
    }
}

fn basic_token(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "basic token".to_string();
    let filename = "test001_basic".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(
                r#"
            check if resource($0), operation("read"), right($0, "read")
            "#
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            resource("file1");
            allow if true;
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn different_root_key(target: &str, root: &KeyPair, test: bool) -> TestResult {
    // using a different seed otherwise it would generate the same root key
    let mut rng: StdRng = SeedableRng::seed_from_u64(5678);
    let title = "different root key".to_string();
    let filename = "test002_different_root_key".to_string();
    let token;

    let root2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root2, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(
                r#"
                check if resource($0), operation("read"), right($0, "read")
            "#
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
        resource("file1");
        allow if true;
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn invalid_signature_format(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid signature format".to_string();
    let filename = "test003_invalid_signature_format".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let serialized = biscuit2.container();
        let mut proto = serialized.to_proto();
        proto.authority.signature.truncate(16);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();
        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn random_block(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "random block".to_string();
    let filename = "test004_random_block".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let serialized = biscuit2.container();
        let mut proto = serialized.to_proto();
        let arr: [u8; 32] = rng.random();
        proto.blocks[0].block = Vec::from(&arr[..]);
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn invalid_signature(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid signature".to_string();
    let filename = "test005_invalid_signature".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let serialized = biscuit2.container();
        let mut proto = serialized.to_proto();
        proto.authority.signature[0] = proto.authority.signature[0] + 1;
        let mut data = Vec::new();
        proto.encode(&mut data).unwrap();

        write_testcase(target, &filename, &data[..]);

        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn reordered_blocks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "reordered blocks".to_string();
    let filename = "test006_reordered_blocks".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit3 = biscuit2
        .append_with_keypair(&keypair3, block!(r#"check if resource("file1")"#))
        .unwrap();
    token = print_blocks(&biscuit3);

    let mut serialized = biscuit3.container().clone();
    let mut blocks = vec![];
    blocks.push(serialized.blocks[1].clone());
    blocks.push(serialized.blocks[0].clone());
    serialized.blocks = blocks;

    let data = if test {
        let v = load_testcase(target, &filename);
        v
    } else {
        let data = serialized.to_vec().unwrap();
        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn scoped_rules(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "scoped rules".to_string();
    let filename = "test007_scoped_rules".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        user_id("alice");
        owner("alice", "file1");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(
                r#"
            right($0, "read") <- resource($0), user_id($1), owner($1, $0);
            check if resource($0), operation("read"), right($0, "read");
        "#
            ),
        )
        .unwrap();

    let block3 = BlockBuilder::new()
        .fact(r#"owner("alice", "file2")"#)
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit3 = biscuit2.append_with_keypair(&keypair3, block3).unwrap();
    token = print_blocks(&biscuit3);

    let data = write_or_load_testcase(target, &filename, root, &biscuit3, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                allow if true;
                "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn scoped_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "scoped checks".to_string();
    let filename = "test008_scoped_checks".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit3 = biscuit2
        .append_with_keypair(&keypair3, block!(r#"right("file2", "read")"#))
        .unwrap();
    token = print_blocks(&biscuit3);

    let data = write_or_load_testcase(target, &filename, root, &biscuit3, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                allow if true;
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn expired_token(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "expired token".to_string();
    let filename = "test009_expired_token".to_string();
    let token;

    let builder = Biscuit::builder();
    let biscuit1 = builder
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let block2 = block!(r#"check if resource("file1");"#)
        // January 1 2019
        .check_expiration_date(
            UNIX_EPOCH
                .checked_add(Duration::from_secs(49 * 365 * 24 * 3600))
                .unwrap(),
        );

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file1");
                operation("read");
                time(2020-12-21T09:23:12Z);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn authorizer_scope(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "authorizer scope".to_string();
    let filename = "test010_authorizer_scope".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"right("file2", "read")"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                check if right($0, $1), resource($0), operation($1);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn authorizer_authority_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "authorizer authority checks".to_string();
    let filename = "test011_authorizer_authority_caveats".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                check if right($0, $1), resource($0), operation($1);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn authority_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "authority checks".to_string();
    let filename = "test012_authority_caveats".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource("file1")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file1");
                operation("read");
                allow if true
            "#,
        ),
    );

    validations.insert(
        "file2".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                operation("read");
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn block_rules(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "block rules".to_string();
    let filename = "test013_block_rules".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block!(r#"
        // generate valid_date("file1") if before Thursday, December 31, 2030 12:59:59 PM UTC
        valid_date("file1") <- time($0), resource("file1"), $0 <= 2030-12-31T12:59:59Z;

        // generate a valid date fact for any file other than "file1" if before Friday, December 31, 1999 12:59:59 PM UTC
        valid_date($1) <- time($0), resource($1), $0 <= 1999-12-31T12:59:59Z, !{"file1"}.contains($1);

        check if valid_date($0), resource($0);
    "#)).unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file1");
                time(2020-12-21T09:23:12Z);
                allow if true
            "#,
        ),
    );

    validations.insert(
        "file2".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                resource("file2");
                time(2020-12-21T09:23:12Z);
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn regex_constraint(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "regex_constraint".to_string();
    let filename = "test014_regex_constraint".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource($0), $0.matches("file[0-9]+.txt")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "file1".to_string(),
        validate_token(root, &data[..], r#"resource("file1"); allow if true"#),
    );

    validations.insert(
        "file123".to_string(),
        validate_token(root, &data[..], r#"resource("file123.txt"); allow if true"#),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn multi_queries_checks(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "multi queries checks".to_string();
    let filename = "test015_multi_queries_caveats".to_string();
    let token;

    let biscuit1 = biscuit!(r#"must_be_present("hello")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"check if must_be_present($0) or must_be_present($0); allow if true"#,
        ),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn check_head_name(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "check head name should be independent from fact names".to_string();
    let filename = "test016_caveat_head_name".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if resource("hello")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"query("test")"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn expressions(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test expression syntax and all available operations".to_string();
    let filename = "test017_expressions".to_string();
    let token;

    let biscuit = biscuit!(r#"
        //boolean true
        check if true;
        //boolean false and negation
        check if !false;
        // boolean strict equality
        check if true === true;
        check if false === false;

        //integer less than
        check if 1 < 2;
        //integer greater than
        check if 2 > 1;
        //integer less or equal
        check if 1 <= 2;
        check if 1 <= 1;
        //integer greater or equal
        check if 2 >= 1;
        check if 2 >= 2;
        //integer strict equal
        check if 3 === 3;
        //integer add sub mul div
        check if 1 + 2 * 3 - 4 /2 === 5;

        // string prefix and suffix
        check if "hello world".starts_with("hello"), "hello world".ends_with("world");
        // string regex
        check if "aaabde".matches("a*c?.e");
        // string contains
        check if "aaabde".contains("abd");
        // string concatenation
        check if "aaabde" === "aaa" + "b" + "de";
        // string strict equal
        check if "abcD12" === "abcD12";
        // string length
        check if "abcD12".length() === 6;
        // string length (non-ascii)
        check if "é".length() === 2;

        //date less than
        check if 2019-12-04T09:46:41+00:00 < 2020-12-04T09:46:41+00:00;
        //date greater than
        check if 2020-12-04T09:46:41+00:00 > 2019-12-04T09:46:41+00:00;
        //date less or equal
        check if 2019-12-04T09:46:41+00:00 <= 2020-12-04T09:46:41+00:00;
        check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
        //date greater or equal
        check if 2020-12-04T09:46:41+00:00 >= 2019-12-04T09:46:41+00:00;
        check if 2020-12-04T09:46:41+00:00 >= 2020-12-04T09:46:41+00:00;
        //date strict equal
        check if 2020-12-04T09:46:41+00:00 === 2020-12-04T09:46:41+00:00;

        //bytes strict equal
        check if hex:12ab === hex:12ab;

        // set contains
        check if {1, 2}.contains(2);
        check if { 2020-12-04T09:46:41+00:00, 2019-12-04T09:46:41+00:00}.contains(2020-12-04T09:46:41+00:00);
        check if {true, false, true}.contains(true);
        check if {"abc", "def"}.contains("abc");
        check if {hex:12ab, hex:34de}.contains(hex:34de);
        check if {1, 2}.contains({2});
        // set strict equal
        check if {1, 2} === {1, 2};
        // set intersection
        check if {1, 2}.intersection({2, 3}) === {2};
        // set union
        check if {1, 2}.union({2, 3}) === {1, 2, 3};
        // chained method calls
        check if {1, 2, 3}.intersection({1, 2}).contains(1);
        // chained method calls with unary method
        check if {1, 2, 3}.intersection({1, 2}).length() === 2;

        // empty set literal
        check if {,}.length() === 0;
    "#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn unbound_variables_in_rule(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid block rule with unbound_variables".to_string();
    let filename = "test018_unbound_variables_in_rule".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if operation("read")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let block2 = BlockBuilder::new()
        // this one does not go through the parser because it checks for unused variables
        .rule(rule(
            "operation",
            &[var("unbound"), string("read")],
            &[pred("operation", &[var("any1"), var("any2")])],
        ))
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1.append_with_keypair(&keypair2, block2).unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"operation("write"); allow if true"#),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn generating_ambient_from_variables(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "invalid block rule generating an #authority or #ambient symbol with a variable"
        .to_string();
    let filename = "test019_generating_ambient_from_variables".to_string();
    let token;

    let biscuit1 = biscuit!(r#"check if operation("read")"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!(r#"operation("read") <- operation($any)"#))
        .unwrap();
    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], r#"operation("write"); allow if true"#),
    );
    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn sealed_token(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "sealed token".to_string();
    let filename = "test020_sealed".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair2,
            block!(r#"check if resource($0), operation("read"), right($0, "read")"#),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = if test {
        let v = load_testcase(target, &filename);
        let t = Biscuit::from(&v[..], root.public()).unwrap();

        let actual = biscuit2.print();
        let expected = t.print();
        print_diff(&actual, &expected);
        v
    } else {
        let data = biscuit2.seal().unwrap().to_vec().unwrap();
        write_testcase(target, &filename, &data[..]);
        data
    };

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"resource("file1"); operation("read"); allow if true"#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn parsing(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "parsing".to_string();
    let filename = "test021_parsing".to_string();
    let token;

    let biscuit1 = biscuit!("ns::fact_123(\"hello é\t😁\")")
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            "check if ns::fact_123(\"hello é\t😁\"); allow if true",
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn default_symbols(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "default_symbols".to_string();
    let filename = "test022_default_symbols".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"read(0);write(1);resource(2);operation(3);right(4);time(5);
    role(6);owner(7);tenant(8);namespace(9);user(10);team(11);
    service(12);admin(13);email(14);group(15);member(16);
    ip_address(17);client(18);client_ip(19);domain(20);path(21);
    version(22);cluster(23);node(24);hostname(25);nonce(26);query(27)"#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            check if read(0),write(1),resource(2),operation(3),right(4),
                time(5),role(6),owner(7),tenant(8),namespace(9),user(10),team(11),
                service(12),admin(13),email(14),group(15),member(16),ip_address(17),
                client(18),client_ip(19),domain(20),path(21),version(22),cluster(23),
                node(24),hostname(25),nonce(26),query(27);
            allow if true
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn execution_scope(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "execution scope".to_string();
    let filename = "test023_execution_scope".to_string();
    let token;

    let biscuit1 = biscuit!("authority_fact(1)")
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();

    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(&keypair2, block!("block1_fact(1)"))
        .unwrap();

    let keypair3 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit3 = biscuit2
        .append_with_keypair(
            &keypair3,
            block!(
                r#"
                check if authority_fact($var);
                check if block1_fact($var);
            "#
            ),
        )
        .unwrap();
    token = print_blocks(&biscuit3);

    let data = write_or_load_testcase(target, &filename, root, &biscuit3, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn third_party(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "third party".to_string();
    let filename = "test024_third_party".to_string();
    let token;

    // keep this to conserve the same RNG state
    let _ = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let external = KeyPair::from(
        &PrivateKey::from_bytes_hex(
            "12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a",
            Algorithm::Ed25519,
        )
        .unwrap(),
    );

    let biscuit1 = biscuit!(
        r#"
        right("read");
        check if group("admin") trusting {external_pub}
    "#,
        external_pub = external.public()
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let req = biscuit1.third_party_request().unwrap();

    let res = req
        .create_block(
            &external.private(),
            block!(
                r#"
                group("admin");
                check if right("read");
            "#
            ),
        )
        .unwrap();
    let keypair2 = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let biscuit2 = biscuit1
        .append_third_party_with_keypair(external.public(), res, keypair2)
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn check_all(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "block rules".to_string();
    let filename = "test025_check_all".to_string();
    let token;

    let biscuit1 = biscuit!(
        r#"
        allowed_operations({"A", "B"});
        check all operation($op), allowed_operations($allowed), $allowed.contains($op);
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    token = print_blocks(&biscuit1);

    let data = write_or_load_testcase(target, &filename, root, &biscuit1, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "A, B".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                operation("A");
                operation("B");
                allow if true
            "#,
        ),
    );

    validations.insert(
        "A, invalid".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                operation("A");
                operation("invalid");
                allow if true
            "#,
        ),
    );

    validations.insert(
        "no matches".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
                allow if true
            "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn public_keys_interning(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "public keys interning".to_string();
    let filename = "test026_public_keys_interning".to_string();
    let token;

    // keep this to conserve the same RNG state
    let _ = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let _ = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);
    let _ = KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng);

    let external1 = KeyPair::from(
        &PrivateKey::from_bytes_hex(
            "12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a",
            Algorithm::Ed25519,
        )
        .unwrap(),
    );
    let external2 = KeyPair::from(
        &PrivateKey::from_bytes_hex(
            "018e3f6864a1c9ffc2e67939a835d41c808b0084b3d7babf9364f674db19eeb3",
            Algorithm::Ed25519,
        )
        .unwrap(),
    );
    let external3 = KeyPair::from(
        &PrivateKey::from_bytes_hex(
            "88c637e4844fc3f52290889dc961cb15d809c994b5ef71990d6a2f989bd2f02c",
            Algorithm::Ed25519,
        )
        .unwrap(),
    );

    let biscuit1 = biscuit!(
        r#"
        query(0);
        check if true trusting previous, {k1};
    "#,
        k1 = external1.public()
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    let req1 = biscuit1.third_party_request().unwrap();

    let res1 = req1
        .create_block(
            &external1.private(),
            block!(
                r#"
        query(1);
        query(1,2) <- query(1), query(2) trusting {k2};
        check if query(2), query(3) trusting {k2};
        check if query(1) trusting {k1};
        "#,
                k1 = external1.public(),
                k2 = external2.public(),
            ),
        )
        .unwrap();

    let biscuit2 = biscuit1
        .append_third_party_with_keypair(
            external1.public(),
            res1,
            KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng),
        )
        .unwrap();

    let req2 = biscuit2.third_party_request().unwrap();
    let res2 = req2
        .create_block(
            &external2.private(),
            block!(
                r#"
        query(2);
        check if query(2), query(3) trusting {k2};
        check if query(1) trusting {k1};
        "#,
                k1 = external1.public(),
                k2 = external2.public(),
            ),
        )
        .unwrap();

    let biscuit3 = biscuit2
        .append_third_party_with_keypair(
            external2.public(),
            res2,
            KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng),
        )
        .unwrap();

    let req3 = biscuit3.third_party_request().unwrap();
    let res3 = req3
        .create_block(
            &external2.private(),
            block!(
                r#"
        query(3);
        check if query(2), query(3) trusting {k2};
        check if query(1) trusting {k1};
        "#,
                k1 = external1.public(),
                k2 = external2.public(),
            ),
        )
        .unwrap();

    let biscuit4 = biscuit3
        .append_third_party_with_keypair(
            external2.public(),
            res3,
            KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng),
        )
        .unwrap();

    let biscuit5 = biscuit4
        .append_with_keypair(
            &KeyPair::new_with_rng(Algorithm::Ed25519, &mut rng),
            block!(
                r#"
            query(4);
            check if query(2) trusting {k2};
            check if query(4) trusting {k3};
            "#,
                k2 = external2.public(),
                k3 = external3.public(),
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit5);

    let data = write_or_load_testcase(target, &filename, root, &biscuit5, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            &format!(
                r#"
              check if query(1,2) trusting ed25519/{k1}, ed25519/{k2};
              deny if query(3);
              deny if query(1,2);
              deny if query(0) trusting ed25519/{k1};
              allow if true;
            "#,
                k1 = &external1.public().to_bytes_hex(),
                k2 = &external2.public().to_bytes_hex(),
            ),
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn integer_wraparound(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "integer wraparound".to_string();
    let filename = "test027_integer_wraparound".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
          check if 10000000000 * 10000000000 !== 0;
          check if 9223372036854775807 + 1 !== 0;
          check if -9223372036854775808 - 1 !== 0;
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], &format!(r#"allow if true;"#)),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn expressions_v4(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test expression syntax and all available operations (v4 blocks)".to_string();
    let filename = "test028_expressions_v4".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
        //bool not strict equal
        check if true !== false;
        //integer not strict equal
        check if 1 !== 3;
        //integer bitwise and or xor
        check if 1 | 2 ^ 3 === 0;
        //string not strict equal
        check if "abcD12x" !== "abcD12";
        //date not strict equal
        check if 2022-12-04T09:46:41+00:00 !== 2020-12-04T09:46:41+00:00;
        //bytes not strict equal
        check if hex:12abcd !== hex:12ab;
        // set not strict equal
        check if {1, 4} !== {1, 2};
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn reject_if(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test reject if".to_string();
    let filename = "test029_reject_if".to_string();
    let token;

    let biscuit = biscuit!(r#"reject if test($test), $test"#)
        .build_with_rng(&root, SymbolTable::default(), &mut rng)
        .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "test(false); allow if true"),
    );
    validations.insert(
        "rejection".to_string(),
        validate_token(root, &data[..], "test(true); allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn null(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test null".to_string();
    let filename = "test030_null".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
    check if fact(null, $value), $value == null;
    reject if fact(null, $value), $value != null;
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "fact(null, null); allow if true"),
    );
    validations.insert(
        "rejection1".to_string(),
        validate_token(root, &data[..], "fact(null, 1); allow if true"),
    );
    validations.insert(
        "rejection2".to_string(),
        validate_token(root, &data[..], "fact(null, true); allow if true"),
    );
    validations.insert(
        "rejection3".to_string(),
        validate_token(root, &data[..], "fact(null, \"abcd\"); allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn heterogeneous_equal(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test heterogeneous equal".to_string();
    let filename = "test031_heterogeneous_equal".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
    check if true == true;
    check if false == false;
    check if false != true;
    check if 1 != true;
    check if 1 == 1;
    check if 1 != 3;
    check if 1 != true;
    check if "abcD12" == "abcD12";
    check if "abcD12x" != "abcD12";
    check if "abcD12x" != true;
    check if 2022-12-04T09:46:41+00:00 == 2022-12-04T09:46:41+00:00;
    check if 2022-12-04T09:46:41+00:00 != 2020-12-04T09:46:41+00:00;
    check if 2022-12-04T09:46:41+00:00 != true;
    check if hex:12abcd == hex:12abcd;
    check if hex:12abcd != hex:12ab;
    check if hex:12abcd != true;
    check if {1, 2} == {1, 2};
    check if {1, 4} != {1, 2};
    check if {1, 4} != true;
    check if fact(1, $value), 1 == $value;
    check if fact2(1, $value), 1 != $value;
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "fact(1,1); fact2(1,2); allow if true"),
    );
    validations.insert(
        "evaluate to false".to_string(),
        validate_token(
            root,
            &data[..],
            "fact(1,2); fact2(1,1); check if false != false; allow if true",
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn closures(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test laziness and closures".to_string();
    let filename = "test032_laziness_closures".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
        // boolean and
        check if !false && true;
        // boolean or
        check if false || true;
        // boolean parens
        check if (true || false) && true;
        // boolean and laziness
        check if !(false && "x".intersection("x"));
        // boolean or laziness
        check if true || "x".intersection("x");
        // all
        check if {1,2,3}.all($p -> $p > 0);
        // all
        check if !{1,2,3}.all($p -> $p == 2);
        // any
        check if {1,2,3}.any($p -> $p > 2);
        // any
        check if !{1,2,3}.any($p -> $p > 3);
        // nested closures
        check if {1,2,3}.any($p -> $p > 1 && {3,4,5}.any($q -> $p == $q));
        "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );
    validations.insert(
        "shadowing".to_string(),
        validate_token(
            root,
            &data[..],
            r#"allow if { "true" }.any($p -> { "true" }.all($p -> $p))"#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn type_of(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test .type()".to_string();
    let filename = "test033_typeof".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
        check if 1.type() == "integer";
        integer(1);
        check if integer($t), $t.type() == "integer";
        check if "test".type() == "string";
        string("test");
        check if string($t), $t.type() == "string";
        check if (2023-12-28T00:00:00Z).type() == "date";
        date(2023-12-28T00:00:00Z);
        check if date($t), $t.type() == "date";
        check if hex:aa.type() == "bytes";
        bytes(hex:aa);
        check if bytes($t), $t.type() == "bytes";
        check if true.type() == "bool";
        bool(true);
        check if bool($t), $t.type() == "bool";
        check if {true, false}.type() == "set";
        set({true, false});
        check if set($t), $t.type() == "set";
        check if null.type() == "null";
        null(null);
        check if null($t), $t.type() == "null";
        array([1,2,3]);
        check if array($t), $t.type() == "array";
        map({"a": true});
        check if map($t), $t.type() == "map";
        "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();

    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn array_map(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test array and map operations".to_string();
    let filename = "test034_array_map".to_string();
    let token;

    let biscuit = biscuit!(
        r#"
        // array
        check if [1, 2, 1].length() == 3;
        check if ["a", "b"] != true;
        check if ["a", "b"] != [1, 2, 3];
        check if ["a", "b"] == ["a", "b"];
        check if ["a", "b"] === ["a", "b"];
        check if ["a", "b"] !== ["a", "c"];
        check if ["a", "b", "c"].contains("c");
        check if [1, 2, 3].starts_with([1, 2]);
        check if [4, 5, 6 ].ends_with([6]);
        check if [1,2, "a"].get(2) == "a";
        check if [1, 2].get(3) == null;
        check if [1,2,3].all($p -> $p > 0);
        check if [1,2,3].any($p -> $p > 2);
        // map
        check if { "a": 1 , "b": 2, "c": 3, "d": 4}.length() == 4;
        check if {  1: "a" , 2: "b"} != true;
        check if {  1: "a" , 2: "b"} != { "a": 1 , "b": 2};
        check if {  1: "a" , 2: "b"} == { 2: "b", 1: "a"  };
        check if {  1: "a" , 2: "b"} !== { "a": 1 , "b": 2};
        check if {  1: "a" , 2: "b"} === { 2: "b", 1: "a"  };
        check if { "a": 1 , "b": 2, "c": 3, "d": 4}.contains("d");
        check if { "a": 1 , "b": 2, 1: "A" }.get("a") == 1;
        check if { "a": 1 , "b": 2, 1: "A" }.get(1) == "A";
        check if { "a": 1 , "b": 2, 1: "A" }.get("c") == null;
        check if { "a": 1 , "b": 2, 1: "A" }.get(2) == null;
        check if { "a": 1 , "b": 2 }.all($kv -> $kv.get(0) != "c" && $kv.get(1) < 3 );
        check if { "a": 1 , "b": 2, 1: "A" }.any($kv -> $kv.get(0) == 1 && $kv.get(1) == "A" );
        // nesting
        check if { "user": { "id": 1, "roles": ["admin"] } }.get("user").get("roles").contains("admin");
    "#
    )
    .build_with_rng(&root, SymbolTable::default(), &mut rng)
    .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn ffi(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test ffi calls (v6 blocks)".to_string();
    let filename = "test035_ffi".to_string();
    let token;

    let biscuit =
        biscuit!(r#"check if true.extern::test(), "a".extern::test("a") == "equal strings""#)
            .build_with_rng(&root, SymbolTable::default(), &mut rng)
            .unwrap();
    token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token_with_limits_and_external_functions(
            root,
            &data[..],
            "allow if true",
            RunLimits::default(),
            HashMap::from([(
                "test".to_string(),
                ExternFunc::new(Arc::new(|left, right| match (left, right) {
                    (t, None) => Ok(t),
                    (builder::Term::Str(left), Some(builder::Term::Str(right)))
                        if left == right =>
                    {
                        Ok(builder::Term::Str("equal strings".to_string()))
                    }
                    (builder::Term::Str(_), Some(builder::Term::Str(_))) => {
                        Ok(builder::Term::Str("different strings".to_string()))
                    }
                    _ => Err("unsupported operands".to_string()),
                })),
            )]),
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn secp256r1(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "ECDSA secp256r1 signatures".to_string();
    let filename = "test036_secp256r1".to_string();
    let token;

    let keypair2 = KeyPair::new_with_rng(Algorithm::Secp256r1, &mut rng);
    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
    "#
    )
    .build_with_key_pair(&root, SymbolTable::default(), &keypair2)
    .unwrap();

    let keypair3 = KeyPair::new_with_rng(Algorithm::Secp256r1, &mut rng);
    let biscuit2 = biscuit1
        .append_with_keypair(
            &keypair3,
            block!(
                r#"
            check if resource($0), operation("read"), right($0, "read")
            "#
            ),
        )
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            resource("file1");
            operation("read");
            allow if true;
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn secp256r1_third_party(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "ECDSA secp256r1 signature on third-party block".to_string();
    let filename = "test037_secp256r1_third_party".to_string();
    let token;

    let external_keypair = KeyPair::new_with_rng(Algorithm::Secp256r1, &mut rng);
    let keypair2 = KeyPair::new_with_rng(Algorithm::Secp256r1, &mut rng);
    let biscuit1 = biscuit!(
        r#"
        right("file1", "read");
        right("file2", "read");
        right("file1", "write");
        check if from_third(true) trusting {external_pub};
    "#,
        external_pub = external_keypair.public(),
    )
    .build_with_key_pair(&root, SymbolTable::default(), &keypair2)
    .unwrap();

    let req = biscuit1.third_party_request().unwrap();
    let block = req
        .create_block(
            &external_keypair.private(),
            block!(
                r#" check if resource($0), operation("read"), right($0, "read"); from_third(true);"#
            ),
        )
        .unwrap();
    let keypair3 = KeyPair::new_with_rng(Algorithm::Secp256r1, &mut rng);

    let biscuit2 = biscuit1
        .append_third_party_with_keypair(external_keypair.public(), block, keypair3)
        .unwrap();

    token = print_blocks(&biscuit2);

    let data = write_or_load_testcase(target, &filename, root, &biscuit2, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            resource("file1");
            operation("read");
            allow if true;
        "#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn try_op(target: &str, root: &KeyPair, test: bool) -> TestResult {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let title = "test try operation".to_string();
    let filename = "test038_try_op".to_string();

    let biscuit = biscuit!(
        r#"
        // regular use
        check if (true === 12).try_or(true);
        // nested try calls work
        check if ((true === 12).try_or(true === 12)).try_or(true);
        reject if (true == 12).try_or(true);
        "#
    )
    .build_with_rng(root, SymbolTable::default(), &mut rng)
    .unwrap();
    let token = print_blocks(&biscuit);

    let data = write_or_load_testcase(target, &filename, root, &biscuit, test);

    let mut validations = BTreeMap::new();
    validations.insert(
        "".to_string(),
        validate_token(root, &data[..], "allow if true"),
    );

    validations.insert(
        "right-hand side does not catch errors".to_string(),
        validate_token(
            root,
            &data[..],
            r#"
            // the fallback argument is evaluated eagerly, so this expression
            // will trigger an evaluation error
            check if true.try_or(true === 12);
            allow if true;"#,
        ),
    );

    TestResult {
        title,
        filename,
        token,
        validations,
    }
}

fn print_blocks(token: &Biscuit) -> Vec<BlockContent> {
    let mut v = Vec::new();

    for i in 0..token.block_count() {
        v.push(BlockContent {
            symbols: token.block_symbols(i).unwrap(),
            code: token.print_block_source(i).unwrap(),
            public_keys: token
                .block_public_keys(i)
                .unwrap()
                .into_inner()
                .iter()
                .map(|k| k.print())
                .collect(),
            external_key: token.block_external_key(i).unwrap().map(|k| k.print()),
            version: token.block_version(i).unwrap(),
        });
    }

    v
}

#[test]
fn test_samples() {
    run("./samples".to_string(), None, true, false);
}
