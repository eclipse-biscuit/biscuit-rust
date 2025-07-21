/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use biscuit_auth::{builder, datalog::RunLimits, KeyPair, PublicKey};
use biscuit_quote::{
    authorizer, authorizer_merge, biscuit, biscuit_merge, block, block_merge, check, fact, policy,
    rule,
};
use serde_json::json;
use std::{collections::BTreeSet, convert::TryInto, time::Duration};

#[test]
fn block_macro() {
    let mut term_set = BTreeSet::new();
    term_set.insert(builder::int(0i64));
    let my_key = "my_value";
    let array_param = 2;
    let mapkey = "hello";

    let mut b = block!(
        r#"fact("test", hex:aabbcc, [1, {array_param}], {my_key}, {term_set}, {"a": 1, 2 : "abcd", {mapkey}: 0 });
            rule($0, true) <- fact($0, $1, $2, {my_key}), true || false;
            check if {my_key}.starts_with("my");
            check if {true,false}.any($p -> true);
            "#,
    );

    let is_true = true;
    b = block_merge!(b, r#"appended({is_true});"#);

    assert_eq!(
        b.to_string(),
        r#"fact("test", hex:aabbcc, [1, 2], "my_value", {0}, {2: "abcd", "a": 1, "hello": 0});
appended(true);
rule($0, true) <- fact($0, $1, $2, "my_value"), true || false;
check if "my_value".starts_with("my");
check if {false, true}.any($p -> true);
"#,
    );

    let b = block!(r#"check if "test".extern::toto() && "test".extern::test("test");"#);

    assert_eq!(
        b.to_string(),
        r#"check if "test".extern::toto() && "test".extern::test("test");
"#
    );
}

#[test]
fn block_macro_trailing_comma() {
    let b = block!(r#"fact({my_key});"#, my_key = "test",);
    assert_eq!(
        b.to_string(),
        r#"fact("test");
"#,
    );
}

#[test]
fn authorizer_macro() {
    let external_key = "test";
    let my_key = "my_value";
    let mut b = authorizer!(
        r#"fact({external_key}, hex:aabbcc, [true], {my_key});
        rule($0, true) <- fact($0, $1, $2, {my_key});
        check if {my_key}.starts_with("my");
        allow if {other_key};
        "#,
        other_key = false,
    );

    let is_true = true;
    b = authorizer_merge!(
        b,
        r#"appended({is_true});
        allow if true;
      "#
    );

    let mut authorizer = b
        .set_limits(RunLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .build_unauthenticated()
        .unwrap();
    authorizer.run().unwrap();
    assert_eq!(
        authorizer.dump_code(),
        r#"appended(true);
fact("test", hex:aabbcc, [true], "my_value");
rule("test", true);

rule($0, true) <- fact($0, $1, $2, "my_value");

check if "my_value".starts_with("my");

allow if false;
allow if true;
"#,
    );
}

#[test]
fn authorizer_macro_trailing_comma() {
    let a = authorizer!(r#"fact("test", {my_key});"#, my_key = "my_value",)
        .set_limits(RunLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        })
        .build_unauthenticated()
        .unwrap();
    assert_eq!(
        a.dump_code(),
        r#"fact("test", "my_value");

"#,
    );
}

#[test]
fn biscuit_macro() {
    use biscuit_auth::PublicKey;
    let pubkey = PublicKey::from_bytes(
        &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db").unwrap(),
        biscuit_auth::builder::Algorithm::Ed25519,
    )
    .unwrap();

    let s = String::from("my_value");
    let my_key = "my_value";
    let mut b = biscuit!(
        r#"fact("test", hex:aabbcc, [true], {my_key}, {my_key_bytes});
        rule($0, true) <- fact($0, $1, $2, {my_key}, {my_key_bytes});
        check if {my_key}.starts_with("my") trusting {pubkey};
        check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
        "#,
        my_key_bytes = s.into_bytes(),
    ).root_key_id(2);

    let is_true = true;
    b = biscuit_merge!(
        b,
        r#"appended({is_true});
        check if true;
      "#
    );

    assert_eq!(
        b.to_string(),
        r#"// root key id: 2
fact("test", hex:aabbcc, [true], "my_value", hex:6d795f76616c7565);
appended(true);
rule($0, true) <- fact($0, $1, $2, "my_value", hex:6d795f76616c7565);
check if "my_value".starts_with("my") trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true;
"#,
    );

    assert_eq!(
        b.dump_code(),
        r#"fact("test", hex:aabbcc, [true], "my_value", hex:6d795f76616c7565);
appended(true);
rule($0, true) <- fact($0, $1, $2, "my_value", hex:6d795f76616c7565);
check if "my_value".starts_with("my") trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db;
check if true;
"#,
    );
}

#[test]
fn biscuit_macro_trailing_comma() {
    let b = biscuit!(r#"fact("test", {my_key});"#, my_key = "my_value",);
    assert_eq!(
        b.dump_code(),
        r#"fact("test", "my_value");
"#,
    );
}

#[test]
fn rule_macro() {
    use biscuit_auth::PublicKey;
    let pubkey = PublicKey::from_bytes(
        &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db").unwrap(),
        biscuit_auth::builder::Algorithm::Ed25519,
    )
    .unwrap();
    let mut term_set = BTreeSet::new();
    term_set.insert(builder::int(0i64));
    let r = rule!(
        r#"rule($0, true) <- fact($0, $1, $2, {my_key}, {term_set}) trusting {pubkey}"#,
        my_key = "my_value",
    );

    assert_eq!(
        r.to_string(),
        r#"rule($0, true) <- fact($0, $1, $2, "my_value", {0}) trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db"#,
    );
}

#[test]
fn fact_macro() {
    let mut term_set = BTreeSet::new();
    term_set.insert(builder::int(0i64));
    let f = fact!(r#"fact({my_key}, {term_set})"#, my_key = "my_value",);

    assert_eq!(f.to_string(), r#"fact("my_value", {0})"#,);
}

#[test]
fn check_macro() {
    use biscuit_auth::PublicKey;
    let pubkey = PublicKey::from_bytes(
        &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db").unwrap(),
        biscuit_auth::builder::Algorithm::Ed25519,
    )
    .unwrap();
    let mut term_set = BTreeSet::new();
    term_set.insert(builder::int(0i64));
    let c = check!(
        r#"check if fact({my_key}, {term_set}) trusting {pubkey}"#,
        my_key = "my_value",
    );

    assert_eq!(
        c.to_string(),
        r#"check if fact("my_value", {0}) trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db"#,
    );
}

#[test]
fn policy_macro() {
    use biscuit_auth::PublicKey;
    let pubkey = PublicKey::from_bytes(
        &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db").unwrap(),
        biscuit_auth::builder::Algorithm::Ed25519,
    )
    .unwrap();
    let mut term_set = BTreeSet::new();
    term_set.insert(builder::int(0i64));
    let p = policy!(
        r#"allow if fact({my_key}, {term_set}) trusting {pubkey}"#,
        my_key = "my_value",
    );

    assert_eq!(
        p.to_string(),
        r#"allow if fact("my_value", {0}) trusting ed25519/6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db"#,
    );
}

#[test]
fn json() {
    let key_pair = KeyPair::new();
    let biscuit = biscuit!(r#"user(123)"#).build(&key_pair).unwrap();

    let value: serde_json::Value = json!(
        {
            "id": 123,
            "roles": ["admin"]
        }
    );
    let json_value: biscuit_auth::builder::Term = value.try_into().unwrap();

    let mut authorizer = authorizer!(
        r#"
        user_roles({json_value});
        allow if
          user($id),
          user_roles($value),
          $value.get("id") == $id,
          $value.get("roles").contains("admin");"#
    )
    .set_limits(RunLimits {
        max_time: Duration::from_secs(10),
        ..Default::default()
    })
    .build(&biscuit)
    .unwrap();
    assert_eq!(
        authorizer
            .authorize_with_limits(RunLimits {
                max_time: Duration::from_secs(1),
                ..Default::default()
            })
            .unwrap(),
        0
    );
}

#[test]
fn ecdsa() {
    use biscuit_auth::PublicKey;

    let pubkey = PublicKey::from_bytes(
        &hex::decode("0245dd01132962da3812911b746b080aed714873c1812e7cefacf13e3880712da0").unwrap(),
        biscuit_auth::builder::Algorithm::Secp256r1,
    )
    .unwrap();
    let mut term_set = BTreeSet::new();
    term_set.insert(builder::int(0i64));
    let r = rule!(
        r#"rule($0, true) <- fact($0, $1, $2, {my_key}, {term_set}) trusting {pubkey}"#,
        my_key = "my_value",
    );

    assert_eq!(
        r.to_string(),
        r#"rule($0, true) <- fact($0, $1, $2, "my_value", {0}) trusting secp256r1/0245dd01132962da3812911b746b080aed714873c1812e7cefacf13e3880712da0"#,
    );
}

#[test]
fn trusting() {
    // this should only work with a proper `PublicKey` value, and fail when trying to provide a string instead
    let pubkey: PublicKey =
        "secp256r1/0245dd01132962da3812911b746b080aed714873c1812e7cefacf13e3880712da0"
            .parse()
            .unwrap();
    let _ = authorizer!(
        r#"
    nonce("a"); operation("o"); pathname("p");
    d($x) <- nonce($x) trusting {pubkey}
        "#
    );
    let _ = rule!(
        r#"
    data($nonce, $operation, $pathname)
      <- nonce($nonce), operation($operation), pathname($pathname)

      trusting {pubkey}
    "#,
    );
}
