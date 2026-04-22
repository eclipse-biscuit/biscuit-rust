/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use biscuit_auth::{builder::AuthorizerBuilder, builder_ext::AuthorizerExt, PublicKey};

fn main() {
    let mut args = std::env::args();
    args.next();
    let target = match args.next() {
        Some(arg) => arg,
        None => {
            println!("missing token path argument");
            return;
        }
    };

    let data = std::fs::read(target).unwrap();
    let root = PublicKey::from_bytes(
        &hex::decode("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189").unwrap(),
        biscuit_auth::builder::Algorithm::Ed25519,
    )
    .unwrap();
    let token = biscuit_auth::Biscuit::from(&data[..], root).unwrap();

    println!("Token content:");
    for i in 0..token.block_count() {
        println!("block {}:\n{}\n", i, token.print_block_source(i).unwrap());
    }
    println!("token:\n{token}");

    let mut authorizer = AuthorizerBuilder::new().allow_all().build(&token).unwrap();

    println!("authorizer result: {:?}", authorizer.authorize());
    println!("authorizer world:\n{}", authorizer.print_world());
}
