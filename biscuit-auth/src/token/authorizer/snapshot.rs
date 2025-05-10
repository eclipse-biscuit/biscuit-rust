/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use prost::Message;
use std::{collections::HashMap, time::Duration};

use crate::{
    builder::{load_and_translate_block, BlockBuilder, Convert, Policy},
    datalog::{Origin, RunLimits, TrustedOrigins},
    error,
    format::{
        convert::{
            policy_to_proto_policy, proto_fact_to_token_fact, proto_policy_to_policy,
            proto_snapshot_block_to_token_block, token_block_to_proto_snapshot_block,
            token_fact_to_proto_fact,
        },
        schema::{self, GeneratedFacts},
    },
    token::{default_symbol_table, MAX_SCHEMA_VERSION, MIN_SCHEMA_VERSION},
    PublicKey,
};

impl super::Authorizer {
    pub fn from_snapshot(input: schema::AuthorizerSnapshot) -> Result<Self, error::Token> {
        let schema::AuthorizerSnapshot {
            limits,
            execution_time,
            world,
        } = input;

        let limits = RunLimits {
            max_facts: limits.max_facts,
            max_iterations: limits.max_iterations,
            max_time: Duration::from_nanos(limits.max_time),
        };

        let execution_time = Duration::from_nanos(execution_time);

        let version = world.version.unwrap_or(0);
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
            return Err(error::Format::Version {
                minimum: crate::token::MIN_SCHEMA_VERSION,
                maximum: crate::token::MAX_SCHEMA_VERSION,
                actual: version,
            }
            .into());
        }

        let mut symbols = default_symbol_table();
        for symbol in world.symbols {
            symbols.insert(&symbol);
        }
        for public_key in world.public_keys {
            symbols
                .public_keys
                .insert(&PublicKey::from_proto(&public_key)?);
        }

        let authorizer_block = proto_snapshot_block_to_token_block(&world.authorizer_block)?;

        let authorizer_block_builder = BlockBuilder::convert_from(&authorizer_block, &symbols)?;
        let policies = world
            .authorizer_policies
            .iter()
            .map(|policy| proto_policy_to_policy(policy, &symbols, version))
            .collect::<Result<Vec<Policy>, error::Format>>()?;

        let mut authorizer = super::Authorizer::new();
        authorizer.symbols = symbols;
        authorizer.authorizer_block_builder = authorizer_block_builder;
        authorizer.policies = policies;
        authorizer.limits = limits;
        authorizer.execution_time =
            Some(execution_time).filter(|_| execution_time > Duration::default());

        let mut public_key_to_block_id: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut blocks = Vec::new();
        for (i, block) in world.blocks.iter().enumerate() {
            let token_symbols = if block.external_key.is_none() {
                authorizer.symbols.clone()
            } else {
                let mut token_symbols = authorizer.symbols.clone();
                token_symbols.public_keys = authorizer.symbols.public_keys.clone();
                token_symbols
            };

            let mut block = proto_snapshot_block_to_token_block(block)?;

            if let Some(key) = block.external_key.as_ref() {
                public_key_to_block_id
                    .entry(authorizer.symbols.public_keys.insert(key) as usize)
                    .or_default()
                    .push(i);
            }

            load_and_translate_block(
                &mut block,
                i,
                &token_symbols,
                &mut authorizer.symbols,
                &mut public_key_to_block_id,
                &mut authorizer.world,
            )?;
            blocks.push(block);
        }

        authorizer.public_key_to_block_id = public_key_to_block_id;

        if !blocks.is_empty() {
            authorizer.token_origins = TrustedOrigins::from_scopes(
                &[crate::token::Scope::Previous],
                &TrustedOrigins::default(),
                blocks.len(),
                &authorizer.public_key_to_block_id,
            );
            authorizer.blocks = Some(blocks);
        }

        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);

        let authorizer_scopes: Vec<crate::token::Scope> = authorizer
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut authorizer.symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &authorizer.public_key_to_block_id,
        );
        for fact in &authorizer.authorizer_block_builder.facts {
            authorizer
                .world
                .facts
                .insert(&authorizer_origin, fact.convert(&mut authorizer.symbols));
        }

        for rule in &authorizer.authorizer_block_builder.rules {
            let rule = rule.convert(&mut authorizer.symbols);

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &authorizer_trusted_origins,
                usize::MAX,
                &authorizer.public_key_to_block_id,
            );

            authorizer
                .world
                .rules
                .insert(usize::MAX, &rule_trusted_origins, rule);
        }

        for GeneratedFacts { origins, facts } in world.generated_facts {
            let origin = proto_origin_to_authorizer_origin(&origins)?;

            for fact in &facts {
                let fact = proto_fact_to_token_fact(fact)?;
                //let fact = Fact::convert_from(&fact, &symbols)?.convert(&mut authorizer.symbols);
                authorizer.world.facts.insert(&origin, fact);
            }
        }

        authorizer.world.iterations = world.iterations;

        Ok(authorizer)
    }

    pub fn from_raw_snapshot(input: &[u8]) -> Result<Self, error::Token> {
        let snapshot = schema::AuthorizerSnapshot::decode(input).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;
        Self::from_snapshot(snapshot)
    }

    pub fn from_base64_snapshot(input: &str) -> Result<Self, error::Token> {
        let bytes = base64::decode_config(input, base64::URL_SAFE)?;
        Self::from_raw_snapshot(&bytes)
    }

    pub fn snapshot(&self) -> Result<schema::AuthorizerSnapshot, error::Format> {
        let mut symbols = default_symbol_table();

        let authorizer_policies = self
            .policies
            .iter()
            .map(|policy| policy_to_proto_policy(policy, &mut symbols))
            .collect();

        let authorizer_block = self.authorizer_block_builder.clone().build(symbols.clone());
        symbols.extend(&authorizer_block.symbols)?;
        symbols.public_keys.extend(&authorizer_block.public_keys)?;

        let authorizer_block = token_block_to_proto_snapshot_block(&authorizer_block);

        let blocks = match self.blocks.as_ref() {
            None => Vec::new(),
            Some(blocks) => blocks
                .iter()
                .map(|block| {
                    block
                        .translate(&self.symbols, &mut symbols)
                        .map(|block| token_block_to_proto_snapshot_block(&block))
                })
                .collect::<Result<Vec<_>, error::Format>>()?,
        };

        let generated_facts = self
            .world
            .facts
            .inner
            .iter()
            .map(|(origin, facts)| {
                Ok(GeneratedFacts {
                    origins: authorizer_origin_to_proto_origin(origin),
                    facts: facts
                        .iter()
                        .map(|fact| {
                            Ok(token_fact_to_proto_fact(
                                &crate::builder::Fact::convert_from(fact, &self.symbols)?
                                    .convert(&mut symbols),
                            ))
                        })
                        .collect::<Result<Vec<_>, error::Format>>()?,
                })
            })
            .collect::<Result<Vec<GeneratedFacts>, error::Format>>()?;

        let world = schema::AuthorizerWorld {
            version: Some(MAX_SCHEMA_VERSION),
            symbols: symbols.strings(),
            public_keys: symbols
                .public_keys
                .into_inner()
                .into_iter()
                .map(|key| key.to_proto())
                .collect(),
            blocks,
            authorizer_block,
            authorizer_policies,
            generated_facts,
            iterations: self.world.iterations,
        };

        Ok(schema::AuthorizerSnapshot {
            world,
            execution_time: self.execution_time.unwrap_or_default().as_nanos() as u64,
            limits: schema::RunLimits {
                max_facts: self.limits.max_facts,
                max_iterations: self.limits.max_iterations,
                max_time: self.limits.max_time.as_nanos() as u64,
            },
        })
    }

    pub fn to_raw_snapshot(&self) -> Result<Vec<u8>, error::Format> {
        let snapshot = self.snapshot()?;
        let mut bytes = Vec::new();
        snapshot.encode(&mut bytes).map_err(|e| {
            error::Format::SerializationError(format!("serialization error: {:?}", e))
        })?;
        Ok(bytes)
    }

    pub fn to_base64_snapshot(&self) -> Result<String, error::Format> {
        let snapshot_bytes = self.to_raw_snapshot()?;
        Ok(base64::encode_config(snapshot_bytes, base64::URL_SAFE))
    }
}

pub(crate) fn authorizer_origin_to_proto_origin(origin: &Origin) -> Vec<schema::Origin> {
    origin
        .inner
        .iter()
        .map(|o| {
            if *o == usize::MAX {
                schema::Origin {
                    content: Some(schema::origin::Content::Authorizer(schema::Empty {})),
                }
            } else {
                schema::Origin {
                    content: Some(schema::origin::Content::Origin(*o as u32)),
                }
            }
        })
        .collect()
}

pub(crate) fn proto_origin_to_authorizer_origin(
    origins: &[schema::Origin],
) -> Result<Origin, error::Format> {
    let mut new_origin = Origin::default();

    for origin in origins {
        match origin.content {
            Some(schema::origin::Content::Authorizer(schema::Empty {})) => {
                new_origin.insert(usize::MAX)
            }
            Some(schema::origin::Content::Origin(o)) => new_origin.insert(o as usize),
            _ => {
                return Err(error::Format::DeserializationError(
                    "invalid origin".to_string(),
                ))
            }
        }
    }

    Ok(new_origin)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use crate::{datalog::RunLimits, Algorithm, AuthorizerBuilder};
    use crate::{Authorizer, BiscuitBuilder, KeyPair};

    #[test]
    fn roundtrip_builder() {
        let secp_pubkey = KeyPair::new_with_algorithm(Algorithm::Secp256r1).public();
        let ed_pubkey = KeyPair::new_with_algorithm(Algorithm::Ed25519).public();
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
            })
            .code_with_params(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true) trusting authority, {ed_pubkey}, {secp_pubkey};
                allow if head(true);
                deny if head(false);
        "#,
                HashMap::default(),
                HashMap::from([
                    ("ed_pubkey".to_string(), ed_pubkey),
                    ("secp_pubkey".to_string(), secp_pubkey),
                ]),
            )
            .unwrap();
        let snapshot = builder.snapshot().unwrap();

        let parsed = AuthorizerBuilder::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), builder.dump_code());
        assert_eq!(parsed.limits, builder.limits);
    }

    #[test]
    fn roundtrip_with_token() {
        let secp_pubkey = KeyPair::new_with_algorithm(Algorithm::Secp256r1).public();
        let ed_pubkey = KeyPair::new_with_algorithm(Algorithm::Ed25519).public();
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
            })
            .code_with_params(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true) trusting authority, {ed_pubkey}, {secp_pubkey};
                allow if head(true);
                deny if head(false);
        "#,
                HashMap::default(),
                HashMap::from([
                    ("ed_pubkey".to_string(), ed_pubkey),
                    ("secp_pubkey".to_string(), secp_pubkey),
                ]),
            )
            .unwrap();
        let biscuit = BiscuitBuilder::new()
            .code_with_params(
                r#"
                bfact(true);
                bhead($a) <- fact($a);
                check if bhead(true) trusting authority, {ed_pubkey}, {secp_pubkey};
                "#,
                HashMap::default(),
                HashMap::from([
                    ("ed_pubkey".to_string(), ed_pubkey),
                    ("secp_pubkey".to_string(), secp_pubkey),
                ]),
            )
            .unwrap()
            .build(&KeyPair::new())
            .unwrap();

        let authorizer_pre_run = builder.build(&biscuit).unwrap();

        let snapshot = authorizer_pre_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_pre_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_pre_run.limits());

        let mut authorizer_post_run = authorizer_pre_run.clone();
        let _ = authorizer_post_run.run();

        let snapshot = authorizer_post_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_post_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_post_run.limits());
    }

    #[test]
    fn roundtrip_without_token() {
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
            })
            .code(
                r#"
                fact(true);
                head($a) <- fact($a);
                check if head(true);
                allow if head(true);
                deny if head(false);
        "#,
            )
            .unwrap();
        let authorizer = builder.build_unauthenticated().unwrap();
        let snapshot = authorizer.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer.dump_code());
        assert_eq!(parsed.limits(), authorizer.limits());

        let mut authorizer_post_run = authorizer.clone();
        let _ = authorizer_post_run.run();
        let snapshot = authorizer_post_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_post_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_post_run.limits());
    }

    #[test]
    fn roundtrip_with_eval_error() {
        let builder = AuthorizerBuilder::new()
            .set_limits(RunLimits {
                max_facts: 42,
                max_iterations: 42,
                max_time: Duration::from_secs(1),
            })
            .code(
                r#"
                fact(true);
                head($a) <- fact($a), $a.length();
                allow if head(true);
                deny if head(false);
        "#,
            )
            .unwrap();
        let authorizer = builder.build_unauthenticated().unwrap();
        let snapshot = authorizer.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer.dump_code());
        assert_eq!(parsed.limits(), authorizer.limits());

        let mut authorizer_post_run = authorizer.clone();
        let _ = authorizer_post_run.run();
        let snapshot = authorizer_post_run.snapshot().unwrap();

        let parsed = Authorizer::from_snapshot(snapshot).unwrap();
        assert_eq!(parsed.dump_code(), authorizer_post_run.dump_code());
        assert_eq!(parsed.limits(), authorizer_post_run.limits());
    }
}
