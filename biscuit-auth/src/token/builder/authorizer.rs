use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::Write,
    time::{Duration, SystemTime},
};

use biscuit_parser::parser::parse_source;
use prost::Message;

use crate::{
    builder::Convert,
    builder_ext::{AuthorizerExt, BuilderExt},
    datalog::{ExternFunc, Origin, RunLimits, SymbolTable, TrustedOrigins, World},
    error,
    format::{
        convert::{
            proto_snapshot_block_to_token_block, token_block_to_proto_snapshot_block,
            v2::{policy_to_proto_policy, proto_policy_to_policy},
        },
        schema,
    },
    token::{self, default_symbol_table, Block, MAX_SCHEMA_VERSION, MIN_SCHEMA_VERSION},
    Authorizer, AuthorizerLimits, Biscuit, PublicKey,
};

use super::{date, fact, BlockBuilder, Check, Fact, Policy, Rule, Scope, Term};

#[derive(Clone, Debug, Default)]
pub struct AuthorizerBuilder {
    authorizer_block_builder: BlockBuilder,
    policies: Vec<Policy>,
    extern_funcs: HashMap<String, ExternFunc>,
    pub(crate) limits: AuthorizerLimits,
}

impl AuthorizerBuilder {
    pub fn new() -> AuthorizerBuilder {
        AuthorizerBuilder::default()
    }

    pub fn fact<F: TryInto<Fact>>(mut self, fact: F) -> Result<Self, error::Token>
    where
        error::Token: From<<F as TryInto<Fact>>::Error>,
    {
        self.authorizer_block_builder = self.authorizer_block_builder.fact(fact)?;
        Ok(self)
    }

    pub fn rule<R: TryInto<Rule>>(mut self, rule: R) -> Result<Self, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        self.authorizer_block_builder = self.authorizer_block_builder.rule(rule)?;
        Ok(self)
    }

    pub fn check<C: TryInto<Check>>(mut self, check: C) -> Result<Self, error::Token>
    where
        error::Token: From<<C as TryInto<Check>>::Error>,
    {
        self.authorizer_block_builder = self.authorizer_block_builder.check(check)?;
        Ok(self)
    }

    /// adds some datalog code to the authorizer
    ///
    /// ```rust
    /// extern crate biscuit_auth as biscuit;
    ///
    /// use biscuit::builder::AuthorizerBuilder;
    ///
    /// let mut authorizer = AuthorizerBuilder::new()
    ///     .code(r#"
    ///       resource("/file1.txt");
    ///
    ///       check if user(1234);
    ///
    ///       // default allow
    ///       allow if true;
    ///     "#)
    ///     .expect("should parse correctly")
    ///     .build_unauthenticated();
    /// ```
    pub fn code<T: AsRef<str>>(self, source: T) -> Result<Self, error::Token> {
        self.code_with_params(source, HashMap::new(), HashMap::new())
    }

    /// Add datalog code to the builder, performing parameter subsitution as required
    /// Unknown parameters are ignored
    pub fn code_with_params<T: AsRef<str>>(
        mut self,
        source: T,
        params: HashMap<String, Term>,
        scope_params: HashMap<String, PublicKey>,
    ) -> Result<Self, error::Token> {
        let source = source.as_ref();

        let source_result = parse_source(source).map_err(|e| {
            let e2: biscuit_parser::error::LanguageError = e.into();
            e2
        })?;

        for (_, fact) in source_result.facts.into_iter() {
            let mut fact: Fact = fact.into();
            for (name, value) in &params {
                let res = match fact.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            fact.validate()?;
            self.authorizer_block_builder.facts.push(fact);
        }

        for (_, rule) in source_result.rules.into_iter() {
            let mut rule: Rule = rule.into();
            for (name, value) in &params {
                let res = match rule.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match rule.set_scope(name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            rule.validate_parameters()?;
            self.authorizer_block_builder.rules.push(rule);
        }

        for (_, check) in source_result.checks.into_iter() {
            let mut check: Check = check.into();
            for (name, value) in &params {
                let res = match check.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match check.set_scope(name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            check.validate_parameters()?;
            self.authorizer_block_builder.checks.push(check);
        }
        for (_, policy) in source_result.policies.into_iter() {
            let mut policy: Policy = policy.into();
            for (name, value) in &params {
                let res = match policy.set(name, value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            for (name, value) in &scope_params {
                let res = match policy.set_scope(name, *value) {
                    Ok(_) => Ok(()),
                    Err(error::Token::Language(
                        biscuit_parser::error::LanguageError::Parameters {
                            missing_parameters, ..
                        },
                    )) if missing_parameters.is_empty() => Ok(()),
                    Err(e) => Err(e),
                };
                res?;
            }
            policy.validate_parameters()?;
            self.policies.push(policy);
        }

        Ok(self)
    }

    pub fn scope(mut self, scope: Scope) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.scope(scope);
        self
    }

    /// add a policy to the authorizer
    pub fn policy<P: TryInto<Policy>>(mut self, policy: P) -> Result<Self, error::Token>
    where
        error::Token: From<<P as TryInto<Policy>>::Error>,
    {
        let policy = policy.try_into()?;
        policy.validate_parameters()?;
        self.policies.push(policy);
        Ok(self)
    }

    /// adds a fact with the current time
    pub fn time(mut self) -> Self {
        let fact = fact("time", &[date(&SystemTime::now())]);
        self.authorizer_block_builder = self.authorizer_block_builder.fact(fact).unwrap();
        self
    }

    /// Sets the runtime limits of the authorizer
    ///
    /// Those limits cover all the executions under the `authorize`, `query` and `query_all` methods
    pub fn set_limits(mut self, limits: AuthorizerLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> &AuthorizerLimits {
        &self.limits
    }

    /// Replaces the registered external functions
    pub fn set_extern_funcs(mut self, extern_funcs: HashMap<String, ExternFunc>) -> Self {
        self.extern_funcs = extern_funcs;
        self
    }

    /// Registers the provided external functions (possibly replacing already registered functions)
    pub fn register_extern_funcs(mut self, extern_funcs: HashMap<String, ExternFunc>) -> Self {
        self.extern_funcs.extend(extern_funcs);
        self
    }

    /// Registers the provided external function (possibly replacing an already registered function)
    pub fn register_extern_func(mut self, name: String, func: ExternFunc) -> Self {
        self.extern_funcs.insert(name, func);
        self
    }

    pub fn dump_code(&self) -> String {
        let mut f = String::new();
        for fact in &self.authorizer_block_builder.facts {
            let _ = writeln!(f, "{fact};");
        }
        if !self.authorizer_block_builder.facts.is_empty() {
            let _ = writeln!(f);
        }

        for rule in &self.authorizer_block_builder.rules {
            let _ = writeln!(f, "{rule};");
        }
        if !self.authorizer_block_builder.rules.is_empty() {
            let _ = writeln!(f);
        }

        for check in &self.authorizer_block_builder.checks {
            let _ = writeln!(f, "{check};");
        }
        if !self.authorizer_block_builder.checks.is_empty() {
            let _ = writeln!(f);
        }

        for policy in &self.policies {
            let _ = writeln!(f, "{policy};");
        }
        f
    }

    /// builds the authorizer from a token
    pub fn build(self, token: &Biscuit) -> Result<Authorizer, error::Token> {
        self.build_inner(Some(token))
    }

    /// builds the authorizer without a token
    pub fn build_unauthenticated(self) -> Result<Authorizer, error::Token> {
        self.build_inner(None)
    }

    fn build_inner(self, token: Option<&Biscuit>) -> Result<Authorizer, error::Token> {
        let mut world = World::new();
        world.extern_funcs = self.extern_funcs;

        let mut symbols = SymbolTable::new();
        let mut public_key_to_block_id: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut token_origins = TrustedOrigins::default();
        let mut blocks: Option<Vec<Block>> = None;

        // load the token if present
        if let Some(token) = token {
            for (i, block) in token.container.blocks.iter().enumerate() {
                if let Some(sig) = block.external_signature.as_ref() {
                    let new_key_id = symbols.public_keys.insert(&sig.public_key);

                    public_key_to_block_id
                        .entry(new_key_id as usize)
                        .or_default()
                        .push(i + 1);
                }
            }

            blocks = Some(
                token
                    .blocks()
                    .enumerate()
                    .map(|(i, block)| {
                        block.and_then(|mut b| {
                            load_and_translate_block(
                                &mut b,
                                i,
                                &token.symbols,
                                &mut symbols,
                                &mut public_key_to_block_id,
                                &mut world,
                            )?;
                            Ok(b)
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );

            token_origins = TrustedOrigins::from_scopes(
                &[token::Scope::Previous],
                &TrustedOrigins::default(),
                token.block_count(),
                &public_key_to_block_id,
            );
        }
        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);

        let authorizer_scopes: Vec<token::Scope> = self
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &public_key_to_block_id,
        );
        for fact in &self.authorizer_block_builder.facts {
            world
                .facts
                .insert(&authorizer_origin, fact.convert(&mut symbols));
        }

        for rule in &self.authorizer_block_builder.rules {
            let rule = rule.convert(&mut symbols);

            let rule_trusted_origins = TrustedOrigins::from_scopes(
                &rule.scopes,
                &authorizer_trusted_origins,
                usize::MAX,
                &public_key_to_block_id,
            );

            world.rules.insert(usize::MAX, &rule_trusted_origins, rule);
        }

        /*
        let start = Instant::now();
        world.run_with_limits(&symbols, self.limits.clone())?;
        let execution_time = start.elapsed();
        */

        Ok(Authorizer {
            authorizer_block_builder: self.authorizer_block_builder,
            world,
            symbols,
            token_origins,
            policies: self.policies,
            blocks,
            public_key_to_block_id,
            limits: self.limits,
            execution_time: None,
        })
    }
}

/// we need to modify the block loaded from the token, because the authorizer's and the token's symbol table can differ
pub(crate) fn load_and_translate_block(
    block: &mut Block,
    i: usize,
    token_symbols: &SymbolTable,
    authorizer_symbols: &mut SymbolTable,
    public_key_to_block_id: &mut HashMap<usize, Vec<usize>>,
    world: &mut World,
) -> Result<(), error::Token> {
    // if it is a 3rd party block, it should not affect the main symbol table
    let block_symbols = if i == 0 || block.external_key.is_none() {
        token_symbols.clone()
    } else {
        block.symbols.clone()
    };

    let mut block_origin = Origin::default();
    block_origin.insert(i);

    for scope in block.scopes.iter_mut() {
        *scope = crate::token::builder::Scope::convert_from(scope, &block_symbols)
            .map(|s| s.convert(authorizer_symbols))?;
    }

    let block_trusted_origins = TrustedOrigins::from_scopes(
        &block.scopes,
        &TrustedOrigins::default(),
        i,
        public_key_to_block_id,
    );

    for fact in block.facts.iter_mut() {
        *fact = Fact::convert_from(fact, &block_symbols)?.convert(authorizer_symbols);
        world.facts.insert(&block_origin, fact.clone());
    }

    for rule in block.rules.iter_mut() {
        if let Err(_message) = rule.validate_variables(&block_symbols) {
            return Err(error::Logic::InvalidBlockRule(0, block_symbols.print_rule(rule)).into());
        }
        *rule = rule.translate(&block_symbols, authorizer_symbols)?;

        let rule_trusted_origins = TrustedOrigins::from_scopes(
            &rule.scopes,
            &block_trusted_origins,
            i,
            public_key_to_block_id,
        );

        world.rules.insert(i, &rule_trusted_origins, rule.clone());
    }

    for check in block.checks.iter_mut() {
        let c = Check::convert_from(check, &block_symbols)?;
        *check = c.convert(authorizer_symbols);
    }

    Ok(())
}

impl BuilderExt for AuthorizerBuilder {
    fn resource(mut self, name: &str) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.resource(name);
        self
    }
    fn check_resource(mut self, name: &str) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.check_resource(name);
        self
    }
    fn operation(mut self, name: &str) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.operation(name);
        self
    }
    fn check_operation(mut self, name: &str) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.check_operation(name);
        self
    }
    fn check_resource_prefix(mut self, prefix: &str) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.check_resource_prefix(prefix);
        self
    }

    fn check_resource_suffix(mut self, suffix: &str) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.check_resource_suffix(suffix);
        self
    }

    fn check_expiration_date(mut self, exp: SystemTime) -> Self {
        self.authorizer_block_builder = self.authorizer_block_builder.check_expiration_date(exp);
        self
    }
}

impl AuthorizerExt for AuthorizerBuilder {
    fn allow_all(self) -> Self {
        self.policy("allow if true").unwrap()
    }
    fn deny_all(self) -> Self {
        self.policy("deny if true").unwrap()
    }
}

impl AuthorizerBuilder {
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

        let version = world.version.unwrap_or(0);
        if !(MIN_SCHEMA_VERSION..=MAX_SCHEMA_VERSION).contains(&version) {
            return Err(error::Format::Version {
                minimum: crate::token::MIN_SCHEMA_VERSION,
                maximum: crate::token::MAX_SCHEMA_VERSION,
                actual: version,
            }
            .into());
        }

        if !world.blocks.is_empty() {
            return Err(error::Format::DeserializationError(
                "cannot deserialize an AuthorizerBuilder fro a snapshot with blocks".to_string(),
            )
            .into());
        }

        if !world.generated_facts.is_empty() {
            return Err(error::Format::DeserializationError(
                "cannot deserialize an AuthorizerBuilder from a snapshot with generated facts"
                    .to_string(),
            )
            .into());
        }

        if world.iterations != 0 {
            return Err(error::Format::DeserializationError(
                "cannot deserialize an AuthorizerBuilder from a snapshot with non-zero iterations"
                    .to_string(),
            )
            .into());
        }

        if execution_time != 0 {
            return Err(error::Format::DeserializationError(
                "cannot deserialize an AuthorizerBuilder from a snapshot with non-zero execution time".to_string(),
            )
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

        let mut authorizer = AuthorizerBuilder::new();
        authorizer.authorizer_block_builder = authorizer_block_builder;
        authorizer.policies = policies;
        authorizer.limits = limits;

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

        let blocks = vec![];

        let generated_facts = vec![];

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
            iterations: 0,
        };

        Ok(schema::AuthorizerSnapshot {
            world,
            execution_time: 0u64,
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
