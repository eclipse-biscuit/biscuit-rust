//! Authorizer structure and associated functions
use super::builder::{AuthorizerBuilder, BlockBuilder, Check, Fact, Policy, PolicyKind, Rule};
use super::{Biscuit, Block};
use crate::builder::{CheckKind, Convert};
use crate::datalog::{self, ExternFunc, Origin, RunLimits, TrustedOrigins};
use crate::error;
use crate::time::Instant;
use crate::token;
use prost::Message;
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    default::Default,
    fmt::Write,
};

mod snapshot;

/// used to check authorization policies on a token
///
/// can be created from [Biscuit::authorizer] or [Authorizer::new]
#[derive(Clone, Debug)]
pub struct Authorizer {
    pub(crate) authorizer_block_builder: BlockBuilder,
    pub(crate) world: datalog::World,
    pub(crate) symbols: datalog::SymbolTable,
    pub(crate) token_origins: TrustedOrigins,
    pub(crate) policies: Vec<Policy>,
    pub(crate) blocks: Option<Vec<Block>>,
    pub(crate) public_key_to_block_id: HashMap<usize, Vec<usize>>,
    pub(crate) limits: AuthorizerLimits,
    pub(crate) execution_time: Option<Duration>,
}

impl Authorizer {
    pub fn run(&mut self) -> Result<Duration, error::Token> {
        match self.execution_time {
            Some(execution_time) => Ok(execution_time),
            None => {
                let start = Instant::now();
                self.world
                    .run_with_limits(&self.symbols, self.limits.clone())?;
                let execution_time = start.elapsed();
                self.execution_time = Some(execution_time);
                Ok(execution_time)
            }
        }
    }

    pub(crate) fn from_token(token: &Biscuit) -> Result<Self, error::Token> {
        AuthorizerBuilder::new().build(token)
    }

    /// creates a new empty authorizer
    ///
    /// this can be used to check policies when:
    /// * there is no token (unauthenticated case)
    /// * there is a lot of data to load in the authorizer on each check
    ///
    /// In the latter case, we can create an empty authorizer, load it
    /// with the facts, rules and checks, and each time a token must be checked,
    /// clone the authorizer and load the token with [`Authorizer::add_token`]
    fn new() -> Self {
        let world = datalog::World::new();
        let symbols = super::default_symbol_table();
        let authorizer_block_builder = BlockBuilder::new();

        Authorizer {
            authorizer_block_builder,
            world,
            symbols,
            token_origins: TrustedOrigins::default(),
            policies: vec![],
            blocks: None,
            public_key_to_block_id: HashMap::new(),
            limits: AuthorizerLimits::default(),
            execution_time: None,
        }
    }

    /// creates an `Authorizer` from a serialized [crate::format::schema::AuthorizerPolicies]
    pub fn from(data: &[u8]) -> Result<Self, error::Token> {
        AuthorizerPolicies::deserialize(data)?.try_into()
    }

    /// serializes a authorizer's content
    ///
    /// you can use this to save a set of policies and load them quickly before
    /// verification. This will not store data obtained or generated from a token.
    pub fn save(&self) -> Result<AuthorizerPolicies, error::Token> {
        let facts = self.authorizer_block_builder.facts.to_vec();

        let rules = self.authorizer_block_builder.rules.to_vec();

        let checks = self.authorizer_block_builder.checks.to_vec();

        Ok(AuthorizerPolicies {
            version: crate::token::MAX_SCHEMA_VERSION,
            facts,
            rules,
            checks,
            policies: self.policies.clone(),
        })
    }

    /// Returns the runtime limits of the authorizer
    ///
    /// Those limits cover all the executions under the `authorize`, `query` and `query_all` methods
    pub fn limits(&self) -> &AuthorizerLimits {
        &self.limits
    }

    /// Returns the currently registered external functions
    pub fn external_funcs(&self) -> &HashMap<String, ExternFunc> {
        &self.world.extern_funcs
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// let keypair = KeyPair::new();
    /// let biscuit = Biscuit::builder()
    ///     .fact("user(\"John Doe\", 42)")
    ///     .expect("parse error")
    ///     .build(&keypair)
    ///     .unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: Vec<(String, i64)> = authorizer.query("data($name, $id) <- user($name, $id)").unwrap();
    /// # assert_eq!(res.len(), 1);
    /// # assert_eq!(res[0].0, "John Doe");
    /// # assert_eq!(res[0].1, 42);
    /// ```
    // TODO rename as `query_token`
    pub fn query<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let execution_time = self.run()?;
        let mut limits = self.limits.clone();
        limits.max_iterations -= self.world.iterations;
        if execution_time >= limits.max_time {
            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
        }
        limits.max_time -= execution_time;

        self.query_with_limits(rule, limits)
    }

    /// Run a query over the authorizer's Datalog engine to gather data.
    /// If there is more than one result, this function will throw an error.
    ///
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// let keypair = KeyPair::new();
    /// let builder = Biscuit::builder().fact("user(\"John Doe\", 42)").unwrap();
    ///
    /// let biscuit = builder.build(&keypair).unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: (String, i64) = authorizer.query_exactly_one("data($name, $id) <- user($name, $id)").unwrap();
    /// assert_eq!(res.0, "John Doe");
    /// assert_eq!(res.1, 42);
    /// ```
    pub fn query_exactly_one<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
    ) -> Result<T, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let mut res: Vec<T> = self.query(rule)?;
        if res.len() == 1 {
            Ok(res.remove(0))
        } else {
            Err(error::Token::RunLimit(
                error::RunLimit::UnexpectedQueryResult(1, res.len()),
            ))
        }
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this only sees facts from the authorizer and the authority block
    ///
    /// this method overrides the authorizer's runtime limits, just for this calls
    pub fn query_with_limits<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let execution_time = self.run()?;
        let rule = rule.try_into()?.convert(&mut self.symbols);

        let start = Instant::now();
        let result = self.query_inner(rule, limits);
        self.execution_time = Some(start.elapsed() + execution_time);

        result
    }

    fn query_inner<T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: datalog::Rule,
        _limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token> {
        let rule_trusted_origins = TrustedOrigins::from_scopes(
            &rule.scopes,
            &TrustedOrigins::default(), // for queries, we don't want to default on the authorizer trust
            // queries are there to explore the final state of the world,
            // whereas authorizer contents are there to authorize or not
            // a token
            usize::MAX,
            &self.public_key_to_block_id,
        );

        let res = self
            .world
            .query_rule(rule, usize::MAX, &rule_trusted_origins, &self.symbols)?;

        res.inner
            .into_iter()
            .flat_map(|(_, set)| set.into_iter())
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| {
                fact.map_err(error::Token::Format)
                    .and_then(|f| f.try_into().map_err(Into::into))
            })
            .collect()
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this has access to the facts generated when evaluating all the blocks
    ///
    /// ```rust
    /// # use biscuit_auth::KeyPair;
    /// # use biscuit_auth::Biscuit;
    /// let keypair = KeyPair::new();
    /// let biscuit = Biscuit::builder()
    ///     .fact("user(\"John Doe\", 42)")
    ///     .expect("parse error")
    ///     .build(&keypair)
    ///     .unwrap();
    ///
    /// let mut authorizer = biscuit.authorizer().unwrap();
    /// let res: Vec<(String, i64)> = authorizer.query_all("data($name, $id) <- user($name, $id)").unwrap();
    /// # assert_eq!(res.len(), 1);
    /// # assert_eq!(res[0].0, "John Doe");
    /// # assert_eq!(res[0].1, 42);
    /// ```
    pub fn query_all<R: TryInto<Rule>, T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: R,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let execution_time = self.run()?;
        let mut limits = self.limits.clone();
        limits.max_iterations -= self.world.iterations;
        if execution_time >= limits.max_time {
            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
        }
        limits.max_time -= execution_time;

        self.query_all_with_limits(rule, limits)
    }

    /// run a query over the authorizer's Datalog engine to gather data
    ///
    /// this has access to the facts generated when evaluating all the blocks
    ///
    /// this method overrides the authorizer's runtime limits, just for this calls
    pub fn query_all_with_limits<
        R: TryInto<Rule>,
        T: TryFrom<Fact, Error = E>,
        E: Into<error::Token>,
    >(
        &mut self,
        rule: R,
        limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token>
    where
        error::Token: From<<R as TryInto<Rule>>::Error>,
    {
        let execution_time = self.run()?;
        let rule = rule.try_into()?.convert(&mut self.symbols);

        let start = Instant::now();
        let result = self.query_all_inner(rule, limits);
        self.execution_time = Some(execution_time + start.elapsed());

        result
    }

    fn query_all_inner<T: TryFrom<Fact, Error = E>, E: Into<error::Token>>(
        &mut self,
        rule: datalog::Rule,
        _limits: AuthorizerLimits,
    ) -> Result<Vec<T>, error::Token> {
        let rule_trusted_origins = if rule.scopes.is_empty() {
            self.token_origins.clone()
        } else {
            TrustedOrigins::from_scopes(
                &rule.scopes,
                &TrustedOrigins::default(), // for queries, we don't want to default on the authorizer trust
                // queries are there to explore the final state of the world,
                // whereas authorizer contents are there to authorize or not
                // a token
                usize::MAX,
                &self.public_key_to_block_id,
            )
        };

        let res = self
            .world
            .query_rule(rule, 0, &rule_trusted_origins, &self.symbols)?;

        let r: HashSet<_> = res.into_iter().map(|(_, fact)| fact).collect();

        r.into_iter()
            .map(|f| Fact::convert_from(&f, &self.symbols))
            .map(|fact| {
                fact.map_err(error::Token::Format)
                    .and_then(|f| f.try_into().map_err(Into::into))
            })
            .collect::<Result<Vec<T>, _>>()
    }

    /// returns the elapsed execution time
    pub fn execution_time(&self) -> Option<Duration> {
        self.execution_time
    }

    /// returns the number of fact generation iterations
    pub fn iterations(&self) -> u64 {
        self.world.iterations
    }

    /// returns the number of facts
    pub fn fact_count(&self) -> usize {
        self.world.facts.len()
    }

    /// verifies the checks and policies
    ///
    /// on error, this can return a list of all the failed checks or deny policy
    /// on success, it returns the index of the policy that matched
    pub fn authorize(&mut self) -> Result<usize, error::Token> {
        let execution_time = self.run()?;
        let mut limits = self.limits.clone();
        limits.max_iterations -= self.world.iterations;
        if execution_time >= limits.max_time {
            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
        }
        limits.max_time -= execution_time;

        self.authorize_with_limits(limits)
    }

    /// verifies the checks and policies
    ///
    /// on error, this can return a list of all the failed checks or deny policy
    ///
    /// this method overrides the authorizer's runtime limits, just for this calls
    pub fn authorize_with_limits(
        &mut self,
        limits: AuthorizerLimits,
    ) -> Result<usize, error::Token> {
        let execution_time = self.run()?;
        let start = Instant::now();
        let result = self.authorize_inner(limits);
        self.execution_time = Some(execution_time + start.elapsed());

        result
    }

    fn authorize_inner(&mut self, limits: AuthorizerLimits) -> Result<usize, error::Token> {
        let start = Instant::now();
        let time_limit = start + limits.max_time;

        let mut errors = vec![];
        let mut policy_result: Option<Result<usize, usize>> = None;

        let mut authorizer_origin = Origin::default();
        authorizer_origin.insert(usize::MAX);

        let authorizer_scopes: Vec<token::Scope> = self
            .authorizer_block_builder
            .scopes
            .clone()
            .iter()
            .map(|s| s.convert(&mut self.symbols))
            .collect();

        let authorizer_trusted_origins = TrustedOrigins::from_scopes(
            &authorizer_scopes,
            &TrustedOrigins::default(),
            usize::MAX,
            &self.public_key_to_block_id,
        );

        for (i, check) in self.authorizer_block_builder.checks.iter().enumerate() {
            let c = check.convert(&mut self.symbols);
            let mut successful = false;

            for query in check.queries.iter() {
                let query = query.convert(&mut self.symbols);
                let rule_trusted_origins = TrustedOrigins::from_scopes(
                    &query.scopes,
                    &authorizer_trusted_origins,
                    usize::MAX,
                    &self.public_key_to_block_id,
                );
                let res = match check.kind {
                    CheckKind::One => self.world.query_match(
                        query,
                        usize::MAX,
                        &rule_trusted_origins,
                        &self.symbols,
                    )?,
                    CheckKind::All => {
                        self.world
                            .query_match_all(query, &rule_trusted_origins, &self.symbols)?
                    }
                    CheckKind::Reject => !self.world.query_match(
                        query,
                        usize::MAX,
                        &rule_trusted_origins,
                        &self.symbols,
                    )?,
                };

                let now = Instant::now();
                if now >= time_limit {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }

                if res {
                    successful = true;
                    break;
                }
            }

            if !successful {
                errors.push(error::FailedCheck::Authorizer(
                    error::FailedAuthorizerCheck {
                        check_id: i as u32,
                        rule: self.symbols.print_check(&c),
                    },
                ));
            }
        }

        if let Some(blocks) = self.blocks.as_ref() {
            for (j, check) in blocks[0].checks.iter().enumerate() {
                let mut successful = false;

                let authority_trusted_origins = TrustedOrigins::from_scopes(
                    &blocks[0].scopes,
                    &TrustedOrigins::default(),
                    0,
                    &self.public_key_to_block_id,
                );

                for query in check.queries.iter() {
                    let rule_trusted_origins = TrustedOrigins::from_scopes(
                        &query.scopes,
                        &authority_trusted_origins,
                        0,
                        &self.public_key_to_block_id,
                    );
                    let res = match check.kind {
                        CheckKind::One => self.world.query_match(
                            query.clone(),
                            0,
                            &rule_trusted_origins,
                            &self.symbols,
                        )?,
                        CheckKind::All => self.world.query_match_all(
                            query.clone(),
                            &rule_trusted_origins,
                            &self.symbols,
                        )?,
                        CheckKind::Reject => !self.world.query_match(
                            query.clone(),
                            0,
                            &rule_trusted_origins,
                            &self.symbols,
                        )?,
                    };

                    let now = Instant::now();
                    if now >= time_limit {
                        return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                    }

                    if res {
                        successful = true;
                        break;
                    }
                }

                if !successful {
                    errors.push(error::FailedCheck::Block(error::FailedBlockCheck {
                        block_id: 0u32,
                        check_id: j as u32,
                        rule: self.symbols.print_check(check),
                    }));
                }
            }
        }

        'policies_test: for (i, policy) in self.policies.iter().enumerate() {
            for query in policy.queries.iter() {
                let query = query.convert(&mut self.symbols);
                let rule_trusted_origins = TrustedOrigins::from_scopes(
                    &query.scopes,
                    &authorizer_trusted_origins,
                    usize::MAX,
                    &self.public_key_to_block_id,
                );

                let res = self.world.query_match(
                    query,
                    usize::MAX,
                    &rule_trusted_origins,
                    &self.symbols,
                )?;

                let now = Instant::now();
                if now >= time_limit {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }

                if res {
                    match policy.kind {
                        PolicyKind::Allow => policy_result = Some(Ok(i)),
                        PolicyKind::Deny => policy_result = Some(Err(i)),
                    };
                    break 'policies_test;
                }
            }
        }

        if let Some(blocks) = self.blocks.as_ref() {
            for (i, block) in (blocks[1..]).iter().enumerate() {
                let block_trusted_origins = TrustedOrigins::from_scopes(
                    &block.scopes,
                    &TrustedOrigins::default(),
                    i + 1,
                    &self.public_key_to_block_id,
                );

                for (j, check) in block.checks.iter().enumerate() {
                    let mut successful = false;

                    for query in check.queries.iter() {
                        let rule_trusted_origins = TrustedOrigins::from_scopes(
                            &query.scopes,
                            &block_trusted_origins,
                            i + 1,
                            &self.public_key_to_block_id,
                        );

                        let res = match check.kind {
                            CheckKind::One => self.world.query_match(
                                query.clone(),
                                i + 1,
                                &rule_trusted_origins,
                                &self.symbols,
                            )?,
                            CheckKind::All => self.world.query_match_all(
                                query.clone(),
                                &rule_trusted_origins,
                                &self.symbols,
                            )?,
                            CheckKind::Reject => !self.world.query_match(
                                query.clone(),
                                i + 1,
                                &rule_trusted_origins,
                                &self.symbols,
                            )?,
                        };

                        let now = Instant::now();
                        if now >= time_limit {
                            return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                        }

                        if res {
                            successful = true;
                            break;
                        }
                    }

                    if !successful {
                        errors.push(error::FailedCheck::Block(error::FailedBlockCheck {
                            block_id: (i + 1) as u32,
                            check_id: j as u32,
                            rule: self.symbols.print_check(check),
                        }));
                    }
                }
            }
        }

        match (policy_result, errors.is_empty()) {
            (Some(Ok(i)), true) => Ok(i),
            (None, _) => Err(error::Token::FailedLogic(error::Logic::NoMatchingPolicy {
                checks: errors,
            })),
            (Some(Ok(i)), _) => Err(error::Token::FailedLogic(error::Logic::Unauthorized {
                policy: error::MatchedPolicy::Allow(i),
                checks: errors,
            })),
            (Some(Err(i)), _) => Err(error::Token::FailedLogic(error::Logic::Unauthorized {
                policy: error::MatchedPolicy::Deny(i),
                checks: errors,
            })),
        }
    }

    /// prints the content of the authorizer
    pub fn print_world(&self) -> String {
        self.to_string()
    }

    /// returns all of the data loaded in the authorizer
    pub fn dump(&self) -> (Vec<Fact>, Vec<Rule>, Vec<Check>, Vec<Policy>) {
        let mut checks = self.authorizer_block_builder.checks.clone();
        if let Some(blocks) = &self.blocks {
            for block in blocks {
                checks.extend(
                    block
                        .checks
                        .iter()
                        .map(|c| Check::convert_from(c, &self.symbols).unwrap()),
                );
            }
        }

        let facts = self
            .world
            .facts
            .iter_all()
            .map(|f| Fact::convert_from(f.1, &self.symbols))
            .collect::<Result<Vec<_>, error::Format>>()
            .unwrap();

        let rules = self
            .world
            .rules
            .iter_all()
            .map(|r| Rule::convert_from(r.1, &self.symbols))
            .collect::<Result<Vec<_>, error::Format>>()
            .unwrap();

        (facts, rules, checks, self.policies.clone())
    }

    pub fn dump_code(&self) -> String {
        let (facts, rules, checks, policies) = self.dump();
        let mut f = String::new();

        let mut facts = facts.into_iter().map(|f| f.to_string()).collect::<Vec<_>>();
        facts.sort();
        for fact in &facts {
            let _ = writeln!(f, "{fact};");
        }
        if !facts.is_empty() {
            let _ = writeln!(f);
        }

        for rule in &rules {
            let _ = writeln!(f, "{rule};");
        }
        if !rules.is_empty() {
            let _ = writeln!(f);
        }

        for check in &checks {
            let _ = writeln!(f, "{check};");
        }
        if !checks.is_empty() {
            let _ = writeln!(f);
        }

        for policy in &policies {
            let _ = writeln!(f, "{policy};");
        }
        f
    }
}

impl std::fmt::Display for Authorizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut has_facts = false;
        let mut all_facts = BTreeMap::new();
        for (origin, factset) in &self.world.facts.inner {
            let mut facts = HashSet::new();
            for fact in factset {
                facts.insert(self.symbols.print_fact(fact));
            }

            has_facts = has_facts || !facts.is_empty();
            all_facts.insert(origin, facts);
        }

        if has_facts {
            writeln!(f, "// Facts:")?;
        }

        for (origin, factset) in &all_facts {
            let mut facts = factset.iter().collect::<Vec<_>>();
            facts.sort();

            if !facts.is_empty() {
                writeln!(f, "// origin: {origin}")?;
            }

            for fact in facts {
                writeln!(f, "{};", fact)?;
            }
        }

        if has_facts {
            writeln!(f)?;
        }

        let mut has_rules = false;
        let mut rules_map: BTreeMap<usize, HashSet<String>> = BTreeMap::new();
        for ruleset in self.world.rules.inner.values() {
            has_rules = has_rules || !ruleset.is_empty();
            for (origin, rule) in ruleset {
                rules_map
                    .entry(*origin)
                    .or_default()
                    .insert(self.symbols.print_rule(rule));
            }
        }

        if has_rules {
            writeln!(f, "// Rules:")?;
        }

        for (origin, rule_list) in &rules_map {
            if !rule_list.is_empty() {
                if *origin == usize::MAX {
                    writeln!(f, "// origin: authorizer")?;
                } else {
                    writeln!(f, "// origin: {origin}")?;
                }
            }

            let mut sorted_rule_list = rule_list.iter().collect::<Vec<_>>();
            sorted_rule_list.sort();
            for rule in sorted_rule_list {
                writeln!(f, "{};", rule)?;
            }
        }

        if has_rules {
            writeln!(f)?;
        }

        let mut has_checks = false;
        let mut checks_map: BTreeMap<usize, Vec<String>> = Default::default();

        if let Some(blocks) = &self.blocks {
            for (i, block) in blocks.iter().enumerate() {
                let entry = checks_map.entry(i).or_default();
                has_checks = has_checks || !&block.checks.is_empty();
                for check in &block.checks {
                    entry.push(self.symbols.print_check(check));
                }
            }
        }

        let authorizer_entry = checks_map.entry(usize::MAX).or_default();

        has_checks = has_checks || !&self.authorizer_block_builder.checks.is_empty();
        for check in &self.authorizer_block_builder.checks {
            authorizer_entry.push(check.to_string());
        }

        if has_checks {
            writeln!(f, "// Checks:")?;
        }

        for (origin, checks) in checks_map {
            if !checks.is_empty() {
                if origin == usize::MAX {
                    writeln!(f, "// origin: authorizer")?;
                } else {
                    writeln!(f, "// origin: {origin}")?;
                }
            }

            for check in checks {
                writeln!(f, "{};", &check)?;
            }
        }

        if has_checks {
            writeln!(f)?;
        }

        if !self.policies.is_empty() {
            writeln!(f, "// Policies:")?;
        }
        for policy in self.policies.iter() {
            writeln!(f, "{policy};")?;
        }

        Ok(())
    }
}

impl TryFrom<AuthorizerPolicies> for Authorizer {
    type Error = error::Token;

    fn try_from(authorizer_policies: AuthorizerPolicies) -> Result<Self, Self::Error> {
        let AuthorizerPolicies {
            version: _,
            facts,
            rules,
            checks,
            policies,
        } = authorizer_policies;

        let mut authorizer = Self::new();

        for fact in facts.into_iter() {
            authorizer.authorizer_block_builder = authorizer.authorizer_block_builder.fact(fact)?;
        }

        for rule in rules.into_iter() {
            authorizer.authorizer_block_builder = authorizer.authorizer_block_builder.rule(rule)?;
        }

        for check in checks.into_iter() {
            authorizer.authorizer_block_builder =
                authorizer.authorizer_block_builder.check(check)?;
        }

        for policy in policies {
            authorizer.policies.push(policy);
        }

        Ok(authorizer)
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizerPolicies {
    pub version: u32,
    /// list of facts provided by this block
    pub facts: Vec<Fact>,
    /// list of rules provided by blocks
    pub rules: Vec<Rule>,
    /// checks that the token and ambient data must validate
    pub checks: Vec<Check>,
    pub policies: Vec<Policy>,
}

impl AuthorizerPolicies {
    pub fn serialize(&self) -> Result<Vec<u8>, error::Token> {
        let proto = crate::format::convert::authorizer_to_proto_authorizer(self);

        let mut v = Vec::new();

        proto
            .encode(&mut v)
            .map(|_| v)
            .map_err(|e| error::Format::SerializationError(format!("serialization error: {:?}", e)))
            .map_err(error::Token::Format)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, error::Token> {
        let data = crate::format::schema::AuthorizerPolicies::decode(data).map_err(|e| {
            error::Format::DeserializationError(format!("deserialization error: {:?}", e))
        })?;

        Ok(crate::format::convert::proto_authorizer_to_authorizer(
            &data,
        )?)
    }
}

pub type AuthorizerLimits = RunLimits;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use datalog::{SymbolTable, World};
    use token::builder::{self, load_and_translate_block, var};
    use token::{public_keys::PublicKeys, DATALOG_3_1};

    use crate::PublicKey;
    use crate::{
        builder::{BiscuitBuilder, BlockBuilder},
        KeyPair,
    };

    use super::*;

    #[test]
    fn empty_authorizer() {
        let mut authorizer = AuthorizerBuilder::new()
            .policy("allow if true")
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        assert_eq!(
            authorizer.authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            }),
            Ok(0)
        );
    }

    #[test]
    fn parameter_substitution() {
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "value".into());
        params.insert("p2".to_string(), 0i64.into());
        params.insert("p3".to_string(), true.into());
        let mut scope_params = HashMap::new();
        scope_params.insert(
            "pk".to_string(),
            PublicKey::from_bytes(
                &hex::decode("6e9e6d5a75cf0c0e87ec1256b4dfed0ca3ba452912d213fcc70f8516583db9db")
                    .unwrap(),
                crate::builder::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let _authorizer = AuthorizerBuilder::new()
            .code_with_params(
                r#"
                  fact({p1}, "value");
                  rule($var, {p2}) <- fact($var, {p2});
                  check if {p3};
                  allow if {p3} trusting {pk};
              "#,
                params,
                scope_params,
            )
            .unwrap()
            .build_unauthenticated()
            .unwrap();
    }

    #[test]
    fn forbid_unbound_parameters() {
        let builder = AuthorizerBuilder::new();

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
        let mut policy = Policy::try_from("allow if {p4}, {p3}").unwrap();
        policy.set("p3", true).unwrap();

        let res = builder.clone().policy(policy);
        assert_eq!(
            res.unwrap_err(),
            error::Token::Language(biscuit_parser::error::LanguageError::Parameters {
                missing_parameters: vec!["p4".to_string()],
                unused_parameters: vec![],
            })
        );
    }

    #[test]
    fn forbid_unbound_parameters_in_add_code() {
        let builder = AuthorizerBuilder::new();
        let mut params = HashMap::new();
        params.insert("p1".to_string(), "hello".into());
        params.insert("p2".to_string(), 1i64.into());
        params.insert("p4".to_string(), "this will be ignored".into());
        let res = builder.code_with_params(
            r#"fact({p1}, "value");
             rule($head_var) <- f1($head_var), {p2} > 0;
             check if {p3};
             allow if {p3};
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
        )
    }

    #[test]
    fn query_authorizer_from_token_tuple() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let biscuit = Biscuit::builder()
            .fact("user(\"John Doe\", 42)")
            .unwrap()
            .build(&keypair)
            .unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Vec<(String, i64)> = authorizer
            .query("data($name, $id) <- user($name, $id)")
            .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].0, "John Doe");
        assert_eq!(res[0].1, 42);
    }

    #[test]
    fn query_authorizer_from_token_string() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let biscuit = Biscuit::builder()
            .fact("user(\"John Doe\")")
            .unwrap()
            .build(&keypair)
            .unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Vec<(String,)> = authorizer.query("data($name) <- user($name)").unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].0, "John Doe");
    }

    #[test]
    fn query_exactly_one_authorizer_from_token_string() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let builder = Biscuit::builder().fact("user(\"John Doe\")").unwrap();

        let biscuit = builder.build(&keypair).unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: (String,) = authorizer
            .query_exactly_one("data($name) <- user($name)")
            .unwrap();
        assert_eq!(res.0, "John Doe");
    }

    #[test]
    fn query_exactly_one_no_results() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let builder = Biscuit::builder();

        let biscuit = builder.build(&keypair).unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Result<(String,), error::Token> =
            authorizer.query_exactly_one("data($name) <- user($name)");
        assert_eq!(
            res.unwrap_err().to_string(),
            "Reached Datalog execution limits"
        );
    }

    #[test]
    fn query_exactly_one_too_many_results() {
        use crate::Biscuit;
        use crate::KeyPair;
        let keypair = KeyPair::new();
        let builder = Biscuit::builder()
            .fact("user(\"John Doe\")")
            .unwrap()
            .fact("user(\"Jane Doe\")")
            .unwrap();

        let biscuit = builder.build(&keypair).unwrap();

        let mut authorizer = biscuit.authorizer().unwrap();
        let res: Result<(String,), error::Token> =
            authorizer.query_exactly_one("data($name) <- user($name)");
        assert_eq!(
            res.unwrap_err().to_string(),
            "Reached Datalog execution limits"
        );
    }

    #[test]
    fn authorizer_with_scopes() {
        let root = KeyPair::new();
        let external = KeyPair::new();

        let mut scope_params = HashMap::new();
        scope_params.insert("external_pub".to_string(), external.public());

        let biscuit1 = Biscuit::builder()
            .code_with_params(
                r#"right("read");
           check if group("admin") trusting {external_pub};
        "#,
                HashMap::new(),
                scope_params,
            )
            .unwrap()
            .build(&root)
            .unwrap();

        let req = biscuit1.third_party_request().unwrap();

        let builder = BlockBuilder::new()
            .code(
                r#"group("admin");
             check if right("read");
            "#,
            )
            .unwrap();
        let res = req.create_block(&external.private(), builder).unwrap();
        let biscuit2 = biscuit1.append_third_party(external.public(), res).unwrap();
        let serialized = biscuit2.to_vec().unwrap();
        let biscuit2 = Biscuit::from(serialized, root.public()).unwrap();

        let builder = AuthorizerBuilder::new();
        let external2 = KeyPair::new();

        let mut scope_params = HashMap::new();
        scope_params.insert("external".to_string(), external.public());
        scope_params.insert("external2".to_string(), external2.public());

        let mut authorizer = builder
            .code_with_params(
                r#"
            // this rule trusts both the third-party block and the authority, and can access facts
            // from both
            possible(true) <- right($right), group("admin") trusting authority, {external};

            // this rule only trusts the third-party block and can't access authority facts
            // it should _not_ generate a fact
            impossible(true) <- right("read") trusting {external2};

            authorizer(true);

            check if possible(true) trusting authority, {external};
            deny if impossible(true) trusting {external2};
            allow if true;
            "#,
                HashMap::new(),
                scope_params,
            )
            .unwrap()
            .set_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10), //Set 10 seconds as the maximum time allowed for the authorization due to "cheap" worker on GitHub Actions
                ..Default::default()
            })
            .build(&biscuit2)
            .unwrap();

        println!("token:\n{}", biscuit2);
        println!("world:\n{}", authorizer.print_world());

        let res = authorizer.authorize_with_limits(AuthorizerLimits {
            max_time: Duration::from_secs(10),
            ..Default::default()
        });
        println!("world after:\n{}", authorizer.print_world());

        res.unwrap();

        // authorizer facts are always visible, no matter what
        let authorizer_facts: Vec<Fact> = authorizer
            .query_with_limits(
                "authorizer(true) <- authorizer(true)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(authorizer_facts.len(), 1);

        // authority facts are visible by default
        let authority_facts: Vec<Fact> = authorizer
            .query_with_limits(
                "right($right) <- right($right)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(authority_facts.len(), 1);

        // authority facts are not visible if
        // there is an explicit rule scope annotation that does
        // not cover previous or authority
        let authority_facts_untrusted: Vec<Fact> = authorizer
            .query_with_limits(
                {
                    let mut r: Rule = "right($right) <- right($right) trusting {external}"
                        .try_into()
                        .unwrap();
                    r.set_scope("external", external.public()).unwrap();
                    r
                },
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(authority_facts_untrusted.len(), 0);

        // block facts are not visible by default
        let block_facts_untrusted: Vec<Fact> = authorizer
            .query_with_limits(
                "group($group) <- group($group)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_untrusted.len(), 0);

        // block facts are visible if trusted
        let block_facts_trusted: Vec<Fact> = authorizer
            .query_with_limits(
                {
                    let mut r: Rule = "group($group) <- group($group) trusting {external}"
                        .try_into()
                        .unwrap();
                    r.set_scope("external", external.public()).unwrap();
                    r
                },
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_trusted.len(), 1);

        // block facts are visible by default with query_all
        let block_facts_query_all: Vec<Fact> = authorizer
            .query_all_with_limits(
                "group($group) <- group($group)",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_query_all.len(), 1);

        // block facts are not visible with query_all if the query has an explicit
        // scope annotation that does not trust them
        let block_facts_query_all_explicit: Vec<Fact> = authorizer
            .query_all_with_limits(
                "group($group) <- group($group) trusting authority",
                AuthorizerLimits {
                    max_time: Duration::from_secs(10),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(block_facts_query_all_explicit.len(), 0);
    }

    #[test]
    fn authorizer_display_before_and_after_authorization() {
        let root = KeyPair::new();

        let token = BiscuitBuilder::new()
            .code(
                r#"
            authority_fact(true);
            authority_rule($v) <- authority_fact($v);
            check if authority_fact(true), authority_rule(true);
        "#,
            )
            .unwrap()
            .build(&root)
            .unwrap();

        let mut authorizer = AuthorizerBuilder::new()
            .code(
                r#"
          authorizer_fact(true);
          authorizer_rule($v) <- authorizer_fact($v);
          check if authorizer_fact(true), authorizer_rule(true);
          allow if true;
        "#,
            )
            .unwrap()
            .build(&token)
            .unwrap();
        let output_before_authorization = authorizer.to_string();

        assert!(
            output_before_authorization.contains("authorizer_fact(true)"),
            "Authorizer.to_string() displays authorizer facts even before running authorize()"
        );

        authorizer
            .authorize_with_limits(AuthorizerLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            })
            .unwrap();

        let output_after_authorization = authorizer.to_string();
        assert!(
            output_after_authorization.contains("authorizer_rule(true)"),
            "Authorizer.to_string() displays generated facts after running authorize()"
        );

        assert_eq!(
            r#"// Facts:
// origin: 0
authority_fact(true);
authority_rule(true);
// origin: authorizer
authorizer_fact(true);
authorizer_rule(true);

// Rules:
// origin: 0
authority_rule($v) <- authority_fact($v);
// origin: authorizer
authorizer_rule($v) <- authorizer_fact($v);

// Checks:
// origin: 0
check if authority_fact(true), authority_rule(true);
// origin: authorizer
check if authorizer_fact(true), authorizer_rule(true);

// Policies:
allow if true;
"#,
            output_after_authorization
        );
    }

    #[test]
    fn empty_authorizer_display() {
        let authorizer = Authorizer::new();
        assert_eq!("", authorizer.to_string())
    }

    #[test]
    fn rule_validate_variables() {
        let builder = AuthorizerBuilder::new();
        let mut syms = SymbolTable::new();
        let rule_name = syms.insert("test");
        let pred_name = syms.insert("pred");
        let rule = datalog::rule(
            rule_name,
            &[datalog::var(&mut syms, "unbound")],
            &[datalog::pred(pred_name, &[datalog::var(&mut syms, "any")])],
        );
        let mut block = Block {
            symbols: syms.clone(),
            facts: vec![],
            rules: vec![rule],
            checks: vec![],
            context: None,
            version: DATALOG_3_1,
            external_key: None,
            public_keys: PublicKeys::new(),
            scopes: vec![],
        };

        // FIXME
        assert_eq!(
            /*builder
            .load_and_translate_block(&mut block, 0, &syms)*/
            load_and_translate_block(
                &mut block,
                0,
                &syms,
                &mut SymbolTable::new(),
                &mut HashMap::new(),
                &mut World::new(),
            )
            .unwrap_err(),
            error::Token::FailedLogic(error::Logic::InvalidBlockRule(
                0,
                "test($unbound) <- pred($any)".to_string()
            ))
        );

        // broken rules directly added to the authorizer currently don’t trigger any error, but silently fail to generate facts when they match
        let mut authorizer = builder
            .rule(builder::rule(
                "test",
                &[var("unbound")],
                &[builder::pred("pred", &[builder::var("any")])],
            ))
            .unwrap()
            .build_unauthenticated()
            .unwrap();
        let res: Vec<(String,)> = authorizer
            .query(builder::rule(
                "output",
                &[builder::string("x")],
                &[builder::pred("test", &[builder::var("any")])],
            ))
            .unwrap();

        assert_eq!(res, vec![]);
    }
}
