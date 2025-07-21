/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Procedural macros to build biscuit-auth tokens and authorizers

use biscuit_parser::{
    builder::{Check, Fact, Policy, Rule},
    error,
    parser::{parse_block_source, parse_source},
};
use proc_macro2::{Span, TokenStream};
use proc_macro_error2::{abort_call_site, proc_macro_error};
use quote::{quote, ToTokens};
use std::collections::{HashMap, HashSet};
use syn::{
    parse::{self, Parse, ParseStream},
    Expr, Ident, LitStr, Token, TypePath,
};

// parses ", foo = bar, baz = quux", including the leading comma
struct ParsedParameters {
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedParameters {
    fn parse(input: ParseStream) -> parse::Result<Self> {
        let mut parameters = HashMap::new();

        while input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
            if input.is_empty() {
                break;
            }

            let key: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;
            let value: Expr = input.parse()?;

            parameters.insert(key.to_string(), value);
        }

        Ok(Self { parameters })
    }
}

// parses "\"...\", foo = bar, baz = quux"
struct ParsedCreateNew {
    datalog: String,
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedCreateNew {
    fn parse(input: ParseStream) -> parse::Result<Self> {
        let datalog = input.parse::<LitStr>()?.value();
        let parameters = input.parse::<ParsedParameters>()?;

        Ok(Self {
            datalog,
            parameters: parameters.parameters,
        })
    }
}

// parses "&mut b, \"...\", foo = bar, baz = quux"
struct ParsedMerge {
    target: Expr,
    datalog: String,
    parameters: HashMap<String, Expr>,
}

impl Parse for ParsedMerge {
    fn parse(input: ParseStream) -> parse::Result<Self> {
        let target = input.parse::<Expr>()?;
        let _: Token![,] = input.parse()?;

        let datalog = input.parse::<LitStr>()?.value();
        let parameters = input.parse::<ParsedParameters>()?;

        Ok(Self {
            target,
            datalog,
            parameters: parameters.parameters,
        })
    }
}

/// Create a `BlockBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
#[proc_macro]
#[proc_macro_error]
pub fn block(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Merge facts, rules, and checks into a `BlockBuilder` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
#[proc_macro]
#[proc_macro_error]
pub fn block_merge(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedMerge {
        target,
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedMerge);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, Some(target), datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Create an `Authorizer` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
#[proc_macro]
#[proc_macro_error]
pub fn authorizer(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    let ty = syn::parse_quote!(::biscuit_auth::builder::AuthorizerBuilder);
    let builder = Builder::source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Merge facts, rules, checks, and policies into an `Authorizer` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
#[proc_macro]
#[proc_macro_error]
pub fn authorizer_merge(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedMerge {
        target,
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedMerge);

    let ty = syn::parse_quote!(::biscuit_auth::builder::AuthorizerBuilder);
    let builder = Builder::source(ty, Some(target), datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Create an `BiscuitBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
#[proc_macro]
#[proc_macro_error]
pub fn biscuit(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BiscuitBuilder);
    let builder = Builder::block_source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

/// Merge facts, rules, and checks into a `BiscuitBuilder` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
#[proc_macro]
#[proc_macro_error]
pub fn biscuit_merge(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedMerge {
        target,
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedMerge);

    let ty = syn::parse_quote!(::biscuit_auth::builder::BiscuitBuilder);
    let builder = Builder::block_source(ty, Some(target), datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    builder.into_token_stream().into()
}

#[derive(Clone, Debug)]
struct Builder {
    pub builder_type: TypePath,
    pub target: Option<Expr>,
    pub parameters: HashMap<String, Expr>,

    // parameters used in the datalog source
    pub datalog_parameters: HashSet<String>,
    // scope parameters used in the datalog source
    pub datalog_scope_parameters: HashSet<String>,
    // parameters provided to the macro
    pub macro_parameters: HashSet<String>,

    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub checks: Vec<Check>,
    pub policies: Vec<Policy>,
}

impl Builder {
    fn new(
        builder_type: TypePath,
        target: Option<Expr>,
        parameters: HashMap<String, Expr>,
    ) -> Self {
        let macro_parameters = parameters.keys().cloned().collect();

        Self {
            builder_type,
            target,
            parameters,

            datalog_parameters: HashSet::new(),
            datalog_scope_parameters: HashSet::new(),
            macro_parameters,

            facts: Vec::new(),
            rules: Vec::new(),
            checks: Vec::new(),
            policies: Vec::new(),
        }
    }

    fn block_source<T: AsRef<str>>(
        builder_type: TypePath,
        target: Option<Expr>,
        source: T,
        parameters: HashMap<String, Expr>,
    ) -> Result<Builder, error::LanguageError> {
        let mut builder = Builder::new(builder_type, target, parameters);
        let source = parse_block_source(source.as_ref())?;

        builder.facts(source.facts.into_iter().map(|(_name, fact)| fact));
        builder.rules(source.rules.into_iter().map(|(_name, rule)| rule));
        builder.checks(source.checks.into_iter().map(|(_name, check)| check));

        builder.validate()?;
        Ok(builder)
    }

    fn source<T: AsRef<str>>(
        builder_type: TypePath,
        target: Option<Expr>,
        source: T,
        parameters: HashMap<String, Expr>,
    ) -> Result<Builder, error::LanguageError> {
        let mut builder = Builder::new(builder_type, target, parameters);
        let source = parse_source(source.as_ref())?;

        builder.facts(source.facts.into_iter().map(|(_name, fact)| fact));
        builder.rules(source.rules.into_iter().map(|(_name, rule)| rule));
        builder.checks(source.checks.into_iter().map(|(_name, check)| check));
        builder.policies(source.policies.into_iter().map(|(_name, policy)| policy));

        builder.validate()?;
        Ok(builder)
    }

    fn facts(&mut self, facts: impl Iterator<Item = Fact>) {
        for fact in facts {
            if let Some(parameters) = &fact.parameters {
                self.datalog_parameters.extend(parameters.keys().cloned());
            }
            self.facts.push(fact);
        }
    }

    fn rule_parameters(&mut self, rule: &Rule) {
        if let Some(parameters) = &rule.parameters {
            self.datalog_parameters.extend(parameters.keys().cloned());
        }

        if let Some(parameters) = &rule.scope_parameters {
            self.datalog_scope_parameters
                .extend(parameters.keys().cloned());
        }
    }

    fn rules(&mut self, rules: impl Iterator<Item = Rule>) {
        for rule in rules {
            self.rule_parameters(&rule);
            self.rules.push(rule);
        }
    }

    fn checks(&mut self, checks: impl Iterator<Item = Check>) {
        for check in checks {
            for rule in check.queries.iter() {
                self.rule_parameters(rule);
            }
            self.checks.push(check);
        }
    }

    fn policies(&mut self, policies: impl Iterator<Item = Policy>) {
        for policy in policies {
            for rule in policy.queries.iter() {
                self.rule_parameters(rule);
            }
            self.policies.push(policy);
        }
    }

    fn validate(&self) -> Result<(), error::LanguageError> {
        let all_parameters = self
            .datalog_parameters
            .union(&self.datalog_scope_parameters)
            .cloned()
            .collect();
        if self.macro_parameters.is_subset(&all_parameters) {
            Ok(())
        } else {
            let unused_parameters: Vec<String> = self
                .macro_parameters
                .difference(&all_parameters)
                .cloned()
                .collect();
            Err(error::LanguageError::Parameters {
                missing_parameters: Vec::new(),
                unused_parameters,
            })
        }
    }
}

struct Item {
    parameters: HashSet<String>,
    scope_parameters: HashSet<String>,
    start: TokenStream,
    middle: TokenStream,
    end: TokenStream,
}

impl Item {
    fn fact(fact: &Fact) -> Self {
        Self {
            parameters: fact
                .parameters
                .iter()
                .flatten()
                .map(|(name, _)| name.to_owned())
                .collect(),
            scope_parameters: HashSet::new(),
            start: quote! {
                let mut __biscuit_auth_item = #fact;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder = __biscuit_auth_builder.fact(__biscuit_auth_item).unwrap();
            },
        }
    }
    fn rule(rule: &Rule) -> Self {
        Self {
            parameters: Item::rule_params(rule).collect(),
            scope_parameters: Item::rule_scope_params(rule).collect(),
            start: quote! {
                let mut __biscuit_auth_item = #rule;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder = __biscuit_auth_builder.rule(__biscuit_auth_item).unwrap();
            },
        }
    }

    fn check(check: &Check) -> Self {
        Self {
            parameters: check.queries.iter().flat_map(Item::rule_params).collect(),
            scope_parameters: check
                .queries
                .iter()
                .flat_map(Item::rule_scope_params)
                .collect(),
            start: quote! {
                let mut __biscuit_auth_item = #check;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder =__biscuit_auth_builder.check(__biscuit_auth_item).unwrap();
            },
        }
    }

    fn policy(policy: &Policy) -> Self {
        Self {
            parameters: policy.queries.iter().flat_map(Item::rule_params).collect(),
            scope_parameters: policy
                .queries
                .iter()
                .flat_map(Item::rule_scope_params)
                .collect(),
            start: quote! {
                let mut __biscuit_auth_item = #policy;
            },
            middle: TokenStream::new(),
            end: quote! {
                __biscuit_auth_builder = __biscuit_auth_builder.policy(__biscuit_auth_item).unwrap();
            },
        }
    }

    fn rule_params(rule: &Rule) -> impl Iterator<Item = String> + '_ {
        rule.parameters
            .iter()
            .flatten()
            .map(|(name, _)| name.to_string())
    }

    fn rule_scope_params(rule: &Rule) -> impl Iterator<Item = String> + '_ {
        rule.scope_parameters
            .iter()
            .flatten()
            .map(|(name, _)| name.to_string())
    }

    fn needs_param(&self, name: &str) -> bool {
        self.parameters.contains(name)
    }
    fn needs_scope_param(&self, name: &str) -> bool {
        self.scope_parameters.contains(name)
    }

    fn add_param(&mut self, name: &str, clone: bool) {
        let ident = Ident::new(name, Span::call_site());

        let expr = if clone {
            quote! { ::core::clone::Clone::clone(&#ident) }
        } else {
            quote! { #ident }
        };

        self.middle.extend(quote! {
            __biscuit_auth_item.set_macro_param(#name, #expr).unwrap();
        });
    }

    fn add_scope_param(&mut self, name: &str, clone: bool) {
        let ident = Ident::new(name, Span::call_site());

        let expr = if clone {
            quote! { ::core::clone::Clone::clone(&#ident) }
        } else {
            quote! { #ident }
        };

        self.middle.extend(quote! {
            __biscuit_auth_item.set_macro_scope_param(#name, #expr).unwrap();
        });
    }
}

impl ToTokens for Item {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(self.start.clone());
        tokens.extend(self.middle.clone());
        tokens.extend(self.end.clone());
    }
}

impl ToTokens for Builder {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let params_quote = {
            let (ident, expr): (Vec<_>, Vec<_>) = self
                .parameters
                .iter()
                .map(|(name, expr)| {
                    let ident = Ident::new(name, Span::call_site());
                    (ident, expr)
                })
                .unzip();

            // Bind all parameters "in parallel". If this were a sequence of let bindings,
            // earlier bindings would affect the scope of later bindings.
            quote! {
                let (#(#ident),*) = (#(#expr),*);
            }
        };

        let mut items = self
            .facts
            .iter()
            .map(Item::fact)
            .chain(self.rules.iter().map(Item::rule))
            .chain(self.checks.iter().map(Item::check))
            .chain(self.policies.iter().map(Item::policy))
            .collect::<Vec<_>>();

        for param in &self.datalog_parameters {
            let mut items = items.iter_mut().filter(|i| i.needs_param(param)).peekable();

            loop {
                match (items.next(), items.peek()) {
                    (Some(cur), Some(_next)) => cur.add_param(param, true),
                    (Some(cur), None) => cur.add_param(param, false),
                    (None, _) => break,
                }
            }
        }

        for param in &self.datalog_scope_parameters {
            let mut items = items
                .iter_mut()
                .filter(|i| i.needs_scope_param(param))
                .peekable();

            loop {
                match (items.next(), items.peek()) {
                    (Some(cur), Some(_next)) => cur.add_scope_param(param, true),
                    (Some(cur), None) => cur.add_scope_param(param, false),
                    (None, _) => break,
                }
            }
        }

        let builder_type = &self.builder_type;
        let builder_quote = if let Some(target) = &self.target {
            quote! {
                let mut __biscuit_auth_builder: #builder_type = #target;
            }
        } else {
            quote! {
                let mut __biscuit_auth_builder = <#builder_type>::new();
            }
        };

        tokens.extend(quote! {
            {
                #builder_quote
                #params_quote
                #(#items)*
                __biscuit_auth_builder
            }
        });
    }
}

/// Create a `Rule` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
#[proc_macro]
#[proc_macro_error]
pub fn rule(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    // here we reuse the machinery made for managing parameter substitution
    // for whole blocks. Of course, we're only interested in a single rule
    // here. The block management happens only at compile-time, so it won't
    // affect runtime performance.
    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    let mut rule_item = if let Some(r) = builder.rules.first() {
        if builder.rules.len() == 1 && builder.facts.is_empty() && builder.checks.is_empty() {
            Item::rule(r)
        } else {
            abort_call_site!("The rule macro only accepts a single rule as input")
        }
    } else {
        abort_call_site!("The rule macro only accepts a single rule as input")
    };

    // here we are only interested in returning the rule, not adding it to a
    // builder, so we override the default behaviour and just return the rule
    // instead of calling `add_rule`
    rule_item.end = quote! {
      __biscuit_auth_item
    };

    let params_quote = {
        let (ident, expr): (Vec<_>, Vec<_>) = builder
            .parameters
            .iter()
            .map(|(name, expr)| {
                let ident = Ident::new(name, Span::call_site());
                (ident, expr)
            })
            .unzip();

        // Bind all parameters "in parallel". If this were a sequence of let bindings,
        // earlier bindings would affect the scope of later bindings.
        quote! {
            let (#(#ident),*) = (#(#expr),*);
        }
    };

    for param in &builder.datalog_parameters {
        if rule_item.needs_param(param) {
            rule_item.add_param(param, false);
        }
    }

    for param in &builder.datalog_scope_parameters {
        if rule_item.needs_scope_param(param) {
            rule_item.add_scope_param(param, false);
        }
    }

    (quote! {
        {
            #params_quote
            #rule_item
        }
    })
    .into()
}

/// Create a `Fact` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
#[proc_macro]
#[proc_macro_error]
pub fn fact(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    // here we reuse the machinery made for managing parameter substitution
    // for whole blocks. Of course, we're only interested in a single fact
    // here. The block management happens only at compile-time, so it won't
    // affect runtime performance.
    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    let mut fact_item = if let Some(f) = builder.facts.first() {
        if builder.facts.len() == 1 && builder.rules.is_empty() && builder.checks.is_empty() {
            Item::fact(f)
        } else {
            abort_call_site!("The fact macro only accepts a single fact as input")
        }
    } else {
        abort_call_site!("The fact macro only accepts a single fact as input")
    };

    // here we are only interested in returning the fact, not adding it to a
    // builder, so we override the default behaviour and just return the fact
    // instead of calling `add_fact`
    fact_item.end = quote! {
      __biscuit_auth_item
    };

    let params_quote = {
        let (ident, expr): (Vec<_>, Vec<_>) = builder
            .parameters
            .iter()
            .map(|(name, expr)| {
                let ident = Ident::new(name, Span::call_site());
                (ident, expr)
            })
            .unzip();

        // Bind all parameters "in parallel". If this were a sequence of let bindings,
        // earlier bindings would affect the scope of later bindings.
        quote! {
            let (#(#ident),*) = (#(#expr),*);
        }
    };

    for param in &builder.datalog_parameters {
        if fact_item.needs_param(param) {
            fact_item.add_param(param, false);
        }
    }

    (quote! {
        {
            #params_quote
            #fact_item
        }
    })
    .into()
}

/// Create a `Check` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
#[proc_macro]
#[proc_macro_error]
pub fn check(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    // here we reuse the machinery made for managing parameter substitution
    // for whole blocks. Of course, we're only interested in a single check
    // here. The block management happens only at compile-time, so it won't
    // affect runtime performance.
    let ty = syn::parse_quote!(::biscuit_auth::builder::BlockBuilder);
    let builder = Builder::block_source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    let mut check_item = if let Some(c) = builder.checks.first() {
        if builder.checks.len() == 1 && builder.facts.is_empty() && builder.rules.is_empty() {
            Item::check(c)
        } else {
            abort_call_site!("The check macro only accepts a single check as input")
        }
    } else {
        abort_call_site!("The check macro only accepts a single check as input")
    };

    // here we are only interested in returning the check, not adding it to a
    // builder, so we override the default behaviour and just return the check
    // instead of calling `add_check`
    check_item.end = quote! {
      __biscuit_auth_item
    };

    let params_quote = {
        let (ident, expr): (Vec<_>, Vec<_>) = builder
            .parameters
            .iter()
            .map(|(name, expr)| {
                let ident = Ident::new(name, Span::call_site());
                (ident, expr)
            })
            .unzip();

        // Bind all parameters "in parallel". If this were a sequence of let bindings,
        // earlier bindings would affect the scope of later bindings.
        quote! {
            let (#(#ident),*) = (#(#expr),*);
        }
    };

    for param in &builder.datalog_parameters {
        if check_item.needs_param(param) {
            check_item.add_param(param, false);
        }
    }

    for param in &builder.datalog_scope_parameters {
        if check_item.needs_scope_param(param) {
            check_item.add_scope_param(param, false);
        }
    }

    (quote! {
        {
            #params_quote
            #check_item
        }
    })
    .into()
}

/// Create a `Policy` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
#[proc_macro]
#[proc_macro_error]
pub fn policy(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ParsedCreateNew {
        datalog,
        parameters,
    } = syn::parse_macro_input!(input as ParsedCreateNew);

    // here we reuse the machinery made for managing parameter substitution
    // for whole blocks. Of course, we're only interested in a single policy
    // here. The block management happens only at compile-time, so it won't
    // affect runtime performance.
    let ty = syn::parse_quote!(::biscuit_auth::Authorizer);
    let builder = Builder::source(ty, None, datalog, parameters)
        .unwrap_or_else(|e| abort_call_site!(e.to_string()));

    let mut policy_item = if let Some(p) = builder.policies.first() {
        if builder.policies.len() == 1
            && builder.facts.is_empty()
            && builder.rules.is_empty()
            && builder.checks.is_empty()
        {
            Item::policy(p)
        } else {
            abort_call_site!("The policy macro only accepts a single policy as input")
        }
    } else {
        abort_call_site!("The policy macro only accepts a single policy as input")
    };

    // here we are only interested in returning the policy, not adding it to a
    // builder, so we override the default behaviour and just return the policy
    // instead of calling `add_policy`
    policy_item.end = quote! {
      __biscuit_auth_item
    };

    let params_quote = {
        let (ident, expr): (Vec<_>, Vec<_>) = builder
            .parameters
            .iter()
            .map(|(name, expr)| {
                let ident = Ident::new(name, Span::call_site());
                (ident, expr)
            })
            .unzip();

        // Bind all parameters "in parallel". If this were a sequence of let bindings,
        // earlier bindings would affect the scope of later bindings.
        quote! {
            let (#(#ident),*) = (#(#expr),*);
        }
    };

    for param in &builder.datalog_parameters {
        if policy_item.needs_param(param) {
            policy_item.add_param(param, false);
        }
    }

    for param in &builder.datalog_scope_parameters {
        if policy_item.needs_scope_param(param) {
            policy_item.add_scope_param(param, false);
        }
    }

    (quote! {
        {
            #params_quote
            #policy_item
        }
    })
    .into()
}
