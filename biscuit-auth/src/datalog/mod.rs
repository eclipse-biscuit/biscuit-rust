/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Logic language implementation for checks
use crate::builder::{CheckKind, Convert};
use crate::error::Execution;
use crate::time::Instant;
use crate::token::{Scope, DATALOG_3_1, DATALOG_3_3, MIN_SCHEMA_VERSION};
use crate::{builder, error};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::AsRef;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod expression;
mod origin;
mod symbol;
pub use expression::*;
pub use origin::*;
pub use symbol::*;

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum Term {
    Variable(u32),
    Integer(i64),
    Str(SymbolIndex),
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Set(BTreeSet<Term>),
    Null,
    Array(Vec<Term>),
    Map(BTreeMap<MapKey, Term>),
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum MapKey {
    Integer(i64),
    Str(SymbolIndex),
}

impl From<&Term> for Term {
    fn from(i: &Term) -> Self {
        match i {
            Term::Variable(ref v) => Term::Variable(*v),
            Term::Integer(ref i) => Term::Integer(*i),
            Term::Str(ref s) => Term::Str(*s),
            Term::Date(ref d) => Term::Date(*d),
            Term::Bytes(ref b) => Term::Bytes(b.clone()),
            Term::Bool(ref b) => Term::Bool(*b),
            Term::Set(ref s) => Term::Set(s.clone()),
            Term::Null => Term::Null,
            Term::Array(ref a) => Term::Array(a.clone()),
            Term::Map(m) => Term::Map(m.clone()),
        }
    }
}

impl AsRef<Term> for Term {
    fn as_ref(&self) -> &Term {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct Predicate {
    pub name: SymbolIndex,
    pub terms: Vec<Term>,
}

impl Predicate {
    pub fn new(name: SymbolIndex, terms: &[Term]) -> Predicate {
        Predicate {
            name,
            terms: terms.to_vec(),
        }
    }
}

impl AsRef<Predicate> for Predicate {
    fn as_ref(&self) -> &Predicate {
        self
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fact {
    pub predicate: Predicate,
}

impl Fact {
    pub fn new(name: SymbolIndex, terms: &[Term]) -> Fact {
        Fact {
            predicate: Predicate::new(name, terms),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Rule {
    pub head: Predicate,
    pub body: Vec<Predicate>,
    pub expressions: Vec<Expression>,
    pub scopes: Vec<Scope>,
}

impl AsRef<Expression> for Expression {
    fn as_ref(&self) -> &Expression {
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub queries: Vec<Rule>,
    pub kind: CheckKind,
}

impl fmt::Display for Fact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({:?})", self.predicate.name, self.predicate.terms)
    }
}

impl Rule {
    /// gather all of the variables used in that rule
    fn variables_set(&self) -> HashSet<u32> {
        self.body
            .iter()
            .flat_map(|pred| {
                pred.terms.iter().filter_map(|id| match id {
                    Term::Variable(i) => Some(*i),
                    _ => None,
                })
            })
            .collect::<HashSet<_>>()
    }

    pub fn apply<'a, IT>(
        &'a self,
        facts: IT,
        rule_origin: usize,
        symbols: &'a SymbolTable,
        extern_funcs: &'a HashMap<String, ExternFunc>,
    ) -> impl Iterator<Item = Result<(Origin, Fact), error::Expression>> + 'a
    where
        IT: Iterator<Item = (&'a Origin, &'a Fact)> + Clone + 'a,
    {
        let head = self.head.clone();
        let variables = MatchedVariables::new(self.variables_set());

        CombineIt::new(variables, &self.body, facts, symbols)
        .map(move |(origin, variables)| {
                    let mut temporary_symbols = TemporarySymbolTable::new(symbols);
                    for e in self.expressions.iter() {
                        match e.evaluate(&variables, &mut temporary_symbols, extern_funcs) {
                            Ok(Term::Bool(true)) => {}
                            Ok(Term::Bool(false)) => return Ok((origin, variables, false)),
                            Ok(_) => return Err(error::Expression::InvalidType),
                            Err(e) => {
                                //println!("expr returned {:?}", res);
                                return Err(e);
                            }
                        }
                    }
            Ok((origin, variables, true))
        }).filter_map(move |res/*(mut origin,h, expression_res)*/| {
            match res {
                Ok((mut origin,h , expression_res)) => {
                    if expression_res {
                    let mut p = head.clone();
                    for index in 0..p.terms.len() {
                        match &p.terms[index] {
                            Term::Variable(i) => match h.get(i) {
                              Some(val) => p.terms[index] = val.clone(),
                              None => {
                                println!("error: variables that appear in the head should appear in the body and constraints as well");
                                return None;
                              }
                            },
                            _ => continue,
                        };
                    }

                    origin.insert(rule_origin);
                    Some(Ok((origin, Fact { predicate: p })))
                } else {None}
                },
                Err(e) => Some(Err(e))
            }

        })
    }

    pub fn find_match(
        &self,
        facts: &FactSet,
        origin: usize,
        scope: &TrustedOrigins,
        symbols: &SymbolTable,
        extern_funcs: &HashMap<String, ExternFunc>,
    ) -> Result<bool, Execution> {
        let fact_it = facts.iterator(scope);
        let mut it = self.apply(fact_it, origin, symbols, extern_funcs);

        let next = it.next();
        match next {
            None => Ok(false),
            Some(Ok(_)) => Ok(true),
            Some(Err(e)) => Err(Execution::Expression(e)),
        }
    }

    pub fn check_match_all(
        &self,
        facts: &FactSet,
        scope: &TrustedOrigins,
        symbols: &SymbolTable,
        extern_funcs: &HashMap<String, ExternFunc>,
    ) -> Result<bool, Execution> {
        let fact_it = facts.iterator(scope);
        let variables = MatchedVariables::new(self.variables_set());
        let mut found = false;

        for (_, variables) in CombineIt::new(variables, &self.body, fact_it, symbols) {
            found = true;

            let mut temporary_symbols = TemporarySymbolTable::new(symbols);
            for e in self.expressions.iter() {
                match e.evaluate(&variables, &mut temporary_symbols, extern_funcs) {
                    Ok(Term::Bool(true)) => {}
                    Ok(Term::Bool(false)) => {
                        //println!("expr returned {:?}", res);
                        return Ok(false);
                    }
                    Ok(_) => {
                        return Err(error::Execution::Expression(error::Expression::InvalidType))
                    }
                    Err(e) => {
                        return Err(error::Execution::Expression(e));
                    }
                }
            }
        }

        Ok(found)
    }

    // use this to translate rules and checks from token to authorizer world without translating
    // to a builder Rule first, because the builder Rule can contain a public key, so we would
    // need to loo up then retranslate that key, while the datalog rule does not need to know about
    // the key (the scope is driven by the authorizer's side)
    pub fn translate(
        &self,
        origin_symbols: &SymbolTable,
        target_symbols: &mut SymbolTable,
    ) -> Result<Self, error::Format> {
        Ok(Rule {
            head: builder::Predicate::convert_from(&self.head, origin_symbols)?
                .convert(target_symbols),
            body: self
                .body
                .iter()
                .map(|p| {
                    builder::Predicate::convert_from(p, origin_symbols)
                        .map(|p| p.convert(target_symbols))
                })
                .collect::<Result<Vec<_>, _>>()?,
            expressions: self
                .expressions
                .iter()
                .map(|c| {
                    builder::Expression::convert_from(c, origin_symbols)
                        .map(|e| e.convert(target_symbols))
                })
                .collect::<Result<Vec<_>, _>>()?,
            scopes: self
                .scopes
                .iter()
                .map(|s| {
                    builder::Scope::convert_from(s, origin_symbols)
                        .map(|s| s.convert(target_symbols))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn validate_variables(&self, symbols: &SymbolTable) -> Result<(), String> {
        let mut head_variables: std::collections::HashSet<u32> = self
            .head
            .terms
            .iter()
            .filter_map(|term| match term {
                Term::Variable(s) => Some(*s),
                _ => None,
            })
            .collect();

        for predicate in self.body.iter() {
            for term in predicate.terms.iter() {
                if let Term::Variable(v) = term {
                    head_variables.remove(v);
                    if head_variables.is_empty() {
                        return Ok(());
                    }
                }
            }
        }

        if head_variables.is_empty() {
            Ok(())
        } else {
            Err(format!(
                    "rule head contains variables that are not used in predicates of the rule's body: {}",
                    head_variables
                    .iter()
                    .map(|s| format!("${}", symbols.print_symbol_default(*s as u64)))
                    .collect::<Vec<_>>()
                    .join(", ")
                    ))
        }
    }
}

/// recursive iterator for rule application
#[allow(clippy::type_complexity)]
pub struct CombineIt<'a, IT> {
    variables: MatchedVariables,
    predicates: &'a [Predicate],
    all_facts: IT,
    symbols: &'a SymbolTable,
    current_facts: Box<dyn Iterator<Item = (&'a Origin, &'a Fact)> + 'a>,
    current_it: Option<Box<dyn Iterator<Item = (Origin, HashMap<u32, Term>)> + 'a>>,
}

impl<'a, IT> CombineIt<'a, IT>
where
    IT: Iterator<Item = (&'a Origin, &'a Fact)> + Clone + 'a,
{
    pub fn new(
        variables: MatchedVariables,
        predicates: &'a [Predicate],
        facts: IT,
        symbols: &'a SymbolTable,
    ) -> Self {
        let current_facts: Box<dyn Iterator<Item = (&'a Origin, &'a Fact)> + 'a> =
            if predicates.is_empty() {
                Box::new(facts.clone())
            } else {
                let p = predicates[0].clone();
                Box::new(
                    facts
                        .clone()
                        .filter(move |fact| match_preds(&p, &fact.1.predicate)),
                )
            };

        CombineIt {
            variables,
            predicates,
            all_facts: facts,
            symbols,
            current_facts,
            current_it: None,
        }
    }
}

impl<'a, IT> Iterator for CombineIt<'a, IT>
where
    IT: Iterator<Item = (&'a Origin, &'a Fact)> + Clone + 'a,
    Self: 'a,
{
    type Item = (Origin, HashMap<u32, Term>);

    fn next(&mut self) -> Option<(Origin, HashMap<u32, Term>)> {
        // if we're the last iterator in the recursive chain, stop here
        if self.predicates.is_empty() {
            match self.variables.complete() {
                None => return None,
                // we got a complete set of variables, let's test the expressions
                Some(variables) => {
                    // if there were no predicates and expressions evaluated to true,
                    // we should return a value, but only once. To prevent further
                    // successful calls, we create a set of variables that cannot
                    // possibly be completed, so the next call will fail
                    self.variables = MatchedVariables::new([0].into());
                    return Some((Origin::default(), variables));
                }
            }
        }

        loop {
            if self.current_it.is_none() {
                //fix the first predicate
                let pred = &self.predicates[0];

                loop {
                    if let Some((current_origin, current_fact)) = self.current_facts.next() {
                        // create a new MatchedVariables in which we fix variables we could unify
                        // from our first predicate and the current fact
                        let mut vars = self.variables.clone();
                        let mut match_terms = true;
                        for (key, id) in pred.terms.iter().zip(&current_fact.predicate.terms) {
                            if let (Term::Variable(k), id) = (key, id) {
                                if !vars.insert(*k, id) {
                                    match_terms = false;
                                }

                                if !match_terms {
                                    break;
                                }
                            }
                        }

                        if !match_terms {
                            continue;
                        }

                        if self.predicates.len() == 1 {
                            match vars.complete() {
                                None => {
                                    //println!("variables not complete, continue");
                                    continue;
                                }
                                // we got a complete set of variables, let's test the expressions
                                Some(variables) => {
                                    return Some((current_origin.clone(), variables));
                                }
                            }
                        } else {
                            // create a new iterator with the matched variables, the rest of the predicates,
                            // and all of the facts
                            self.current_it = Some(Box::new(
                                CombineIt::new(
                                    vars,
                                    &self.predicates[1..],
                                    self.all_facts.clone(),
                                    self.symbols,
                                )
                                .map(move |(origin, variables)| {
                                    (origin.union(current_origin), variables)
                                }),
                            ));
                        }
                        break;
                    } else {
                        return None;
                    }
                }
            }

            if self.current_it.is_none() {
                break None;
            }

            if let Some((origin, variables)) = self.current_it.as_mut().and_then(|it| it.next()) {
                break Some((origin, variables));
            } else {
                self.current_it = None;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedVariables {
    pub variables: HashMap<u32, Option<Term>>,
}

impl MatchedVariables {
    pub fn new(import: HashSet<u32>) -> Self {
        MatchedVariables {
            variables: import.iter().map(|key| (*key, None)).collect(),
        }
    }

    pub fn insert(&mut self, key: u32, value: &Term) -> bool {
        match self.variables.get(&key) {
            Some(None) => {
                self.variables.insert(key, Some(value.clone()));
                true
            }
            Some(Some(v)) => value == v,
            None => false,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.variables.values().all(|v| v.is_some())
    }

    pub fn complete(&self) -> Option<HashMap<u32, Term>> {
        let mut result = HashMap::new();
        for (k, v) in self.variables.iter() {
            match v {
                Some(value) => result.insert(*k, value.clone()),
                None => return None,
            };
        }
        Some(result)
    }
}

pub fn fact<I: AsRef<Term>>(name: SymbolIndex, terms: &[I]) -> Fact {
    Fact {
        predicate: Predicate {
            name,
            terms: terms.iter().map(|id| id.as_ref().clone()).collect(),
        },
    }
}

pub fn pred<I: AsRef<Term>>(name: SymbolIndex, terms: &[I]) -> Predicate {
    Predicate {
        name,
        terms: terms.iter().map(|id| id.as_ref().clone()).collect(),
    }
}

pub fn rule<I: AsRef<Term>, P: AsRef<Predicate>>(
    head_name: SymbolIndex,
    head_terms: &[I],
    predicates: &[P],
) -> Rule {
    Rule {
        head: pred(head_name, head_terms),
        body: predicates.iter().map(|p| p.as_ref().clone()).collect(),
        expressions: Vec::new(),
        scopes: vec![],
    }
}

pub fn expressed_rule<I: AsRef<Term>, P: AsRef<Predicate>, C: AsRef<Expression>>(
    head_name: SymbolIndex,
    head_terms: &[I],
    predicates: &[P],
    expressions: &[C],
) -> Rule {
    Rule {
        head: pred(head_name, head_terms),
        body: predicates.iter().map(|p| p.as_ref().clone()).collect(),
        expressions: expressions.iter().map(|c| c.as_ref().clone()).collect(),
        scopes: vec![],
    }
}

pub fn int(i: i64) -> Term {
    Term::Integer(i)
}

/*pub fn string(s: &str) -> Term {
    Term::Str(s.to_string())
}*/

pub fn date(t: &SystemTime) -> Term {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    Term::Date(dur.as_secs())
}

pub fn var(syms: &mut SymbolTable, name: &str) -> Term {
    let id = syms.insert(name);
    Term::Variable(id as u32)
}

pub fn match_preds(rule_pred: &Predicate, fact_pred: &Predicate) -> bool {
    rule_pred.name == fact_pred.name
        && rule_pred.terms.len() == fact_pred.terms.len()
        && rule_pred
            .terms
            .iter()
            .zip(&fact_pred.terms)
            .all(|(fid, pid)| match (fid, pid) {
                // the fact should not contain variables
                (_, Term::Variable(_)) => false,
                (Term::Variable(_), _) => true,
                (Term::Integer(i), Term::Integer(j)) => i == j,
                (Term::Str(i), Term::Str(j)) => i == j,
                (Term::Date(i), Term::Date(j)) => i == j,
                (Term::Bytes(i), Term::Bytes(j)) => i == j,
                (Term::Bool(i), Term::Bool(j)) => i == j,
                (Term::Null, Term::Null) => true,
                (Term::Set(i), Term::Set(j)) => i == j,
                (Term::Array(i), Term::Array(j)) => i == j,
                (Term::Map(i), Term::Map(j)) => i == j,
                _ => false,
            })
}

#[derive(Debug, Clone, Default)]
pub struct World {
    pub facts: FactSet,
    pub rules: RuleSet,
    pub iterations: u64,
    pub extern_funcs: HashMap<String, ExternFunc>,
}

impl World {
    pub fn new() -> Self {
        World::default()
    }

    pub fn add_fact(&mut self, origin: &Origin, fact: Fact) {
        self.facts.insert(origin, fact);
    }

    pub fn add_rule(&mut self, origin: usize, scope: &TrustedOrigins, rule: Rule) {
        self.rules.insert(origin, scope, rule);
    }

    pub fn run(&mut self, symbols: &SymbolTable) -> Result<(), crate::error::Execution> {
        self.run_with_limits(symbols, RunLimits::default())
    }

    pub fn run_with_limits(
        &mut self,
        symbols: &SymbolTable,
        limits: RunLimits,
    ) -> Result<(), crate::error::Execution> {
        let start = Instant::now();
        let time_limit = start + limits.max_time;
        let mut index = 0;

        let res = loop {
            let mut new_facts = FactSet::default();

            for (scope, rules) in self.rules.inner.iter() {
                let it = self.facts.iterator(scope);
                for (origin, rule) in rules {
                    for res in rule.apply(it.clone(), *origin, symbols, &self.extern_funcs) {
                        match res {
                            Ok((origin, fact)) => {
                                new_facts.insert(&origin, fact);
                            }
                            Err(e) => {
                                return Err(Execution::Expression(e));
                            }
                        }
                    }
                    //println!("new_facts after applying {:?}:\n{:#?}", rule, new_facts);
                }
            }

            let len = self.facts.len();
            self.facts.merge(new_facts);
            if self.facts.len() == len {
                break Ok(());
            }

            index += 1;
            if index == limits.max_iterations {
                break Err(Execution::RunLimit(
                    crate::error::RunLimit::TooManyIterations,
                ));
            }

            if self.facts.len() >= limits.max_facts as usize {
                break Err(Execution::RunLimit(crate::error::RunLimit::TooManyFacts));
            }

            let now = Instant::now();
            if now >= time_limit {
                break Err(Execution::RunLimit(crate::error::RunLimit::Timeout));
            }
        };

        self.iterations += index;

        res
    }

    /*pub fn query(&self, pred: Predicate) -> Vec<&Fact> {
        self.facts
            .iter()
            .filter(|f| {
                f.predicate.name == pred.name
                    && f.predicate.terms.iter().zip(&pred.terms).all(|(fid, pid)| {
                        match (fid, pid) {
                            //(Term::Symbol(_), Term::Variable(_)) => true,
                            //(Term::Symbol(i), Term::Symbol(ref j)) => i == j,
                            (_, Term::Variable(_)) => true,
                            (Term::Integer(i), Term::Integer(ref j)) => i == j,
                            (Term::Str(i), Term::Str(ref j)) => i == j,
                            (Term::Date(i), Term::Date(ref j)) => i == j,
                            (Term::Bytes(i), Term::Bytes(ref j)) => i == j,
                            (Term::Bool(i), Term::Bool(ref j)) => i == j,
                            (Term::Set(i), Term::Set(ref j)) => i == j,
                            _ => false,
                        }
                    })
            })
            .collect::<Vec<_>>()
    }*/

    pub fn query_rule(
        &self,
        rule: Rule,
        origin: usize,
        scope: &TrustedOrigins,
        symbols: &SymbolTable,
    ) -> Result<FactSet, Execution> {
        let mut new_facts = FactSet::default();
        let it = self.facts.iterator(scope);
        //new_facts.extend(rule.apply(it, origin, symbols));
        for res in rule.apply(it.clone(), origin, symbols, &self.extern_funcs) {
            match res {
                Ok((origin, fact)) => {
                    new_facts.insert(&origin, fact);
                }
                Err(e) => {
                    return Err(Execution::Expression(e));
                }
            }
        }

        Ok(new_facts)
    }

    pub fn query_match(
        &self,
        rule: Rule,
        origin: usize,
        scope: &TrustedOrigins,
        symbols: &SymbolTable,
    ) -> Result<bool, Execution> {
        rule.find_match(&self.facts, origin, scope, symbols, &self.extern_funcs)
    }

    pub fn query_match_all(
        &self,
        rule: Rule,
        scope: &TrustedOrigins,
        symbols: &SymbolTable,
    ) -> Result<bool, Execution> {
        rule.check_match_all(&self.facts, scope, symbols, &self.extern_funcs)
    }
}

/// runtime limits for the Datalog engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLimits {
    /// maximum number of Datalog facts (memory usage)
    pub max_facts: u64,
    /// maximum number of iterations of the rules applications (prevents degenerate rules)
    pub max_iterations: u64,
    /// maximum execution time
    pub max_time: Duration,
}

impl std::default::Default for RunLimits {
    fn default() -> Self {
        RunLimits {
            max_facts: 1000,
            max_iterations: 100,
            max_time: Duration::from_millis(1),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FactSet {
    pub(crate) inner: HashMap<Origin, HashSet<Fact>>,
}

impl FactSet {
    pub fn insert(&mut self, origin: &Origin, fact: Fact) {
        match self.inner.get_mut(origin) {
            None => {
                let mut set = HashSet::new();
                set.insert(fact);
                self.inner.insert(origin.clone(), set);
            }
            Some(set) => {
                set.insert(fact);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.values().fold(0, |acc, set| acc + set.len())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.values().all(|set| set.is_empty())
    }

    pub fn iterator<'a>(
        &'a self,
        block_ids: &'a TrustedOrigins,
    ) -> impl Iterator<Item = (&'a Origin, &'a Fact)> + Clone {
        self.inner
            .iter()
            .filter_map(move |(ids, facts)| {
                if block_ids.contains(ids) {
                    Some(facts.iter().map(move |fact| (ids, fact)))
                } else {
                    None
                }
            })
            .flatten()
    }

    pub fn iter_all(&self) -> impl Iterator<Item = (&Origin, &Fact)> + Clone {
        self.inner
            .iter()
            .flat_map(move |(ids, facts)| facts.iter().map(move |fact| (ids, fact)))
    }

    pub fn merge(&mut self, other: FactSet) {
        for (origin, facts) in other.inner {
            let entry = self.inner.entry(origin).or_default();
            entry.extend(facts.into_iter());
        }
    }
}

impl Extend<(Origin, Fact)> for FactSet {
    fn extend<T: IntoIterator<Item = (Origin, Fact)>>(&mut self, iter: T) {
        for (origin, fact) in iter {
            let entry = self.inner.entry(origin).or_default();
            entry.insert(fact);
        }
    }
}

impl IntoIterator for FactSet {
    type Item = (Origin, Fact);

    type IntoIter = Box<dyn Iterator<Item = (Origin, Fact)>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(
            self.inner.into_iter().flat_map(move |(ids, facts)| {
                facts.into_iter().map(move |fact| (ids.clone(), fact))
            }),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub inner: HashMap<TrustedOrigins, Vec<(usize, Rule)>>,
}

impl RuleSet {
    pub fn insert(&mut self, origin: usize, scope: &TrustedOrigins, rule: Rule) {
        match self.inner.get_mut(scope) {
            None => {
                self.inner.insert(scope.clone(), vec![(origin, rule)]);
            }
            Some(set) => {
                set.push((origin, rule));
            }
        }
    }

    pub fn iter_all(&self) -> impl Iterator<Item = (&TrustedOrigins, &Rule)> + Clone {
        self.inner
            .iter()
            .flat_map(move |(ids, rules)| rules.iter().map(move |(_, rule)| (ids, rule)))
    }
}

pub struct SchemaVersion {
    contains_scopes: bool,
    contains_v3_1: bool,
    contains_check_all: bool,
    contains_v3_3: bool,
}

impl SchemaVersion {
    pub fn version(&self) -> u32 {
        if self.contains_v3_3 {
            DATALOG_3_3
        } else if self.contains_scopes || self.contains_v3_1 || self.contains_check_all {
            DATALOG_3_1
        } else {
            MIN_SCHEMA_VERSION
        }
    }

    pub fn check_compatibility(&self, version: u32) -> Result<(), error::Format> {
        if version < DATALOG_3_1 {
            if self.contains_scopes {
                Err(error::Format::DeserializationError(
                    "scopes are only supported in datalog v3.1+".to_string(),
                ))
            } else if self.contains_v3_1 {
                Err(error::Format::DeserializationError(
                    "bitwise operators and != are only supported in datalog v3.1+".to_string(),
                ))
            } else if self.contains_check_all {
                Err(error::Format::DeserializationError(
                    "check all is only supported in datalog v3.1+".to_string(),
                ))
            } else {
                Ok(())
            }
        } else if version < DATALOG_3_3 && self.contains_v3_3 {
            Err(error::Format::DeserializationError(
                "maps, arrays, null, closures are only supported in datalog v3.3+".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Determine the schema version given the elements of a block.
pub fn get_schema_version(
    facts: &[Fact],
    rules: &[Rule],
    checks: &[Check],
    scopes: &[Scope],
) -> SchemaVersion {
    let contains_scopes = !scopes.is_empty()
        || rules.iter().any(|r: &Rule| !r.scopes.is_empty())
        || checks
            .iter()
            .any(|c: &Check| c.queries.iter().any(|q| !q.scopes.is_empty()));

    let mut contains_check_all = false;
    let mut contains_v3_3 = false;

    for c in checks.iter() {
        if c.kind == CheckKind::All {
            contains_check_all = true;
        } else if c.kind == CheckKind::Reject {
            contains_v3_3 = true;
        }
    }

    let contains_v3_1 = rules.iter().any(|rule| contains_v3_1_op(&rule.expressions))
        || checks.iter().any(|check| {
            check
                .queries
                .iter()
                .any(|query| contains_v3_1_op(&query.expressions))
        });

    // null, heterogeneous equals, closures
    if !contains_v3_3 {
        contains_v3_3 = rules.iter().any(|rule| {
            contains_v3_3_predicate(&rule.head)
                || rule.body.iter().any(contains_v3_3_predicate)
                || contains_v3_3_op(&rule.expressions)
        }) || checks.iter().any(|check| {
            check.queries.iter().any(|query| {
                query.body.iter().any(contains_v3_3_predicate)
                    || contains_v3_3_op(&query.expressions)
            })
        });
    }
    if !contains_v3_3 {
        contains_v3_3 = facts
            .iter()
            .any(|fact| contains_v3_3_predicate(&fact.predicate))
    }

    SchemaVersion {
        contains_scopes,
        contains_v3_1,
        contains_check_all,
        contains_v3_3,
    }
}

/// Determine whether any of the expression contain a v3.1 operator.
/// Bitwise operators and != are only supported in biscuits v3.1+
pub fn contains_v3_1_op(expressions: &[Expression]) -> bool {
    expressions.iter().any(|expression| {
        expression.ops.iter().any(|op| {
            if let Op::Binary(binary) = op {
                match binary {
                    Binary::BitwiseAnd
                    | Binary::BitwiseOr
                    | Binary::BitwiseXor
                    | Binary::NotEqual => return true,
                    _ => return false,
                }
            }
            false
        })
    })
}

fn contains_v3_3_op(expressions: &[Expression]) -> bool {
    expressions.iter().any(|expression| {
        expression.ops.iter().any(|op| match op {
            Op::Value(term) => contains_v3_3_term(term),
            Op::Closure(_, _) => true,
            Op::Unary(unary) => matches!(unary, Unary::TypeOf | Unary::Ffi(_)),
            Op::Binary(binary) => matches!(
                binary,
                Binary::HeterogeneousEqual
                    | Binary::HeterogeneousNotEqual
                    | Binary::LazyAnd
                    | Binary::LazyOr
                    | Binary::All
                    | Binary::Any
                    | Binary::Ffi(_)
            ),
        })
    })
}

fn contains_v3_3_predicate(predicate: &Predicate) -> bool {
    predicate.terms.iter().any(contains_v3_3_term)
}

fn contains_v3_3_term(term: &Term) -> bool {
    match term {
        Term::Null => true,
        Term::Set(s) => s.contains(&Term::Null),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn family() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let a = syms.add("A");
        let b = syms.add("B");
        let c = syms.add("C");
        let d = syms.add("D");
        let e = syms.add("e");
        let parent = syms.insert("parent");
        let grandparent = syms.insert("grandparent");

        w.add_fact(&[0].iter().collect(), fact(parent, &[&a, &b]));
        w.add_fact(&[0].iter().collect(), fact(parent, &[&b, &c]));
        w.add_fact(&[0].iter().collect(), fact(parent, &[&c, &d]));

        let r1 = rule(
            grandparent,
            &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
            &[
                pred(
                    parent,
                    &[var(&mut syms, "grandparent"), var(&mut syms, "parent")],
                ),
                pred(
                    parent,
                    &[var(&mut syms, "parent"), var(&mut syms, "grandchild")],
                ),
            ],
        );

        println!("symbols: {syms:?}");
        println!("testing r1: {}", syms.print_rule(&r1));
        let query_rule_result = w.query_rule(r1, 0, &[0].iter().collect(), &syms);
        println!("grandparents query_rules: {query_rule_result:?}");
        println!("current facts: {:?}", w.facts);

        let r2 = rule(
            grandparent,
            &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
            &[
                pred(
                    parent,
                    &[var(&mut syms, "grandparent"), var(&mut syms, "parent")],
                ),
                pred(
                    parent,
                    &[var(&mut syms, "parent"), var(&mut syms, "grandchild")],
                ),
            ],
        );

        println!("adding r2: {}", syms.print_rule(&r2));
        w.add_rule(0, &[0].iter().collect(), r2);

        w.run_with_limits(
            &syms,
            RunLimits {
                max_time: Duration::from_secs(10),
                ..Default::default()
            },
        )
        .unwrap();

        println!("parents:");
        let res = w
            .query_rule(
                rule::<Term, Predicate>(
                    parent,
                    &[var(&mut syms, "parent"), var(&mut syms, "child")],
                    &[pred(
                        parent,
                        &[var(&mut syms, "parent"), var(&mut syms, "child")],
                    )],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (origin, fact) in res.iterator(&[0].iter().collect()) {
            println!("\t{:?}\t{}", origin, syms.print_fact(fact));
        }

        println!(
            "parents of B: {:?}",
            w.query_rule(
                rule::<&Term, Predicate>(
                    parent,
                    &[&var(&mut syms, "parent"), &b],
                    &[pred(parent, &[&var(&mut syms, "parent"), &b])]
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
        );
        println!(
            "grandparents: {:?}",
            w.query_rule(
                rule::<Term, Predicate>(
                    grandparent,
                    &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
                    &[pred(
                        grandparent,
                        &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")]
                    )]
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
        );
        w.add_fact(&[0].iter().collect(), fact(parent, &[&c, &e]));
        w.run(&syms).unwrap();
        let res = w
            .query_rule(
                rule::<Term, Predicate>(
                    grandparent,
                    &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
                    &[pred(
                        grandparent,
                        &[var(&mut syms, "grandparent"), var(&mut syms, "grandchild")],
                    )],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();
        println!("grandparents after inserting parent(C, E): {res:?}");

        let res = res
            .iter_all()
            .map(|(_origin, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![
            fact(grandparent, &[&a, &c]),
            fact(grandparent, &[&b, &d]),
            fact(grandparent, &[&b, &e]),
        ])
        .drain(..)
        .collect::<HashSet<_>>();
        assert_eq!(res, compared);

        /*w.add_rule(rule("siblings", &[var("A"), var("B")], &[
          pred(parent, &[var(parent), var("A")]),
          pred(parent, &[var(parent), var("B")])
        ]));

        w.run();
        println!("siblings: {:#?}", w.query(pred("siblings", &[var("A"), var("B")])));
        */
    }

    #[test]
    fn numbers() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let ghi = syms.add("ghi");
        let jkl = syms.add("jkl");
        let mno = syms.add("mno");
        let aaa = syms.add("AAA");
        let bbb = syms.add("BBB");
        let ccc = syms.add("CCC");
        let t1 = syms.insert("t1");
        let t2 = syms.insert("t2");
        let join = syms.insert("join");

        w.add_fact(&[0].iter().collect(), fact(t1, &[&int(0), &abc]));
        w.add_fact(&[0].iter().collect(), fact(t1, &[&int(1), &def]));
        w.add_fact(&[0].iter().collect(), fact(t1, &[&int(2), &ghi]));
        w.add_fact(&[0].iter().collect(), fact(t1, &[&int(3), &jkl]));
        w.add_fact(&[0].iter().collect(), fact(t1, &[&int(4), &mno]));

        w.add_fact(&[0].iter().collect(), fact(t2, &[&int(0), &aaa, &int(0)]));
        w.add_fact(&[0].iter().collect(), fact(t2, &[&int(1), &bbb, &int(0)]));
        w.add_fact(&[0].iter().collect(), fact(t2, &[&int(2), &ccc, &int(1)]));

        let res = w
            .query_rule(
                rule(
                    join,
                    &[var(&mut syms, "left"), var(&mut syms, "right")],
                    &[
                        pred(t1, &[var(&mut syms, "id"), var(&mut syms, "left")]),
                        pred(
                            t2,
                            &[
                                var(&mut syms, "t2_id"),
                                var(&mut syms, "right"),
                                var(&mut syms, "id"),
                            ],
                        ),
                    ],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_origin, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![
            fact(join, &[&abc, &aaa]),
            fact(join, &[&abc, &bbb]),
            fact(join, &[&def, &ccc]),
        ])
        .drain(..)
        .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        // test constraints
        let res = w
            .query_rule(
                expressed_rule(
                    join,
                    &[var(&mut syms, "left"), var(&mut syms, "right")],
                    &[
                        pred(t1, &[var(&mut syms, "id"), var(&mut syms, "left")]),
                        pred(
                            t2,
                            &[
                                var(&mut syms, "t2_id"),
                                var(&mut syms, "right"),
                                var(&mut syms, "id"),
                            ],
                        ),
                    ],
                    &[Expression {
                        ops: vec![
                            Op::Value(var(&mut syms, "id")),
                            Op::Value(Term::Integer(1)),
                            Op::Binary(Binary::LessThan),
                        ],
                    }],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_origin, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![fact(join, &[&abc, &aaa]), fact(join, &[&abc, &bbb])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn str() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let app_0 = syms.add("app_0");
        let app_1 = syms.add("app_1");
        let app_2 = syms.add("app_2");
        let route = syms.insert("route");
        let suff = syms.insert("route suffix");
        let example = syms.add("example.com");
        let test_com = syms.add("test.com");
        let test_fr = syms.add("test.fr");
        let www_example = syms.add("www.example.com");
        let mx_example = syms.add("mx.example.com");

        w.add_fact(
            &[0].iter().collect(),
            fact(route, &[&int(0), &app_0, &example]),
        );
        w.add_fact(
            &[0].iter().collect(),
            fact(route, &[&int(1), &app_1, &test_com]),
        );
        w.add_fact(
            &[0].iter().collect(),
            fact(route, &[&int(2), &app_2, &test_fr]),
        );
        w.add_fact(
            &[0].iter().collect(),
            fact(route, &[&int(3), &app_0, &www_example]),
        );
        w.add_fact(
            &[0].iter().collect(),
            fact(route, &[&int(4), &app_1, &mx_example]),
        );

        fn test_suffix(
            w: &World,
            syms: &mut SymbolTable,
            suff: SymbolIndex,
            route: SymbolIndex,
            suffix: &str,
        ) -> Vec<Fact> {
            let id_suff = syms.add(suffix);
            w.query_rule(
                expressed_rule(
                    suff,
                    &[var(syms, "app_id"), var(syms, "domain_name")],
                    &[pred(
                        route,
                        &[
                            var(syms, "route_id"),
                            var(syms, "app_id"),
                            var(syms, "domain_name"),
                        ],
                    )],
                    &[Expression {
                        ops: vec![
                            Op::Value(var(syms, "domain_name")),
                            Op::Value(id_suff),
                            Op::Binary(Binary::Suffix),
                        ],
                    }],
                ),
                0,
                &[0].iter().collect(),
                syms,
            )
            .unwrap()
            .iter_all()
            .map(|(_, fact)| fact.clone())
            .collect()
        }

        let res = test_suffix(&w, &mut syms, suff, route, ".fr");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![fact(suff, &[&app_2, &test_fr])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let res = test_suffix(&w, &mut syms, suff, route, "example.com");
        for fact in &res {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res.iter().cloned().collect::<HashSet<_>>();
        let compared = (vec![
            fact(suff, &[&app_0, &example]),
            fact(suff, &[&app_0, &www_example]),
            fact(suff, &[&app_1, &mx_example]),
        ])
        .drain(..)
        .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn date_constraint() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let t1 = SystemTime::now();
        println!("t1 = {t1:?}");
        let t2 = t1 + Duration::from_secs(10);
        println!("t2 = {t2:?}");
        let t3 = t2 + Duration::from_secs(30);
        println!("t3 = {t3:?}");

        let t2_timestamp = t2.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let x = syms.insert("x");
        let before = syms.insert("before");
        let after = syms.insert("after");

        w.add_fact(&[0].iter().collect(), fact(x, &[&date(&t1), &abc]));
        w.add_fact(&[0].iter().collect(), fact(x, &[&date(&t3), &def]));

        let r1 = expressed_rule(
            before,
            &[var(&mut syms, "date"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "date"), var(&mut syms, "val")])],
            &[
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(Term::Date(t2_timestamp)),
                        Op::Binary(Binary::LessOrEqual),
                    ],
                },
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(Term::Date(0)),
                        Op::Binary(Binary::GreaterOrEqual),
                    ],
                },
            ],
        );

        println!("testing r1: {}", syms.print_rule(&r1));
        let res = w.query_rule(r1, 0, &[0].iter().collect(), &syms).unwrap();
        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_origin, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![fact(before, &[&date(&t1), &abc])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let r2 = expressed_rule(
            after,
            &[var(&mut syms, "date"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "date"), var(&mut syms, "val")])],
            &[
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(Term::Date(t2_timestamp)),
                        Op::Binary(Binary::GreaterOrEqual),
                    ],
                },
                Expression {
                    ops: vec![
                        Op::Value(var(&mut syms, "date")),
                        Op::Value(Term::Date(0)),
                        Op::Binary(Binary::GreaterOrEqual),
                    ],
                },
            ],
        );

        println!("testing r2: {}", syms.print_rule(&r2));
        let res = w.query_rule(r2, 0, &[0].iter().collect(), &syms).unwrap();
        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![fact(after, &[&date(&t3), &def])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn set_constraint() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let x = syms.insert("x");
        let int_set = syms.insert("int_set");
        let symbol_set = syms.insert("symbol_set");
        let string_set = syms.insert("string_set");
        let test = syms.add("test");
        let hello = syms.add("hello");
        let aaa = syms.add("zzz");

        w.add_fact(&[0].iter().collect(), fact(x, &[&abc, &int(0), &test]));
        w.add_fact(&[0].iter().collect(), fact(x, &[&def, &int(2), &hello]));

        let res = w
            .query_rule(
                expressed_rule(
                    int_set,
                    &[var(&mut syms, "sym"), var(&mut syms, "str")],
                    &[pred(
                        x,
                        &[
                            var(&mut syms, "sym"),
                            var(&mut syms, "int"),
                            var(&mut syms, "str"),
                        ],
                    )],
                    &[Expression {
                        ops: vec![
                            Op::Value(Term::Set(
                                [Term::Integer(0), Term::Integer(1)]
                                    .iter()
                                    .cloned()
                                    .collect(),
                            )),
                            Op::Value(var(&mut syms, "int")),
                            Op::Binary(Binary::Contains),
                        ],
                    }],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![fact(int_set, &[&abc, &test])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let abc_sym_id = syms.add("abc");
        let ghi_sym_id = syms.add("ghi");

        let res = w
            .query_rule(
                expressed_rule(
                    symbol_set,
                    &[
                        var(&mut syms, "symbol"),
                        var(&mut syms, "int"),
                        var(&mut syms, "str"),
                    ],
                    &[pred(
                        x,
                        &[
                            var(&mut syms, "symbol"),
                            var(&mut syms, "int"),
                            var(&mut syms, "str"),
                        ],
                    )],
                    &[Expression {
                        ops: vec![
                            Op::Value(Term::Set(
                                [abc_sym_id, ghi_sym_id].iter().cloned().collect(),
                            )),
                            Op::Value(var(&mut syms, "symbol")),
                            Op::Binary(Binary::Contains),
                            Op::Unary(Unary::Negate),
                        ],
                    }],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![fact(symbol_set, &[&def, &int(2), &hello])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);

        let res = w
            .query_rule(
                expressed_rule(
                    string_set,
                    &[
                        var(&mut syms, "sym"),
                        var(&mut syms, "int"),
                        var(&mut syms, "str"),
                    ],
                    &[pred(
                        x,
                        &[
                            var(&mut syms, "sym"),
                            var(&mut syms, "int"),
                            var(&mut syms, "str"),
                        ],
                    )],
                    &[Expression {
                        ops: vec![
                            Op::Value(Term::Set([test.clone(), aaa].iter().cloned().collect())),
                            Op::Value(var(&mut syms, "str")),
                            Op::Binary(Binary::Contains),
                        ],
                    }],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        let compared = (vec![fact(string_set, &[&abc, &int(0), &test])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn resource() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let resource = syms.insert("resource");
        let operation = syms.insert("operation");
        let right = syms.insert("right");
        let file1 = syms.add("file1");
        let file2 = syms.add("file2");
        let read = syms.add("read");
        let write = syms.add("write");
        let check1 = syms.insert("check1");
        let check2 = syms.insert("check2");

        w.add_fact(&[0].iter().collect(), fact(resource, &[&file2]));
        w.add_fact(&[0].iter().collect(), fact(operation, &[&write]));
        w.add_fact(&[0].iter().collect(), fact(right, &[&file1, &read]));
        w.add_fact(&[0].iter().collect(), fact(right, &[&file2, &read]));
        w.add_fact(&[0].iter().collect(), fact(right, &[&file1, &write]));

        let res = w
            .query_rule(
                rule(check1, &[&file1], &[pred(resource, &[&file1])]),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());

        let res = w
            .query_rule(
                rule(
                    check2,
                    &[Term::Variable(0)],
                    &[
                        pred(resource, &[&Term::Variable(0)]),
                        pred(operation, &[&read]),
                        pred(right, &[&Term::Variable(0), &read]),
                    ],
                ),
                0,
                &[0].iter().collect(),
                &syms,
            )
            .unwrap();

        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());
    }

    #[test]
    fn int_expr() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let abc = syms.add("abc");
        let def = syms.add("def");
        let x = syms.insert("x");
        let less_than = syms.insert("less_than");

        w.add_fact(&[0].iter().collect(), fact(x, &[&int(-2), &abc]));
        w.add_fact(&[0].iter().collect(), fact(x, &[&int(0), &def]));

        let r1 = expressed_rule(
            less_than,
            &[var(&mut syms, "nb"), var(&mut syms, "val")],
            &[pred(x, &[var(&mut syms, "nb"), var(&mut syms, "val")])],
            &[Expression {
                ops: vec![
                    Op::Value(Term::Integer(5)),
                    Op::Value(Term::Integer(-4)),
                    Op::Binary(Binary::Add),
                    Op::Value(Term::Integer(-1)),
                    Op::Binary(Binary::Mul),
                    Op::Value(var(&mut syms, "nb")),
                    Op::Binary(Binary::LessThan),
                ],
            }],
        );

        println!("world:\n{}\n", syms.print_world(&w));
        println!("\ntesting r1: {}\n", syms.print_rule(&r1));
        let res = w.query_rule(r1, 0, &[0].iter().collect(), &syms).unwrap();
        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        let res2 = res
            .iter_all()
            .map(|(_, fact)| fact)
            .cloned()
            .collect::<HashSet<_>>();
        println!("got res: {res2:?}");
        let compared = (vec![fact(less_than, &[&int(0), &def])])
            .drain(..)
            .collect::<HashSet<_>>();
        assert_eq!(res2, compared);
    }

    #[test]
    fn unbound_variables() {
        let mut w = World::new();
        let mut syms = SymbolTable::new();

        let operation = syms.insert("operation");
        let check = syms.insert("check");
        let read = syms.add("read");
        let write = syms.add("write");
        let unbound = var(&mut syms, "unbound");
        let any1 = var(&mut syms, "any1");
        let any2 = var(&mut syms, "any2");

        w.add_fact(&[0].iter().collect(), fact(operation, &[&write]));

        let r1 = rule(
            operation,
            &[&unbound, &read],
            &[pred(operation, &[&any1, &any2])],
        );
        println!("world:\n{}\n", syms.print_world(&w));
        println!("\ntesting r1: {}\n", syms.print_rule(&r1));
        let res = w.query_rule(r1, 0, &[0].iter().collect(), &syms).unwrap();

        println!("generated facts:");
        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }

        assert!(res.is_empty());

        // operation($unbound, "read") should not have been generated
        // in case it is generated though, verify that rule application
        // will not match it
        w.add_fact(&[0].iter().collect(), fact(operation, &[&unbound, &read]));
        let r2 = rule(check, &[&read], &[pred(operation, &[&read])]);
        println!("world:\n{}\n", syms.print_world(&w));
        println!("\ntesting r2: {}\n", syms.print_rule(&r2));
        let res = w.query_rule(r2, 0, &[0].iter().collect(), &syms).unwrap();

        println!("generated facts:");
        for (_, fact) in res.iter_all() {
            println!("\t{}", syms.print_fact(fact));
        }
        assert!(res.is_empty());
    }
}
