//! helper functions and structure to create tokens and blocks
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "datalog-macro")]
use quote::{quote, ToTokens};

/// Builder for a Datalog value
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Term {
    Variable(String),
    Integer(i64),
    Str(String),
    Date(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Set(BTreeSet<Term>),
    Parameter(String),
    Null,
    Array(Vec<Term>),
    Map(BTreeMap<MapKey, Term>),
}

impl Term {
    fn extract_parameters(&self, parameters: &mut HashMap<String, Option<Term>>) {
        match self {
            Term::Parameter(name) => {
                parameters.insert(name.to_string(), None);
            }
            Term::Set(s) => {
                for term in s {
                    term.extract_parameters(parameters);
                }
            }
            Term::Array(a) => {
                for term in a {
                    term.extract_parameters(parameters);
                }
            }
            Term::Map(m) => {
                for (key, term) in m {
                    if let MapKey::Parameter(name) = key {
                        parameters.insert(name.to_string(), None);
                    }
                    term.extract_parameters(parameters);
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MapKey {
    Parameter(String),
    Integer(i64),
    Str(String),
}

impl From<&Term> for Term {
    fn from(i: &Term) -> Self {
        match i {
            Term::Variable(ref v) => Term::Variable(v.clone()),
            Term::Integer(ref i) => Term::Integer(*i),
            Term::Str(ref s) => Term::Str(s.clone()),
            Term::Date(ref d) => Term::Date(*d),
            Term::Bytes(ref s) => Term::Bytes(s.clone()),
            Term::Bool(b) => Term::Bool(*b),
            Term::Set(ref s) => Term::Set(s.clone()),
            Term::Parameter(ref p) => Term::Parameter(p.clone()),
            Term::Null => Term::Null,
            Term::Array(ref a) => Term::Array(a.clone()),
            Term::Map(ref m) => Term::Map(m.clone()),
        }
    }
}

impl AsRef<Term> for Term {
    fn as_ref(&self) -> &Term {
        self
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Term {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Term::Variable(v) => quote! { ::biscuit_auth::builder::Term::Variable(#v.to_string()) },
            Term::Integer(v) => quote! { ::biscuit_auth::builder::Term::Integer(#v) },
            Term::Str(v) => quote! { ::biscuit_auth::builder::Term::Str(#v.to_string()) },
            Term::Date(v) => quote! { ::biscuit_auth::builder::Term::Date(#v) },
            Term::Bool(v) => quote! { ::biscuit_auth::builder::Term::Bool(#v) },
            Term::Parameter(v) => quote! { ::biscuit_auth::builder::Term::Parameter(#v.to_string()) },
            Term::Bytes(v) => quote! { ::biscuit_auth::builder::Term::Bytes(<[u8]>::into_vec(Box::new([ #(#v),*]))) },
            Term::Set(v) => {
                quote! {{
                    use std::iter::FromIterator;
                    ::biscuit_auth::builder::Term::Set(::std::collections::BTreeSet::from_iter(<[::biscuit_auth::builder::Term]>::into_vec(Box::new([ #(#v),*]))))
                }}
            }
            Term::Null => quote! { ::biscuit_auth::builder::Term::Null },
            Term::Array(v) => {
                quote! {{
                    use std::iter::FromIterator;
                    ::biscuit_auth::builder::Term::Array(::std::vec::Vec::from_iter(<[::biscuit_auth::builder::Term]>::into_vec( Box::new([ #(#v),*]))))
                }}
            }
            Term::Map(m) => {
                let  it = m.iter().map(|(key, term)| MapEntry {key, term });
                quote! {{
                    use std::iter::FromIterator;
                    ::biscuit_auth::builder::Term::Map(::std::collections::BTreeMap::from_iter(<[(::biscuit_auth::builder::MapKey,::biscuit_auth::builder::Term)]>::into_vec(Box::new([ #(#it),*]))))
                }}
            }
        })
    }
}

#[cfg(feature = "datalog-macro")]
struct MapEntry<'a> {
    key: &'a MapKey,
    term: &'a Term,
}

#[cfg(feature = "datalog-macro")]
impl<'a> ToTokens for MapEntry<'a> {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let term = self.term;
        tokens.extend(match self.key {
            MapKey::Parameter(p) => {
                quote! { (::biscuit_auth::builder::MapKey::Parameter(#p.to_string()) , #term )}
            }
            MapKey::Integer(i) => {
                quote! { (::biscuit_auth::builder::MapKey::Integer(#i) , #term )}
            }
            MapKey::Str(s) => {
                quote! { (::biscuit_auth::builder::MapKey::Str(#s.to_string()) , #term )}
            }
        });
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Scope {
    Authority,
    Previous,
    PublicKey(PublicKey),
    Parameter(String),
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Scope {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Scope::Authority => quote! { ::biscuit_auth::builder::Scope::Authority},
            Scope::Previous => quote! { ::biscuit_auth::builder::Scope::Previous},
            Scope::PublicKey(pk) => {
                let bytes = pk.key.iter();
                match pk.algorithm {
                    Algorithm::Ed25519 => quote! { ::biscuit_auth::builder::Scope::PublicKey(
                        ::biscuit_auth::PublicKey::from_bytes(&[#(#bytes),*], ::biscuit_auth::builder::Algorithm::Ed25519).unwrap()
                      )},
                    Algorithm::Secp256r1 => quote! { ::biscuit_auth::builder::Scope::PublicKey(
                        ::biscuit_auth::PublicKey::from_bytes(&[#(#bytes),*], ::biscuit_auth::builder::Algorithm::Secp256r1).unwrap()
                      )},
                }
            }
            Scope::Parameter(v) => {
                quote! { ::biscuit_auth::builder::Scope::Parameter(#v.to_string())}
            }
        })
    }
}

/// Builder for a Datalog dicate, used in facts and rules
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct Predicate {
    pub name: String,
    pub terms: Vec<Term>,
}

impl Predicate {
    pub fn new<T: Into<Vec<Term>>>(name: String, terms: T) -> Predicate {
        Predicate {
            name,
            terms: terms.into(),
        }
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Predicate {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = &self.name;
        let terms = self.terms.iter();
        tokens.extend(quote! {
            ::biscuit_auth::builder::Predicate::new(
              #name.to_string(),
              <[::biscuit_auth::builder::Term]>::into_vec(Box::new([#(#terms),*]))
            )
        })
    }
}

/// Builder for a Datalog fact
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub predicate: Predicate,
    pub parameters: Option<HashMap<String, Option<Term>>>,
}

impl Fact {
    pub fn new<T: Into<Vec<Term>>>(name: String, terms: T) -> Fact {
        let mut parameters = HashMap::new();
        let terms: Vec<Term> = terms.into();

        for term in &terms {
            term.extract_parameters(&mut parameters);
        }
        Fact {
            predicate: Predicate::new(name, terms),
            parameters: Some(parameters),
        }
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Fact {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let name = &self.predicate.name;
        let terms = self.predicate.terms.iter();
        tokens.extend(quote! {
            ::biscuit_auth::builder::Fact::new(
              #name.to_string(),
              <[::biscuit_auth::builder::Term]>::into_vec(Box::new([#(#terms),*]))
            )
        })
    }
}

/// Builder for a Datalog expression
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expression {
    pub ops: Vec<Op>,
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Expression {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let ops = self.ops.iter();
        tokens.extend(quote! {
          ::biscuit_auth::builder::Expression {
            ops: <[::biscuit_auth::builder::Op]>::into_vec(Box::new([#(#ops),*]))
          }
        });
    }
}

/// Builder for an expression operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Value(Term),
    Unary(Unary),
    Binary(Binary),
    Closure(Vec<String>, Vec<Op>),
}

impl Op {
    fn collect_parameters(&self, parameters: &mut HashMap<String, Option<Term>>) {
        match self {
            Op::Value(term) => {
                term.extract_parameters(parameters);
            }
            Op::Closure(_, ops) => {
                for op in ops {
                    op.collect_parameters(parameters);
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unary {
    Negate,
    Parens,
    Length,
    TypeOf,
    Ffi(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binary {
    LessThan,
    GreaterThan,
    LessOrEqual,
    GreaterOrEqual,
    Equal,
    Contains,
    Prefix,
    Suffix,
    Regex,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Intersection,
    Union,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    NotEqual,
    HeterogeneousEqual,
    HeterogeneousNotEqual,
    LazyAnd,
    LazyOr,
    All,
    Any,
    Get,
    Ffi(String),
    Try,
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Op {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Op::Value(t) => quote! { ::biscuit_auth::builder::Op::Value(#t) },
            Op::Unary(u) => quote! { ::biscuit_auth::builder::Op::Unary(#u) },
            Op::Binary(b) => quote! { ::biscuit_auth::builder::Op::Binary(#b) },
            Op::Closure(params, os) => quote! {
            ::biscuit_auth::builder::Op::Closure(
                    <[String]>::into_vec(Box::new([#(#params.to_string()),*])),
                    <[::biscuit_auth::builder::Op]>::into_vec(Box::new([#(#os),*]))
                    )
            },
        });
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Unary {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Unary::Negate => quote! {::biscuit_auth::builder::Unary::Negate },
            Unary::Parens => quote! {::biscuit_auth::builder::Unary::Parens },
            Unary::Length => quote! {::biscuit_auth::builder::Unary::Length },
            Unary::TypeOf => quote! {::biscuit_auth::builder::Unary::TypeOf },
            Unary::Ffi(name) => quote! {::biscuit_auth::builder::Unary::Ffi(#name.to_string()) },
        });
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Binary {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            Binary::LessThan => quote! { ::biscuit_auth::builder::Binary::LessThan  },
            Binary::GreaterThan => quote! { ::biscuit_auth::builder::Binary::GreaterThan  },
            Binary::LessOrEqual => quote! { ::biscuit_auth::builder::Binary::LessOrEqual  },
            Binary::GreaterOrEqual => quote! { ::biscuit_auth::builder::Binary::GreaterOrEqual  },
            Binary::Equal => quote! { ::biscuit_auth::builder::Binary::Equal  },
            Binary::Contains => quote! { ::biscuit_auth::builder::Binary::Contains  },
            Binary::Prefix => quote! { ::biscuit_auth::builder::Binary::Prefix  },
            Binary::Suffix => quote! { ::biscuit_auth::builder::Binary::Suffix  },
            Binary::Regex => quote! { ::biscuit_auth::builder::Binary::Regex  },
            Binary::Add => quote! { ::biscuit_auth::builder::Binary::Add  },
            Binary::Sub => quote! { ::biscuit_auth::builder::Binary::Sub  },
            Binary::Mul => quote! { ::biscuit_auth::builder::Binary::Mul  },
            Binary::Div => quote! { ::biscuit_auth::builder::Binary::Div  },
            Binary::And => quote! { ::biscuit_auth::builder::Binary::And  },
            Binary::Or => quote! { ::biscuit_auth::builder::Binary::Or  },
            Binary::Intersection => quote! { ::biscuit_auth::builder::Binary::Intersection  },
            Binary::Union => quote! { ::biscuit_auth::builder::Binary::Union  },
            Binary::BitwiseAnd => quote! { ::biscuit_auth::builder::Binary::BitwiseAnd  },
            Binary::BitwiseOr => quote! { ::biscuit_auth::builder::Binary::BitwiseOr  },
            Binary::BitwiseXor => quote! { ::biscuit_auth::builder::Binary::BitwiseXor  },
            Binary::NotEqual => quote! { ::biscuit_auth::builder::Binary::NotEqual },
            Binary::HeterogeneousEqual => {
                quote! { ::biscuit_auth::builder::Binary::HeterogeneousEqual}
            }
            Binary::HeterogeneousNotEqual => {
                quote! { ::biscuit_auth::builder::Binary::HeterogeneousNotEqual}
            }
            Binary::LazyAnd => quote! { ::biscuit_auth::builder::Binary::LazyAnd },
            Binary::LazyOr => quote! { ::biscuit_auth::builder::Binary::LazyOr },
            Binary::All => quote! { ::biscuit_auth::builder::Binary::All },
            Binary::Any => quote! { ::biscuit_auth::builder::Binary::Any },
            Binary::Get => quote! { ::biscuit_auth::builder::Binary::Get },
            Binary::Ffi(name) => quote! {::biscuit_auth::builder::Binary::Ffi(#name.to_string()) },
            Binary::Try => quote! { ::biscuit_auth::builder::Binary::Try },
        });
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicKey {
    pub key: Vec<u8>,
    pub algorithm: Algorithm,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    Secp256r1,
}

/// Builder for a Datalog rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub head: Predicate,
    pub body: Vec<Predicate>,
    pub expressions: Vec<Expression>,
    pub parameters: Option<HashMap<String, Option<Term>>>,
    pub scopes: Vec<Scope>,
    pub scope_parameters: Option<HashMap<String, Option<PublicKey>>>,
}

impl Rule {
    pub fn new(
        head: Predicate,
        body: Vec<Predicate>,
        expressions: Vec<Expression>,
        scopes: Vec<Scope>,
    ) -> Rule {
        let mut parameters = HashMap::new();
        let mut scope_parameters = HashMap::new();

        for term in &head.terms {
            term.extract_parameters(&mut parameters);
        }

        for predicate in &body {
            for term in &predicate.terms {
                term.extract_parameters(&mut parameters);
            }
        }

        for expression in &expressions {
            for op in &expression.ops {
                op.collect_parameters(&mut parameters);
            }
        }

        for scope in &scopes {
            if let Scope::Parameter(name) = &scope {
                scope_parameters.insert(name.to_string(), None);
            }
        }

        Rule {
            head,
            body,
            expressions,
            parameters: Some(parameters),
            scopes,
            scope_parameters: Some(scope_parameters),
        }
    }

    pub fn validate_variables(&self) -> Result<(), String> {
        let mut free_variables: HashSet<String> = HashSet::default();
        for term in self.head.terms.iter() {
            if let Term::Variable(s) = term {
                free_variables.insert(s.to_string());
            }
        }

        for e in self.expressions.iter() {
            for op in e.ops.iter() {
                if let Op::Value(Term::Variable(s)) = op {
                    free_variables.insert(s.to_string());
                }
            }
        }

        for predicate in self.body.iter() {
            for term in predicate.terms.iter() {
                if let Term::Variable(v) = term {
                    free_variables.remove(v);
                    if free_variables.is_empty() {
                        return Ok(());
                    }
                }
            }
        }

        if free_variables.is_empty() {
            Ok(())
        } else {
            Err(format!(
                    "the rule contains variables that are not bound by predicates in the rule's body: {}",
                    free_variables
                    .iter()
                    .map(|s| format!("${}", s))
                    .collect::<Vec<_>>()
                    .join(", ")
                    ))
        }
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Rule {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let head = &self.head;
        let body = self.body.iter();
        let expressions = self.expressions.iter();
        let scopes = self.scopes.iter();
        tokens.extend(quote! {
          ::biscuit_auth::builder::Rule::new(
            #head,
            <[::biscuit_auth::builder::Predicate]>::into_vec(Box::new([#(#body),*])),
            <[::biscuit_auth::builder::Expression]>::into_vec(Box::new([#(#expressions),*])),
            <[::biscuit_auth::builder::Scope]>::into_vec(Box::new([#(#scopes),*]))
          )
        });
    }
}

/// Builder for a Biscuit check
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub queries: Vec<Rule>,
    pub kind: CheckKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckKind {
    One,
    All,
    Reject,
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Check {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let queries = self.queries.iter();
        let kind = &self.kind;
        tokens.extend(quote! {
          ::biscuit_auth::builder::Check {
            queries: <[::biscuit_auth::builder::Rule]>::into_vec(Box::new([#(#queries),*])),
            kind: #kind,
          }
        });
    }
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for CheckKind {
    fn to_tokens(&self, tokens: &mut quote::__private::TokenStream) {
        tokens.extend(match self {
            CheckKind::One => quote! {
              ::biscuit_auth::builder::CheckKind::One
            },
            CheckKind::All => quote! {
              ::biscuit_auth::builder::CheckKind::All
            },
            CheckKind::Reject => quote! {
              ::biscuit_auth::builder::CheckKind::Reject
            },
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyKind {
    Allow,
    Deny,
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for PolicyKind {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        tokens.extend(match self {
            PolicyKind::Allow => quote! {
              ::biscuit_auth::builder::PolicyKind::Allow
            },
            PolicyKind::Deny => quote! {
              ::biscuit_auth::builder::PolicyKind::Deny
            },
        });
    }
}

/// Builder for a Biscuit policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub queries: Vec<Rule>,
    pub kind: PolicyKind,
}

#[cfg(feature = "datalog-macro")]
impl ToTokens for Policy {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let queries = self.queries.iter();
        let kind = &self.kind;
        tokens.extend(quote! {
          ::biscuit_auth::builder::Policy{
            kind: #kind,
            queries: <[::biscuit_auth::builder::Rule]>::into_vec(Box::new([#(#queries),*])),
          }
        });
    }
}

/// creates a new fact
pub fn fact<I: AsRef<Term>>(name: &str, terms: &[I]) -> Fact {
    let pred = pred(name, terms);
    Fact::new(pred.name, pred.terms)
}

/// creates a predicate
pub fn pred<I: AsRef<Term>>(name: &str, terms: &[I]) -> Predicate {
    Predicate {
        name: name.to_string(),
        terms: terms.iter().map(|term| term.as_ref().clone()).collect(),
    }
}

/// creates a rule
pub fn rule<T: AsRef<Term>>(head_name: &str, head_terms: &[T], predicates: &[Predicate]) -> Rule {
    Rule::new(
        pred(head_name, head_terms),
        predicates.to_vec(),
        Vec::new(),
        vec![],
    )
}

/// creates a rule with constraints
pub fn constrained_rule<T: AsRef<Term>>(
    head_name: &str,
    head_terms: &[T],
    predicates: &[Predicate],
    expressions: &[Expression],
) -> Rule {
    Rule::new(
        pred(head_name, head_terms),
        predicates.to_vec(),
        expressions.to_vec(),
        vec![],
    )
}

/// creates a check
pub fn check<P: AsRef<Predicate>>(predicates: &[P], kind: CheckKind) -> Check {
    let empty_terms: &[Term] = &[];
    Check {
        queries: vec![Rule::new(
            pred("query", empty_terms),
            predicates.iter().map(|p| p.as_ref().clone()).collect(),
            vec![],
            vec![],
        )],
        kind,
    }
}

/// creates an integer value
pub fn int(i: i64) -> Term {
    Term::Integer(i)
}

/// creates a string
pub fn string(s: &str) -> Term {
    Term::Str(s.to_string())
}

/// creates a date
///
/// internally the date will be stored as seconds since UNIX_EPOCH
pub fn date(t: &SystemTime) -> Term {
    let dur = t.duration_since(UNIX_EPOCH).unwrap();
    Term::Date(dur.as_secs())
}

/// creates a variable for a rule
pub fn var(s: &str) -> Term {
    Term::Variable(s.to_string())
}

/// creates a variable for a rule
pub fn variable(s: &str) -> Term {
    Term::Variable(s.to_string())
}

/// creates a byte array
pub fn bytes(s: &[u8]) -> Term {
    Term::Bytes(s.to_vec())
}

/// creates a boolean
pub fn boolean(b: bool) -> Term {
    Term::Bool(b)
}

/// creates a set
pub fn set(s: BTreeSet<Term>) -> Term {
    Term::Set(s)
}

/// creates a null
pub fn null() -> Term {
    Term::Null
}

/// creates an array
pub fn array(a: Vec<Term>) -> Term {
    Term::Array(a)
}

/// creates a map
pub fn map(m: BTreeMap<MapKey, Term>) -> Term {
    Term::Map(m)
}

/// creates a parameter
pub fn parameter(p: &str) -> Term {
    Term::Parameter(p.to_string())
}
