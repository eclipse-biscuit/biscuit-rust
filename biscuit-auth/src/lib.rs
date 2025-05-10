/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Biscuit authentication and authorization token
//!
//! Biscuit is an authorization token for microservices architectures with the following properties:
//!
//! * decentralized validation: any node could validate the token only with public information;
//! * offline delegation: a new, valid token can be created from another one by attenuating its rights, by its holder, without communicating with anyone;
//! * capabilities based: authorization in microservices should be tied to rights related to the request, instead of relying to an identity that might not make sense to the authorizer;
//! * flexible rights managements: the token uses a logic language to specify attenuation and add bounds on ambient data;
//! * small enough to fit anywhere (cookies, etc).
//!
//! Non goals:
//!
//! * This is not a new authentication protocol. Biscuit tokens can be used as opaque tokens delivered by other systems such as OAuth.
//! * Revocation: while tokens come with expiration dates, revocation requires external state management.
//!
//! # Usage
//!
//! Most of the interaction with this library is done through the
//! [Biscuit](`crate::token::Biscuit`) structure, that represents a valid
//! token, and the [Authorizer](`crate::token::authorizer::Authorizer`), used to
//! check authorization policies on a token.
//!
//! In this example we will see how we can create a token, add some checks,
//! serialize and deserialize a token, append more checks, and validate
//! those checks in the context of a request:
//!
//! ```rust
//! extern crate biscuit_auth as biscuit;
//!
//! use biscuit::{KeyPair, Biscuit, Authorizer, builder::*, error, macros::*};
//!
//! fn main() -> Result<(), error::Token> {
//!   // let's generate the root key pair. The root public key will be necessary
//!   // to verify the token
//!   let root = KeyPair::new();
//!   let public_key = root.public();
//!
//!   // creating a first token
//!   let token1 = {
//!     // the first block of the token is the authority block. It contains global
//!     // information like which operation types are available
//!     let biscuit = biscuit!(r#"
//!           right("/a/file1.txt", "read");
//!           right("/a/file1.txt", "write");
//!           right("/a/file2.txt", "read");
//!           right("/b/file3.txt", "write");
//!     "#)
//!       .build(&root)?; // the first block is signed
//!
//!     println!("biscuit (authority): {}", biscuit);
//!
//!     biscuit.to_vec()?
//!   };
//!
//!   // this token is only 249 bytes, holding the authority data and the signature
//!   assert_eq!(token1.len(), 249);
//!
//!   // now let's add some restrictions to this token
//!   // we want to limit access to `/a/file1.txt` and to read operations
//!   let token2 = {
//!     // the token is deserialized, the signature is verified
//!     let deser = Biscuit::from(&token1,  root.public())?;
//!
//!     // biscuits can be attenuated by appending checks
//!     let biscuit = deser.append(block!(r#"
//!       // checks are implemented as logic rules. If the rule produces something,
//!       // the check is successful
//!       // here we verify the presence of a `resource` fact with a path set to "/a/file1.txt"
//!       // and a read operation
//!       check if resource("/a/file1.txt"), operation("read");
//!     "#))?;
//!
//!     println!("biscuit (authority): {}", biscuit);
//!
//!     biscuit.to_vec()?
//!   };
//!
//!   // this new token fits in 385 bytes
//!   assert_eq!(token2.len(), 385);
//!
//!   /************** VERIFICATION ****************/
//!
//!   // let's deserialize the token:
//!   let biscuit2 = Biscuit::from(&token2,  root.public())?;
//!
//!   // let's define 3 authorizers (corresponding to 3 different requests):
//!   // - one for /a/file1.txt and a read operation
//!   // - one for /a/file1.txt and a write operation
//!   // - one for /a/file2.txt and a read operation
//!
//!   let mut v1 = authorizer!(r#"
//!      resource("/a/file1.txt");
//!      operation("read");
//!      
//!      // a verifier can come with allow/deny policies. While checks are all tested
//!      // and must all succeeed, allow/deny policies are tried one by one in order,
//!      // and we stop verification on the first that matches
//!      //
//!      // here we will check that the token has the corresponding right
//!      allow if right("/a/file1.txt", "read");
//!      // explicit catch-all deny. here it is not necessary: if no policy
//!      // matches, a default deny applies
//!      deny if true;
//!   "#)
//!   .build(&biscuit2)?;
//!
//!   let mut v2 = authorizer!(r#"
//!      resource("/a/file1.txt");
//!      operation("write");
//!      allow if right("/a/file1.txt", "write");
//!   "#)
//!   .build(&biscuit2)?;
//!
//!   let mut v3 = authorizer!(r#"
//!      resource("/a/file2.txt");
//!      operation("read");
//!      allow if right("/a/file2.txt", "read");
//!   "#)
//!   .build(&biscuit2)?;
//!
//!   // the token restricts to read operations:
//!   assert!(v1.authorize().is_ok());
//!   // the second verifier requested a read operation
//!   assert!(v2.authorize().is_err());
//!   // the third verifier requests /a/file2.txt
//!   assert!(v3.authorize().is_err());
//!
//!   Ok(())
//! }
//! ```
//!
//! # Concepts
//!
//! ## Blocks
//!
//! A Biscuit token is made with a list of blocks defining data and checks that
//! must be validated upon reception with a request. Any failed check will invalidate
//! the entire token.
//!
//! If you hold a valid token, it is possible to add a new block to restrict further
//! the token, like limiting access to one particular resource, or adding a short
//! expiration date. This will generate a new, valid token. This can be done offline,
//! without asking the original token creator.
//!
//! On the other hand, if a block is modified or removed, the token will fail the
//! cryptographic signature verification.
//!
//! ## Cryptography
//!
//! Biscuit tokens get inspiration from macaroons and JSON Web Tokens, reproducing
//! useful features from both:
//!
//! - offline delegation like macaroons
//! - based on public key cryptography like JWT, so any application holding the root public key can verify a token (while macaroons are based on a root shared secret)
//!
//! Blocks are signed in a chain, starting with the root key, with each block signature
//! covering the block content, and the next block's public key.
//! Signatures can be generated either with Ed25519, or with ECDSA over P256.
//!
//! ## A logic language for authorization policies: Datalog with constraints
//!
//! We rely on a modified version of Datalog, that can represent complex behaviours
//! in a compact form, and add flexible constraints on data.
//!
//! Here are examples of checks that can be implemented with that language:
//!
//! - valid if the requested resource is "file.txt" and the operation is "read": `check if resource("file.txt"), operation("read")`
//! - valid if current time is before January 1st 2030, 00h00mn00s UTC: `check if time($0), $0 < 2030-01-01T00:00:00Z`
//! - source IP is in set [1.2.3.4, 5.6.7.8]: `check if ip($0), $0 in {"1.2.3.4", "5.6.7.8"}`
//! - resource matches prefix "/home/biscuit/data/": `check if resource($0), $0.starts_with("home/biscuit/data/")`
//!
//! But it can also combine into more complex patterns, like: we can read a resource
//! **if** the user has the read right, **or** the user is member of an organisation
//! and that organisation has the read right:
//!
//! ```
//! allow if right($0, "read");
//! allow if organisation($1), right($1, "read");
//! ```
//!
//! Like Datalog, this language is based around facts and rules, but with some
//! slight modifications: a block's rules and checks can only apply to facts
//! from the current or previous blocks. The authorizer executes its checks and
//! policies in the context of the first block. This allows Biscuit to carry
//! basic rights in the first block while preventing later blocks from
//! increasing the token's rights.
//!
//! ### Checks
//!
//! A check requires the presence of one or more facts, and can have additional
//! constraints on these facts (the constraints are implemented separately to simplify
//! the language implementation: among other things, it avoids implementing negation).
//! It is possible to create rules like these ones:
//!
//! - `check if resource("file1")`
//! - `check if resource($0), owner("user1", $0)` the $0 represents a "hole" that must be filled with the correct value
//! - `check if time($0), $0 < 2019-02-05T23:00:00Z` expiration date
//! - `check if application($0), operation($1), user($2), right(#app, $0, $1), owner($2, $0), credit($2, $3), $3 > 0` verifies that the user owns the applications, the application has the right on the operation, there's a credit information for the operation, and the credit is larger than 0
//!
//! It is also possible to refuse a request if a condition is met, using `reject`:
//! - `reject if resource("file1")`
//!
//! ### Allow/deny policies
//!
//! On the verification side, we can define *allow/deny policies*, which are tested
//! after all checks passed, one by one in order until one of them matches.
//!
//! * if an *allow* matches, verification succeeds
//! * if a *deny* matches, verification fails
//! * if there's no *allow* or *deny*, verification fails
//!
//! They can be written as follows:
//!
//! ```ignore
//! // verify that we have the right for this request
//! allow if
//!   resource($res),
//!   operation($op),
//!   right($res, $op);
//!
//! deny if true;
//! ```
//!
//! When processing the request, the authorizer will make sure that all checks succeeds
//! and none of the reject rules matches, otherwise it will retur an error with the list
//! of failures.
//!
//! Then it tries the allow/deny policis and will return the index of the policy that matched.
//!
//! ## Symbol table
//!
//! To reduce the size of tokens, the language uses string interning: strings are
//! serialized as an index in a list of strings. Any repetition of the string will
//! then use reduced space.
//!
//! They can be used for pretty printing of a fact or rule. As an example, with a table
//! containing `["resource", "operation", "read", "rule1", "file1.txt"]`, we could have the following rule:
//! `#3() <- #0(#4), #1(#2)` that would be printed as `rule1() <- resource("file.txt"), operation("read")`
//!
//! biscuit implementations come with a default symbol table to avoid transmitting
//! frequent values with every token.

mod crypto;
pub mod datalog;
pub mod error;
pub mod format;
pub mod parser;
mod token;

pub use crypto::{KeyPair, PrivateKey, PublicKey};
pub use token::authorizer::{Authorizer, AuthorizerLimits};
pub use token::builder;
pub use token::builder::{Algorithm, AuthorizerBuilder, BiscuitBuilder, BlockBuilder};
pub use token::builder_ext;
pub use token::unverified::UnverifiedBiscuit;
pub use token::Biscuit;
pub use token::RootKeyProvider;
pub use token::{ThirdPartyBlock, ThirdPartyRequest};

#[cfg(feature = "bwk")]
mod bwk;
#[cfg(feature = "bwk")]
pub use bwk::*;

mod time;

/// Procedural macros to construct Datalog policies
#[cfg(feature = "datalog-macro")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "datalog-macro")))]
pub mod macros;
