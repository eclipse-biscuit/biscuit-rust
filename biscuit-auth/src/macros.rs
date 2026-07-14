/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Procedural macros to create tokens and authorizers
//!
//! ```rust
//! use biscuit_auth::PrivateKey;
//! use biscuit_auth::macros::{authorizer, biscuit, block};
//! use std::time::{Duration, SystemTime};
//!
//! let root = PrivateKey::new();
//!
//! let user_id = "1234";
//! let biscuit = biscuit!(
//!   r#"
//!   // you can directly reference in-scope variables
//!   user({user_id});
//!   right({user_id}, "file1", {operation});
//!   "#,
//!   // you can also declare bindings manually
//!   operation = "read",
//! ).build(&root).expect("Failed to create biscuit");
//!
//! let new_biscuit = biscuit.append(block!(
//!   r#"
//!     check if time($time), $time < {expiration};
//!   "#,
//!   expiration = SystemTime::now() + Duration::from_secs(86_400),
//! )).expect("Failed to append block");
//!
//! authorizer!(
//!   r#"
//!      time({now});
//!      operation({operation});
//!      resource({resource});
//!
//!      is_allowed($user_id) <- right($user_id, $resource, $operation),
//!                              resource($resource),
//!                              operation($operation);
//!
//!      allow if is_allowed({user_id});
//!   "#,
//!   now = SystemTime::now(),
//!   operation = "read",
//!   resource = "file1",
//!   user_id = "1234",
//! )
//!   .build(&new_biscuit)
//!   .expect("failed to build the authorizer")
//!   .authorize()
//!   .expect("Failed to authorize biscuit");
//! ```

/// Create an `Authorizer` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// use biscuit_auth::macros::authorizer;
/// use std::time::SystemTime;
///
/// let a = authorizer!(
///   r#"
///     time({now});
///     allow if true;
///   "#,
///   now = SystemTime::now(),
/// );
/// ```
pub use biscuit_quote::authorizer;

/// Merge facts, rules, checks, and policies into an `Authorizer` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
///
/// ```rust
/// use biscuit_auth::macros::{authorizer, authorizer_merge};
/// use std::time::SystemTime;
///
/// let mut b = authorizer!(
///   r#"
///     time({now});
///   "#,
///   now = SystemTime::now()
/// );
///
/// b = authorizer_merge!(
///   b,
///   r#"
///     allow if true;
///   "#
/// );
/// ```
pub use biscuit_quote::authorizer_merge;

/// Create an `BiscuitBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// use biscuit_auth::{Biscuit, PrivateKey};
/// use biscuit_auth::macros::biscuit;
/// use std::time::{SystemTime, Duration};
///
/// let root = PrivateKey::new();
/// let biscuit = biscuit!(
///   r#"
///     user({user_id});
///     check if time($time), $time < {expiration}
///   "#,
///   user_id = "1234",
///   expiration = SystemTime::now() + Duration::from_secs(86_400)
/// ).build(&root);
/// ```
pub use biscuit_quote::biscuit;

/// Merge facts, rules, and checks into a `BiscuitBuilder` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
///
/// ```rust
/// use biscuit_auth::{Biscuit, PrivateKey};
/// use biscuit_auth::macros::{biscuit, biscuit_merge};
/// use std::time::{SystemTime, Duration};
///
/// let root = PrivateKey::new();
///
/// let mut b = biscuit!(
///   r#"
///     user({user_id});
///   "#,
///   user_id = "1234"
/// );
///
/// b = biscuit_merge!(
///   b,
///   r#"
///     check if time($time), $time < {expiration}
///   "#,
///   expiration = SystemTime::now() + Duration::from_secs(86_400)
/// );
///
/// let biscuit = b.build(&root);
/// ```
pub use biscuit_quote::biscuit_merge;

/// Create a `BlockBuilder` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// block building.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_auth::macros::block;
///
/// let b = block!(
///   r#"
///     user({user_id});
///     check if user($id);
///   "#,
///   user_id = "1234"
/// );
/// ```
pub use biscuit_quote::block;

/// Merge facts, rules, and checks into a `BlockBuilder` from a datalog
/// string and optional parameters. The datalog string is parsed at compile time
/// and replaced by manual block building.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_auth::macros::{block, block_merge};
///
/// let mut b = block!(
///   r#"
///     user({user_id});
///   "#,
///   user_id = "1234"
/// );
///
/// b = block_merge!(
///   b,
///   r#"
///     check if user($id);
///   "#
/// );
/// ```
pub use biscuit_quote::block_merge;

/// Create a `Rule` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_auth::macros::rule;
///
/// let r = rule!(
///   r#"is_allowed($operation) <- user({user_id}), right({user_id}, $operation)
///   "#,
///   user_id = "1234"
/// );
/// ```
pub use biscuit_quote::rule;

/// Create a `Fact` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_auth::macros::fact;
///
/// let f = fact!(
///   r#"user({user_id})"#,
///   user_id = "1234"
/// );
/// ```
pub use biscuit_quote::fact;

/// Create a `Check` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_auth::macros::check;
///
/// let c = check!(
///   r#"check if user({user_id})"#,
///   user_id = "1234"
/// );
/// ```
pub use biscuit_quote::check;

/// Create a `Policy` from a datalog string and optional parameters.
/// The datalog string is parsed at compile time and replaced by manual
/// builder calls.
///
/// ```rust
/// use biscuit_auth::Biscuit;
/// use biscuit_auth::macros::policy;
///
/// let p = policy!(
///   r#"allow if user({user_id})"#,
///   user_id = "1234"
/// );
/// ```
pub use biscuit_quote::policy;
