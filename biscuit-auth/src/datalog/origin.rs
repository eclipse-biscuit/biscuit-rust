/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::iter::FromIterator;

use crate::token::Scope;

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Origin {
    pub(crate) inner: BTreeSet<usize>,
}

impl Origin {
    pub fn insert(&mut self, i: usize) {
        self.inner.insert(i);
    }

    pub fn union(&self, other: &Self) -> Self {
        Origin {
            inner: self.inner.union(&other.inner).cloned().collect(),
        }
    }

    pub fn is_superset(&self, other: &Self) -> bool {
        self.inner.is_superset(&other.inner)
    }
}

impl<'a> Extend<&'a usize> for Origin {
    fn extend<T: IntoIterator<Item = &'a usize>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}

impl Extend<usize> for Origin {
    fn extend<T: IntoIterator<Item = usize>>(&mut self, iter: T) {
        self.inner.extend(iter)
    }
}

impl<'a> FromIterator<&'a usize> for Origin {
    fn from_iter<T: IntoIterator<Item = &'a usize>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().cloned().collect(),
        }
    }
}

impl FromIterator<usize> for Origin {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut it = self.inner.iter();

        if let Some(i) = it.next() {
            if *i == usize::MAX {
                write!(f, "authorizer")?;
            } else {
                write!(f, "{i}")?;
            }
        }

        for i in it {
            if *i == usize::MAX {
                write!(f, ", authorizer")?;
            } else {
                write!(f, ", {i}")?;
            }
        }
        Ok(())
    }
}

/// This represents the sets of origins trusted by a rule
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrustedOrigins(Origin);

#[allow(clippy::should_implement_trait)]
impl TrustedOrigins {
    pub fn default() -> TrustedOrigins {
        let mut origins = Origin::default();
        origins.insert(usize::MAX);
        origins.insert(0);
        TrustedOrigins(origins)
    }

    pub fn from_scopes(
        rule_scopes: &[Scope],
        default_origins: &TrustedOrigins,
        current_block: usize,
        public_key_to_block_id: &HashMap<usize, Vec<usize>>,
    ) -> TrustedOrigins {
        if rule_scopes.is_empty() {
            let mut origins = default_origins.clone();
            origins.0.insert(current_block);
            origins.0.insert(usize::MAX);
            return origins;
        }

        let mut origins = Origin::default();
        origins.insert(usize::MAX);
        origins.insert(current_block);

        for scope in rule_scopes {
            match scope {
                Scope::Authority => {
                    origins.insert(0);
                }
                Scope::Previous => {
                    if current_block != usize::MAX {
                        origins.extend(0..current_block + 1)
                    }
                }
                Scope::PublicKey(key_id) => {
                    if let Some(block_ids) = public_key_to_block_id.get(&(*key_id as usize)) {
                        origins.extend(block_ids.iter())
                    }
                }
            }
        }

        TrustedOrigins(origins)
    }

    pub fn contains(&self, fact_origin: &Origin) -> bool {
        self.0.is_superset(fact_origin)
    }
}

impl FromIterator<usize> for TrustedOrigins {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a> FromIterator<&'a usize> for TrustedOrigins {
    fn from_iter<T: IntoIterator<Item = &'a usize>>(iter: T) -> Self {
        Self(iter.into_iter().cloned().collect())
    }
}
