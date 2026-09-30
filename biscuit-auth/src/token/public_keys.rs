/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use nom::Finish;

use crate::crypto::SerializePublicKey;
use crate::{Algorithm, error};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    pub(crate) keys: Vec<PublicKeyData>,
}

impl PublicKeys {
    pub(crate) fn new() -> Self {
        PublicKeys { keys: vec![] }
    }

    pub(crate) fn from_keys(keys: Vec<PublicKeyData>) -> Self {
        PublicKeys { keys }
    }

    pub(crate) fn extend(&mut self, other: &PublicKeys) -> Result<(), error::Format> {
        if !self.is_disjoint(other) {
            return Err(error::Format::PublicKeyTableOverlap);
        }
        self.keys.extend(other.keys.iter().cloned());
        Ok(())
    }

    pub(crate) fn insert(&mut self, k: &PublicKeyData) -> u64 {
        match self.keys.iter().position(|key| key == k) {
            Some(index) => index as u64,
            None => {
                self.keys.push(k.clone());
                (self.keys.len() - 1) as u64
            }
        }
    }

    pub(crate) fn insert_fallible(&mut self, k: &PublicKeyData) -> Result<u64, error::Format> {
        match self.keys.iter().position(|key| key == k) {
            Some(_) => Err(error::Format::PublicKeyTableOverlap),
            None => {
                self.keys.push(k.clone());
                Ok((self.keys.len() - 1) as u64)
            }
        }
    }

    pub(crate) fn current_offset(&self) -> usize {
        self.keys.len()
    }

    pub(crate) fn split_at(&mut self, offset: usize) -> PublicKeys {
        let mut table = PublicKeys::new();
        table.keys = self.keys.split_off(offset);
        table
    }

    pub(crate) fn is_disjoint(&self, other: &PublicKeys) -> bool {
        let h1 = self.keys.iter().collect::<HashSet<_>>();
        let h2 = other.keys.iter().collect::<HashSet<_>>();

        h1.is_disjoint(&h2)
    }

    pub(crate) fn get_key(&self, i: u64) -> Option<&PublicKeyData> {
        self.keys.get(i as usize)
    }

    pub(crate) fn into_inner(self) -> Vec<PublicKeyData> {
        self.keys
    }
}

impl IntoIterator for PublicKeys {
    type Item = PublicKeyData;
    type IntoIter = std::vec::IntoIter<PublicKeyData>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.into_iter()
    }
}

impl<'a> IntoIterator for &'a PublicKeys {
    type Item = &'a PublicKeyData;
    type IntoIter = std::slice::Iter<'a, PublicKeyData>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKeyData {
    algorithm: Algorithm,
    key: Vec<u8>,
}

impl PublicKeyData {
    pub fn from_bytes(algorithm: Algorithm, key: Vec<u8>) -> PublicKeyData {
        PublicKeyData { algorithm, key }
    }

    pub(crate) fn from_proto(key: &biscuit_proto::PublicKey) -> PublicKeyData {
        PublicKeyData {
            algorithm: key.algorithm().into(),
            key: key.key.clone(),
        }
    }

    pub(crate) fn to_proto(&self) -> biscuit_proto::PublicKey {
        biscuit_proto::PublicKey {
            algorithm: biscuit_proto::public_key::Algorithm::from(self.algorithm) as i32,
            key: self.key.clone(),
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn print(&self) -> String {
        self.to_string()
    }
}

/// lowers a public key from any crypto implementation into its serialized
/// representation
impl<K: SerializePublicKey> From<&K> for PublicKeyData {
    fn from(key: &K) -> PublicKeyData {
        PublicKeyData {
            algorithm: key.algorithm(),
            key: key.to_bytes(),
        }
    }
}

impl From<crate::crypto::PublicKey> for PublicKeyData {
    fn from(key: crate::crypto::PublicKey) -> PublicKeyData {
        (&key).into()
    }
}

impl Display for PublicKeyData {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.algorithm, hex::encode(&self.key))
    }
}

impl FromStr for PublicKeyData {
    type Err = error::Format;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, public_key) = biscuit_parser::parser::public_key(s)
            .finish()
            .map_err(|e| error::Format::InvalidKey(e.to_string()))?;

        Ok(PublicKeyData::from_bytes(
            public_key.algorithm.into(),
            public_key.key,
        ))
    }
}
