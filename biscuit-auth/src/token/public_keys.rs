/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};

use crate::crypto::SerializePublicKey;
use crate::format::schema;
use crate::{Algorithm, error};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    pub(crate) keys: Vec<PublicKey>,
}

impl PublicKeys {
    pub(crate) fn new() -> Self {
        PublicKeys { keys: vec![] }
    }

    pub(crate) fn from_keys(keys: Vec<PublicKey>) -> Self {
        PublicKeys { keys }
    }

    pub(crate) fn extend(&mut self, other: &PublicKeys) -> Result<(), error::Format> {
        if !self.is_disjoint(other) {
            return Err(error::Format::PublicKeyTableOverlap);
        }
        self.keys.extend(other.keys.iter().cloned());
        Ok(())
    }

    pub(crate) fn insert(&mut self, k: &PublicKey) -> u64 {
        match self.keys.iter().position(|key| key == k) {
            Some(index) => index as u64,
            None => {
                self.keys.push(k.clone());
                (self.keys.len() - 1) as u64
            }
        }
    }

    pub(crate) fn insert_serialize<K: SerializePublicKey>(&mut self, k: &K) -> u64 {
        self.insert(&PublicKey::from(k))
    }

    pub(crate) fn insert_data(&mut self, k: &PublicKey) -> u64 {
        match self.keys.iter().position(|key| key == k) {
            Some(index) => index as u64,
            None => {
                self.keys.push(k.clone());
                (self.keys.len() - 1) as u64
            }
        }
    }

    pub(crate) fn insert_proto(&mut self, k: &schema::PublicKey) -> u64 {
        let k = PublicKey::from_proto(k);
        match self.keys.iter().position(|key| *key == k) {
            Some(index) => index as u64,
            None => {
                self.keys.push(k.clone());
                (self.keys.len() - 1) as u64
            }
        }
    }

    pub(crate) fn insert_proto_fallible(&mut self, k: &schema::PublicKey) -> Result<u64, error::Format> {
        let k = PublicKey::from_proto(k);
        match self.keys.iter().position(|key| *key == k) {
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

    pub(crate) fn get_key(&self, i: u64) -> Option<&PublicKey> {
        self.keys.get(i as usize)
    }

    pub(crate) fn into_inner(self) -> Vec<PublicKey> {
        self.keys
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey {
    algorithm: Algorithm,
    key: Vec<u8>,
}

impl PublicKey {
    pub fn from_bytes(algorithm: Algorithm, key: Vec<u8>) -> PublicKey {
        PublicKey { algorithm, key }
    }

    pub(crate) fn from<K: SerializePublicKey>(key: &K) -> PublicKey {
        PublicKey {
            algorithm: key.algorithm(),
            key: key.to_bytes(),
        }
    }

    fn from_proto(key: &schema::PublicKey) -> PublicKey {
        PublicKey {
            algorithm: key.algorithm().into(),
            key: key.key.clone(),
        }
    }

    pub(crate) fn to_proto(&self) -> schema::PublicKey {
        schema::PublicKey {
            algorithm: schema::public_key::Algorithm::from(self.algorithm) as i32,
            key: self.key.clone(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.algorithm, hex::encode(&self.key))
    }
}
