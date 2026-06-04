/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 */
use std::convert::TryFrom;

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::builder::Algorithm;
use crate::{error, PublicKey};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(into = "BiscuitWebKeyRepr")]
#[serde(try_from = "BiscuitWebKeyRepr")]
pub struct BiscuitWebKey {
    pub public_key: PublicKey,
    pub key_id: u32,
    pub issuer: Option<String>,
    pub expires_at: Option<DateTime<FixedOffset>>,
}

#[derive(Serialize, Deserialize)]
struct BiscuitWebKeyRepr {
    pub algorithm: String,
    pub key_bytes: String,
    pub key_id: u32,
    pub issuer: Option<String>,
    pub expires_at: Option<DateTime<FixedOffset>>,
}

impl From<BiscuitWebKey> for BiscuitWebKeyRepr {
    fn from(value: BiscuitWebKey) -> Self {
        BiscuitWebKeyRepr {
            algorithm: value.public_key.algorithm_string().to_string(),
            key_bytes: value.public_key.to_bytes_hex(),
            key_id: value.key_id,
            issuer: value.issuer,
            expires_at: value.expires_at,
        }
    }
}

impl TryFrom<BiscuitWebKeyRepr> for BiscuitWebKey {
    type Error = error::Format;

    fn try_from(value: BiscuitWebKeyRepr) -> Result<Self, Self::Error> {
        let algorithm = Algorithm::try_from(value.algorithm.as_str())?;
        let public_key = PublicKey::from_bytes_hex(&value.key_bytes, algorithm)?;

        Ok(BiscuitWebKey {
            public_key,
            key_id: value.key_id,
            issuer: value.issuer,
            expires_at: value.expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::PrivateKey;
    use chrono::Utc;

    use super::*;

    #[test]
    fn roundtrips() {
        let keypair = PrivateKey::new();
        let bwk = BiscuitWebKey {
            public_key: keypair.public(),
            key_id: 12,
            expires_at: None,
            issuer: None,
        };

        let serialized = serde_json::to_string(&bwk).unwrap();
        let parsed: BiscuitWebKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, bwk);

        let keypair = PrivateKey::new_with_algorithm(Algorithm::Secp256r1);
        let bwk = BiscuitWebKey {
            public_key: keypair.public(),
            key_id: 0,
            expires_at: None,
            issuer: Some("test".to_string()),
        };

        let serialized = serde_json::to_string(&bwk).unwrap();
        let parsed: BiscuitWebKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, bwk);

        let keypair = PrivateKey::new();
        let bwk = BiscuitWebKey {
            public_key: keypair.public(),
            key_id: 0,
            expires_at: Some(Utc::now().fixed_offset()),
            issuer: Some("test".to_string()),
        };

        let serialized = serde_json::to_string(&bwk).unwrap();
        let parsed: BiscuitWebKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, bwk);
    }
    #[test]
    fn samples() {
        assert_eq!(
            serde_json::from_str::<BiscuitWebKey>(
                r#"
             {
                "algorithm": "ed25519",
                "key_bytes": "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                "key_id": 12,
                "expires_at": "2023-06-28T11:20:00+02:00",
                "issuer": "test"
             }
        "#
            )
            .unwrap(),
            BiscuitWebKey {
                public_key: PublicKey::from_bytes_hex(
                    "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                    Algorithm::Ed25519
                )
                .unwrap(),
                key_id: 12,
                expires_at: Some(
                    DateTime::parse_from_rfc3339("2023-06-28T11:20:00+02:00").unwrap()
                ),
                issuer: Some("test".to_string())
            }
        );
        assert_eq!(
            serde_json::from_str::<BiscuitWebKey>(
                r#"
             {
                "algorithm": "ed25519",
                "key_bytes": "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                "key_id": 12,
                "expires_at": null,
                "issuer": null
             }
        "#
            )
            .unwrap(),
            BiscuitWebKey {
                public_key: PublicKey::from_bytes_hex(
                    "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                    Algorithm::Ed25519
                )
                .unwrap(),
                key_id: 12,
                expires_at: None,
                issuer: None
            }
        );
        assert_eq!(
            serde_json::from_str::<BiscuitWebKey>(
                r#"
             {
                "algorithm": "ed25519",
                "key_bytes": "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                "key_id": 12
             }
        "#
            )
            .unwrap(),
            BiscuitWebKey {
                public_key: PublicKey::from_bytes_hex(
                    "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                    Algorithm::Ed25519
                )
                .unwrap(),
                key_id: 12,
                expires_at: None,
                issuer: None
            }
        );
        assert_eq!(
            serde_json::from_str::<BiscuitWebKey>(
                r#"
             {
                "algorithm": "ed25519",
                "key_bytes": "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                "key_id": 4294967295
             }
        "#
            )
            .unwrap(),
            BiscuitWebKey {
                public_key: PublicKey::from_bytes_hex(
                    "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                    Algorithm::Ed25519
                )
                .unwrap(),
                key_id: u32::MAX,
                expires_at: None,
                issuer: None
            }
        );
        assert!(serde_json::from_str::<BiscuitWebKey>(
            r#"
             {
                "algorithm": "invalid",
                "key_bytes": "63c7a8628c14b778a4b66a22e1f53dab4542423295b6fb5a52283da58bcf6d9a",
                "key_id": 4294967295
             }
        "#
        )
        .is_err());
    }
}
