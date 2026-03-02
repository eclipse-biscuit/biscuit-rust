use crate::crypto::{KeyPairImpl, KeySerialization, PrivateKeyImpl, PublicKeyImpl, Signature};
use crate::error;
use crate::error::Format;
use crate::format::schema::public_key::Algorithm;
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as AwsKeyPair, UnparsedPublicKey, ED25519};
use rand_core::{CryptoRng, RngCore};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct PublicKey(UnparsedPublicKey<[u8; 32]>);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.algorithm() as i32).hash(state);
        self.0.as_ref().hash(state);
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ed25519/{}", self.to_bytes_hex())
    }
}

impl KeySerialization for PublicKey {
    type Bytes = Vec<u8>;
    type String = String;

    fn to_bytes(&self) -> Self::Bytes {
        self.0.as_ref().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;
        Ok(Self(UnparsedPublicKey::new(&ED25519, bytes)))
    }
}

#[cfg(feature = "pem")]
impl super::AwsLcPublicKey for PublicKey {
    fn parsed(&self) -> Result<aws_lc_rs::signature::ParsedPublicKey, Format> {
        self.0
            .parse()
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)
    }
}

impl PublicKeyImpl for PublicKey {
    fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<(), Format> {
        self.0
            .verify(data, signature.0.as_slice())
            .map_err(|e| e.to_string())
            .map_err(error::Signature::InvalidSignature)
            .map_err(Format::Signature)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(Zeroizing<[u8; 32]>);

impl KeySerialization for PrivateKey {
    type Bytes = Zeroizing<Vec<u8>>;
    type String = Zeroizing<String>;

    fn to_bytes(&self) -> Self::Bytes {
        self.0.to_vec().into()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Format::InvalidKeySize(bytes.len()))?;
        let _ = Ed25519KeyPair::from_seed_unchecked(&bytes)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl PrivateKeyImpl for PrivateKey {
    type PublicKey = PublicKey;

    fn public(&self) -> Self::PublicKey {
        let kp =
            Ed25519KeyPair::from_seed_unchecked(self.0.as_ref()).expect("invalid ed25519 key seed");
        PublicKey::from_bytes(kp.public_key().as_ref()).expect("invalid ed25519 public key")
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }
}

#[cfg(feature = "pem")]
impl crate::crypto::KeyPemSerialization for PrivateKey {
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        let kp = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        let seed_bin: aws_lc_rs::encoding::Curve25519SeedBin = kp
            .seed()
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?
            .as_be_bytes()
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(seed_bin.as_ref());
        Ok(Self(seed))
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use pkcs8::spki::Document;
        let (label, doc) = Document::from_pem(str)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        if label != "PRIVATE KEY" {
            return Err(Format::InvalidKey(format!(
                "unexpected PEM label: expected \"PRIVATE KEY\", got \"{label}\""
            )));
        }
        Self::from_der(doc.as_ref())
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        use aws_lc_rs::encoding::AsDer;
        let kp = Ed25519KeyPair::from_seed_unchecked(self.0.as_ref())
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)?;
        let pkcs8: aws_lc_rs::encoding::Pkcs8V1Der = kp
            .as_der()
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)?;
        Ok(Zeroizing::new(pkcs8.as_ref().to_vec()))
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use pkcs8::der::pem::LineEnding;
        let der = self.to_der()?;
        let pem = pkcs8::der::pem::encode_string("PRIVATE KEY", LineEnding::LF, &der)
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)?;
        Ok(Zeroizing::new(pem))
    }
}

#[derive(Debug)]
pub struct KeyPair(Ed25519KeyPair);

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.private() == other.private()
    }
}

impl KeyPairImpl for KeyPair {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    fn sign(&self, data: &[u8]) -> Result<Signature, Format> {
        let signature = self.0.sign(data);

        Ok(Signature(signature.as_ref().to_vec()))
    }

    fn from_private(key: &Self::PrivateKey) -> Self {
        let kp = Ed25519KeyPair::from_seed_unchecked(key.0.as_ref()).expect("invalid key seed");
        Self(kp)
    }

    fn public(&self) -> Self::PublicKey {
        PublicKey::from_bytes(self.0.public_key().as_ref()).expect("invalid public key")
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn private(&self) -> Self::PrivateKey {
        let seed = self.0.seed().expect("could not get seed");
        PrivateKey::from_bytes(seed.as_be_bytes().expect("get seed bytes").as_ref())
            .expect("invalid seed")
    }

    fn generate() -> Self {
        let kp = Ed25519KeyPair::generate().expect("could not generate keys");
        Self(kp)
    }

    fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *scalar);
        let priv_key = PrivateKey(scalar);
        Self::from_private(&priv_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        let msg = b"hello world";
        let sig = kp.sign(msg).unwrap();
        pub_key.verify_signature(msg, &sig).unwrap();
    }

    #[test]
    fn verify_wrong_message_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign(b"correct message").unwrap();
        assert!(kp
            .public()
            .verify_signature(b"wrong message", &sig)
            .is_err());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();
        let msg = b"test";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.public().verify_signature(msg, &sig).is_err());
    }

    #[test]
    fn private_key_bytes_roundtrip() {
        let kp = KeyPair::generate();
        let priv_key = kp.private();
        let bytes = priv_key.to_bytes();
        let restored = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(priv_key, restored);
        assert_eq!(priv_key.public(), restored.public());
    }

    #[test]
    fn private_key_hex_roundtrip() {
        let kp = KeyPair::generate();
        let priv_key = kp.private();
        let hex = priv_key.to_bytes_hex();
        let restored = PrivateKey::from_bytes_hex(&hex).unwrap();
        assert_eq!(priv_key, restored);
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        let bytes = pub_key.to_bytes();
        assert_eq!(bytes.len(), 32);
        let restored = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pub_key, restored);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        let hex = pub_key.to_bytes_hex();
        let restored = PublicKey::from_bytes_hex(&hex).unwrap();
        assert_eq!(pub_key, restored);
    }

    #[test]
    fn keypair_from_private_key() {
        let kp = KeyPair::generate();
        let priv_key = kp.private();
        let kp2 = KeyPair::from_private(&priv_key);
        assert_eq!(kp.public(), kp2.public());

        let msg = b"test message";
        let sig = kp2.sign(msg).unwrap();
        kp.public().verify_signature(msg, &sig).unwrap();
    }

    #[test]
    fn keypair_equality() {
        let kp = KeyPair::generate();
        let kp2 = KeyPair::from_private(&kp.private());
        assert_eq!(kp, kp2);
    }

    #[test]
    fn invalid_private_key_size() {
        assert!(matches!(
            PrivateKey::from_bytes(&[0xaa]),
            Err(Format::InvalidKeySize(1))
        ));
        assert!(matches!(
            PrivateKey::from_bytes(&[0u8; 31]),
            Err(Format::InvalidKeySize(31))
        ));
        assert!(matches!(
            PrivateKey::from_bytes(&[0u8; 33]),
            Err(Format::InvalidKeySize(33))
        ));
    }

    #[test]
    fn invalid_public_key_size() {
        assert!(matches!(
            PublicKey::from_bytes(&[0xaa]),
            Err(Format::InvalidKeySize(1))
        ));
        assert!(matches!(
            PublicKey::from_bytes(&[0u8; 31]),
            Err(Format::InvalidKeySize(31))
        ));
        assert!(matches!(
            PublicKey::from_bytes(&[0u8; 33]),
            Err(Format::InvalidKeySize(33))
        ));
    }

    #[test]
    fn algorithm_identifiers() {
        let kp = KeyPair::generate();
        assert_eq!(kp.algorithm(), Algorithm::Ed25519);
        assert_eq!(kp.public().algorithm(), Algorithm::Ed25519);
        assert_eq!(kp.private().algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn public_key_display() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        let display = format!("{pub_key}");
        assert!(display.starts_with("ed25519/"));
        // 32 bytes = 64 hex chars
        let hex_part = display.strip_prefix("ed25519/").unwrap();
        assert_eq!(hex_part.len(), 64);
    }

    #[test]
    fn public_key_hash_consistency() {
        use std::collections::HashSet;
        let kp = KeyPair::generate();
        let pub1 = kp.public();
        let pub2 = PublicKey::from_bytes(&pub1.to_bytes()).unwrap();

        let mut set = HashSet::new();
        set.insert(pub1);
        assert!(set.contains(&pub2));
    }

    #[cfg(feature = "pem")]
    mod pem_tests {
        use super::*;
        use crate::crypto::KeyPemSerialization;

        #[test]
        fn private_key_pem_roundtrip() {
            let kp = KeyPair::generate();
            let priv_key = kp.private();
            let pem = priv_key.to_pem().unwrap();
            assert!(pem.contains("PRIVATE KEY"));
            let restored = PrivateKey::from_pem(&pem).unwrap();
            assert_eq!(priv_key, restored);
        }

        #[test]
        fn private_key_der_roundtrip() {
            let kp = KeyPair::generate();
            let priv_key = kp.private();
            let der = priv_key.to_der().unwrap();
            let restored = PrivateKey::from_der(&der).unwrap();
            assert_eq!(priv_key, restored);
        }

        #[test]
        fn public_key_pem_roundtrip() {
            let kp = KeyPair::generate();
            let pub_key = kp.public();
            let pem = pub_key.to_pem().unwrap();
            assert!(pem.contains("PUBLIC KEY"));
            let restored = PublicKey::from_pem(&pem).unwrap();
            assert_eq!(pub_key, restored);
        }

        #[test]
        fn public_key_der_roundtrip() {
            let kp = KeyPair::generate();
            let pub_key = kp.public();
            let der = pub_key.to_der().unwrap();
            let restored = PublicKey::from_der(&der).unwrap();
            assert_eq!(pub_key, restored);
        }

        #[test]
        fn private_key_wrong_pem_label() {
            let kp = KeyPair::generate();
            let pem = kp.private().to_pem().unwrap();
            let bad_pem = pem.replace("PRIVATE KEY", "PUBLIC KEY");
            assert!(PrivateKey::from_pem(&bad_pem).is_err());
        }

        #[test]
        fn public_key_wrong_pem_label() {
            let kp = KeyPair::generate();
            let pem = kp.public().to_pem().unwrap();
            let bad_pem = pem.replace("PUBLIC KEY", "PRIVATE KEY");
            assert!(PublicKey::from_pem(&bad_pem).is_err());
        }
    }
}
