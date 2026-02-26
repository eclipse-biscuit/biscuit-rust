use crate::crypto::{KeyPairImpl, KeySerialization, PrivateKeyImpl, PublicKeyImpl, Signature};
use crate::error;
use crate::error::Format;
use crate::error::Signature::InvalidSignatureGeneration;
use crate::format::schema::public_key::Algorithm;
use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
#[cfg(feature = "pem")]
use aws_lc_rs::encoding::{AsDer, EcPrivateKeyRfc5915Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    EcdsaKeyPair, KeyPair as AwsLcKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING,
};
use aws_lc_sys::{
    point_conversion_form_t, EC_GROUP_free, EC_GROUP_new_by_curve_name, EC_POINT_free,
    EC_POINT_new, EC_POINT_oct2point, EC_POINT_point2oct, NID_X9_62_prime256v1, EC_GROUP, EC_POINT,
};
use rand_core::{CryptoRng, RngCore};
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct PublicKey(UnparsedPublicKey<[u8; 65]>);

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
        write!(f, "secp256r1/{}", self.to_bytes_hex())
    }
}

impl KeySerialization for PublicKey {
    type Bytes = Vec<u8>;
    type String = String;

    fn to_bytes(&self) -> Self::Bytes {
        compress_p256(self.0.as_ref()).to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Format> {
        match bytes.len() {
            33 => {
                let uncompressed = decompress_p256(bytes)?;
                Ok(Self(UnparsedPublicKey::new(
                    &ECDSA_P256_SHA256_ASN1,
                    uncompressed,
                )))
            }
            65 => {
                let mut arr = [0u8; 65];
                arr.copy_from_slice(bytes);
                Ok(Self(UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, arr)))
            }
            _ => Err(Format::InvalidKeySize(bytes.len())),
        }
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
        Algorithm::Secp256r1
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
        if bytes.len() != 32 {
            return Err(Format::InvalidKeySize(bytes.len()));
        }
        let _ = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::ECDH_P256,
            bytes,
        )
        .map_err(|e| e.to_string())
        .map_err(Format::InvalidKey)?;
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(bytes);
        Ok(Self(scalar))
    }
}

#[cfg(feature = "pem")]
impl crate::crypto::KeyPemSerialization for PrivateKey {
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        // Parse via aws-lc to validate, then extract the scalar
        let priv_key = aws_lc_rs::agreement::PrivateKey::from_private_key_der(
            &aws_lc_rs::agreement::ECDH_P256,
            bytes,
        )
        .map_err(|e| e.to_string())
        .map_err(Format::InvalidKey)?;
        let scalar_bin: EcPrivateKeyBin = priv_key
            .as_be_bytes()
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(scalar_bin.as_ref());
        Ok(Self(scalar))
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use pkcs8::spki::Document;
        let (label, doc) = Document::from_pem(str)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        if label != "PRIVATE KEY" && label != "EC PRIVATE KEY" {
            return Err(Format::InvalidKey(format!(
                "unexpected PEM label: expected \"PRIVATE KEY\" or \"EC PRIVATE KEY\", got \"{label}\""
            )));
        }
        Self::from_der(doc.as_ref())
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        let priv_key = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::ECDH_P256,
            self.0.as_ref(),
        )
        .map_err(|e| e.to_string())
        .map_err(Format::PKCS8)?;
        let rfc5915: EcPrivateKeyRfc5915Der = priv_key
            .as_der()
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)?;
        Ok(Zeroizing::new(rfc5915.as_ref().to_vec()))
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use pkcs8::der::pem::LineEnding;
        let der = self.to_der()?;
        let pem = pkcs8::der::pem::encode_string("EC PRIVATE KEY", LineEnding::LF, &der)
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)?;
        Ok(Zeroizing::new(pem))
    }
}

impl PrivateKeyImpl for PrivateKey {
    type PublicKey = PublicKey;

    fn public(&self) -> Self::PublicKey {
        let priv_key = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::ECDH_P256,
            self.0.as_ref(),
        )
        .expect("stored scalar should produce a valid private key");
        let pub_key = priv_key
            .compute_public_key()
            .expect("should be able to compute public key");
        // compute_public_key returns uncompressed SEC1
        let mut uncompressed = [0u8; 65];
        uncompressed.copy_from_slice(pub_key.as_ref());
        PublicKey(UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            uncompressed,
        ))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256r1
    }
}

#[derive(Debug)]
pub struct KeyPair(EcdsaKeyPair);

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.private() == other.private()
    }
}

impl KeyPairImpl for KeyPair {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;

    fn sign(&self, data: &[u8]) -> Result<Signature, Format> {
        let rng = SystemRandom::new();
        let signature = self
            .0
            .sign(&rng, data)
            .map_err(|e| e.to_string())
            .map_err(InvalidSignatureGeneration)
            .map_err(Format::Signature)?;

        Ok(Signature(signature.as_ref().to_vec()))
    }

    fn from_private(key: &Self::PrivateKey) -> Self {
        let kp =
            keypair_from_scalar(&*key.0).expect("stored scalar should produce a valid keypair");
        Self(kp)
    }

    fn public(&self) -> Self::PublicKey {
        let pub_key = self.0.public_key();
        let mut uncompressed = [0u8; 65];
        uncompressed.copy_from_slice(pub_key.as_ref());
        PublicKey(UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            uncompressed,
        ))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256r1
    }

    fn private(&self) -> Self::PrivateKey {
        let scalar_bin: EcPrivateKeyBin = self
            .0
            .private_key()
            .as_be_bytes()
            .expect("scalar export failed");
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(scalar_bin.as_ref());
        PrivateKey(scalar)
    }

    fn generate() -> Self {
        let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)
            .expect("P256 key generation failed");
        Self(kp)
    }

    fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut scalar = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *scalar);
        let priv_key = PrivateKey(scalar);
        Self::from_private(&priv_key)
    }
}

/// Build an EcdsaKeyPair from a raw 32-byte scalar
fn keypair_from_scalar(scalar: &[u8]) -> Result<EcdsaKeyPair, Format> {
    let priv_key = aws_lc_rs::agreement::PrivateKey::from_private_key(
        &aws_lc_rs::agreement::ECDH_P256,
        scalar,
    )
    .map_err(|e| e.to_string())
    .map_err(Format::InvalidKey)?;
    let pub_key = priv_key
        .compute_public_key()
        .map_err(|e| e.to_string())
        .map_err(Format::InvalidKey)?;
    EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        scalar,
        pub_key.as_ref(),
    )
    .map_err(|e| e.to_string())
    .map_err(Format::InvalidKey)
}

struct EcGroup(*mut EC_GROUP);

impl EcGroup {
    pub fn init(nid: i32) -> Result<Self, Format> {
        let group = unsafe { EC_GROUP_new_by_curve_name(nid) };
        if group.is_null() {
            Err(Format::InvalidKey("failed to create EC group".to_string()))
        } else {
            Ok(Self(group))
        }
    }
}

impl Drop for EcGroup {
    fn drop(&mut self) {
        unsafe { EC_GROUP_free(self.0) };
    }
}

struct EcPoint<'a> {
    point: *mut EC_POINT,
    group: &'a EcGroup,
}

impl<'a> EcPoint<'a> {
    pub fn init(group: &'a EcGroup) -> Result<Self, Format> {
        let point = unsafe { EC_POINT_new(group.0) };
        if point.is_null() {
            Err(Format::InvalidKey("failed to create EC point".to_string()))
        } else {
            Ok(Self { group, point })
        }
    }

    pub fn decompress(&self, compressed: &[u8]) -> Result<[u8; 65], Format> {
        let rc = unsafe {
            EC_POINT_oct2point(
                self.group.0,
                self.point,
                compressed.as_ptr(),
                compressed.len(),
                std::ptr::null_mut(),
            )
        };
        if rc != 1 {
            return Err(Format::InvalidKey(
                "failed to decompress EC point".to_string(),
            ));
        }

        let mut uncompressed = [0u8; 65];

        let len = unsafe {
            EC_POINT_point2oct(
                self.group.0,
                self.point,
                point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED,
                uncompressed.as_mut_ptr(),
                uncompressed.len(),
                std::ptr::null_mut(),
            )
        };

        if len != 65 {
            Err(Format::InvalidKey(
                "unexpected uncompressed point length".to_string(),
            ))
        } else {
            Ok(uncompressed)
        }
    }
}

impl<'a> Drop for EcPoint<'a> {
    fn drop(&mut self) {
        unsafe { EC_POINT_free(self.point) };
    }
}

/// Decompress a SEC1 compressed P-256 point (33 bytes) to uncompressed (65 bytes).
fn decompress_p256(compressed: &[u8]) -> Result<[u8; 65], Format> {
    let group = EcGroup::init(NID_X9_62_prime256v1)?;
    let point = EcPoint::init(&group)?;

    point.decompress(compressed)
}

/// Compress an uncompressed SEC1 P-256 point (65 bytes) to compressed (33 bytes).
fn compress_p256(uncompressed: &[u8]) -> [u8; 33] {
    let mut compressed = [0u8; 33];
    // 0x02 if y is even, 0x03 if y is odd
    compressed[0] = if uncompressed[64] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    compressed[1..33].copy_from_slice(&uncompressed[1..33]);
    compressed
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
    fn public_key_compressed_roundtrip() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        // to_bytes produces compressed (33 bytes)
        let compressed = pub_key.to_bytes();
        assert_eq!(compressed.len(), 33);
        let restored = PublicKey::from_bytes(&compressed).unwrap();
        assert_eq!(pub_key, restored);
    }

    #[test]
    fn public_key_uncompressed_roundtrip() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        // from_bytes also accepts uncompressed (65 bytes)
        let uncompressed: &[u8] = pub_key.0.as_ref();
        assert_eq!(uncompressed.len(), 65);
        let restored = PublicKey::from_bytes(uncompressed).unwrap();
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

        // Signature from reconstructed keypair verifies with original public key
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
            PublicKey::from_bytes(&[0u8; 32]),
            Err(Format::InvalidKeySize(32))
        ));
    }

    #[test]
    fn algorithm_identifiers() {
        let kp = KeyPair::generate();
        assert_eq!(kp.algorithm(), Algorithm::Secp256r1);
        assert_eq!(kp.public().algorithm(), Algorithm::Secp256r1);
        assert_eq!(kp.private().algorithm(), Algorithm::Secp256r1);
    }

    #[test]
    fn public_key_display() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        let display = format!("{pub_key}");
        assert!(display.starts_with("secp256r1/"));
        // The hex portion should be 66 chars (33 compressed bytes)
        let hex_part = display.strip_prefix("secp256r1/").unwrap();
        assert_eq!(hex_part.len(), 66);
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

    #[test]
    fn compress_decompress_roundtrip() {
        let kp = KeyPair::generate();
        let pub_key = kp.public();
        let uncompressed: &[u8] = pub_key.0.as_ref();
        let compressed = compress_p256(uncompressed);
        let decompressed = decompress_p256(&compressed).unwrap();
        assert_eq!(uncompressed, &decompressed);
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
            assert!(pem.contains("EC PRIVATE KEY"));
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
            // Tamper with the label
            let bad_pem = pem.replace("EC PRIVATE KEY", "PUBLIC KEY");
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
