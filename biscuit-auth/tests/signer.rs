use biscuit_auth::{datalog::SymbolTable, error, Algorithm, Biscuit, PublicKey, Signature, Signer};
use rand::{rngs::StdRng, SeedableRng};

struct Ed25519Signer(ed25519_dalek::SigningKey);

impl Signer for Ed25519Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        use ed25519_dalek::Signer;
        Ok(self.0.sign(data).into())
    }
}

struct P256Signer(p256::ecdsa::SigningKey);

impl Signer for P256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Secp256r1
    }

    fn sign(&self, data: &[u8]) -> Result<Signature, error::Format> {
        use p256::ecdsa::signature::Signer;

        let sig: p256::ecdsa::Signature = self.0.sign(data);
        Ok(sig.into())
    }
}

fn assert_signer_roundtrip(signer: &impl Signer, root_public: PublicKey) {
    let mut rng = StdRng::seed_from_u64(42);

    let token = Biscuit::builder()
        .fact(r#"user("alice")"#)
        .unwrap()
        .build_with_rng(signer, SymbolTable::default(), &mut rng)
        .unwrap();

    let serialized = token.to_vec().unwrap();

    // This cryptographically verifies the custom signer's authority signature.
    Biscuit::from(&serialized, root_public).unwrap();
}

#[test]
fn external_ed25519_signer_builds_valid_token() {
    let mut rng = StdRng::seed_from_u64(0);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let root_public =
        PublicKey::from_bytes(signing_key.verifying_key().as_bytes(), Algorithm::Ed25519).unwrap();

    assert_signer_roundtrip(&Ed25519Signer(signing_key), root_public);
}

#[test]
fn external_p256_signer_builds_valid_token() {
    let mut rng = StdRng::seed_from_u64(1);
    let signing_key = p256::ecdsa::SigningKey::random(&mut rng);
    let encoded_public_key = signing_key.verifying_key().to_encoded_point(true);
    let root_public =
        PublicKey::from_bytes(encoded_public_key.as_bytes(), Algorithm::Secp256r1).unwrap();

    assert_signer_roundtrip(&P256Signer(signing_key), root_public);
}
