use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::builder::Algorithm;
use crate::crypto::Signature;
use crate::error;

pub trait Verify {
    fn verify_signature(
        &self,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), error::Format>;
    fn algorithm(&self) -> Algorithm;
}

pub trait Sign {
    type PublicKey: Verify;

    fn sign(&self, data: &[u8]) -> Result<Signature, error::Format>;
    fn public(&self) -> Self::PublicKey;
    fn algorithm(&self) -> Algorithm;
}

pub trait SerializePublicKey: Verify + Clone + PartialEq + Sized {
    fn from_bytes_and_algorithm(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, error::Format>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait SerializePrivateKey: Sign<PublicKey: SerializePublicKey> + Clone + Sized {
    fn new_with_rng<R: RngCore + CryptoRng>(algorithm: Algorithm, rng: &mut R) -> Self;
    fn from_bytes_and_algorithm(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, error::Format>;
    fn to_bytes(&self) -> Zeroizing<Vec<u8>>;
}
