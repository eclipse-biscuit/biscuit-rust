//! Cryptographic key traits for backend abstraction.
//!
//! This module defines traits that allow different cryptographic backends
//! (e.g., ed25519-dalek, ring) to be used interchangeably.
//!
//! # Trait Hierarchy
//!
//! - [`Backend`] - Groups Ed25519 and P256 implementations for a crypto library
//! - [`PrivateKeyImpl`] - Private key implementation (generation, signing)
//! - [`PublicKeyImpl`] - Public key implementation (verification)
//! - [`KeySerialization`] - Base trait for byte/hex serialization
//! - [`KeyPemSerialization`] - Extension trait for PEM/DER formats (requires `pem` feature)
//!

use super::Signature;
use crate::error;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Trait for grouping cryptographic backend implementations.
///
/// A backend provides implementations for both Ed25519 and P256 (secp256r1)
/// key types. This allows swapping out the underlying crypto library
/// (e.g., ed25519-dalek/p256 vs ring) at compile time.
///
/// # Example
///
/// ```ignore
/// use biscuit_auth::crypto::{Backend, DefaultBackend};
///
/// // Use the default backend
/// type MyKey = <DefaultBackend as Backend>::Ed25519;
/// let key = MyKey::generate();
/// ```
pub trait Backend {
    /// The Ed25519 private key implementation.
    type Ed25519: KeyPairImpl;
    /// The P256 (secp256r1) private key implementation.
    type P256: KeyPairImpl;
}

/// Extension trait for PEM/DER key serialization.
///
/// This trait is only available when the `pem` feature is enabled.
/// Types implementing [`PublicKeyImpl`] or [`PrivateKeyImpl`] should also
/// implement this trait to support standard key formats.
#[cfg(feature = "pem")]
pub trait KeyPemSerialization: KeySerialization + Sized {
    /// Deserializes a key from DER-encoded bytes.
    fn from_der(bytes: &[u8]) -> Result<Self, error::Format>;

    /// Deserializes a key from a PEM-encoded string.
    fn from_pem(str: &str) -> Result<Self, error::Format>;

    /// Serializes the key to DER-encoded bytes.
    fn to_der(&self) -> Result<Self::Bytes, error::Format>;

    /// Serializes the key to a PEM-encoded string.
    fn to_pem(&self) -> Result<Self::String, error::Format>;
}

/// Trait for key byte serialization and deserialization.
///
/// Provides methods for converting keys to and from raw bytes and hex strings.
/// All key types should implement this trait for basic serialization support.
pub trait KeySerialization: Sized {
    type Bytes: AsRef<[u8]> + From<Vec<u8>>;
    type String: AsRef<str> + From<String>;
    /// Returns an owned copy of the key's raw bytes.
    fn to_bytes(&self) -> Self::Bytes;

    /// Serializes the key to a hex-encoded string.
    fn to_bytes_hex(&self) -> Self::String {
        hex::encode(self.to_bytes()).into()
    }

    /// Deserializes a key from raw bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, error::Format>;

    /// Deserializes a key from a hex-encoded string.
    fn from_bytes_hex(str: &str) -> Result<Self, error::Format> {
        let bytes = hex::decode(str).map_err(|e| error::Format::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Trait for public key implementation.
///
/// Public keys are used to verify signatures created by the corresponding
/// private key. They are safe to share and are typically embedded in tokens.
pub trait PublicKeyImpl: KeySerialization<Bytes = Vec<u8>, String = String> {
    /// Verifies a signature against this public key.
    ///
    /// Returns `Ok(())` if the signature is valid for the given data,
    /// or an error if verification fails.
    fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<(), error::Format>;

    /// Returns the algorithm identifier for this key.
    fn algorithm(&self) -> crate::format::schema::public_key::Algorithm;
}

/// Trait for private key implementation.
///
/// Private keys are used to sign data and must be kept secret.
/// Each private key has a corresponding public key that can verify
/// its signatures.
pub trait PrivateKeyImpl:
    KeySerialization<Bytes = Zeroizing<Vec<u8>>, String = Zeroizing<String>>
{
    type PublicKey: PublicKeyImpl;

    /// Returns the public key corresponding to this private key.
    fn public(&self) -> Self::PublicKey;

    /// Returns the algorithm identifier for this key.
    fn algorithm(&self) -> crate::format::schema::public_key::Algorithm;
}

pub trait KeyPairImpl {
    type PublicKey: PublicKeyImpl;
    type PrivateKey: PrivateKeyImpl;

    /// Signs data with this private key.
    ///
    /// Returns the signature on success, or an error if signing fails.   
    fn sign(&self, data: &[u8]) -> Result<Signature, error::Format>;

    fn from_private(key: &Self::PrivateKey) -> Self;

    fn public(&self) -> Self::PublicKey;

    fn algorithm(&self) -> crate::format::schema::public_key::Algorithm;

    fn private(&self) -> Self::PrivateKey;

    /// Generates a new private key using the default OS random number generator.
    fn generate() -> Self;

    /// Generates a new private key using the provided random number generator.
    fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
}
