use super::Signature;
use crate::{error, Algorithm};
// so we can link to this in cargo docs.
#[cfg(doc)]
use crate::BiscuitBuilder;

/// A trait for signing arbitrary byte inputs with biscuit-compatible
/// [algorithms](Algorithm).
///
/// Instances of `Signer` may be used with [BiscuitBuilder] as root keys.
pub trait Signer {
    /// The algorithm used.  Must match the signature returned via [sign](Self::sign).
    fn algorithm(&self) -> Algorithm;
    /// Sign a series of bytes, returning a signature.  This signature must match
    /// what [self.algorithm()](Self::algorithm) returns.  Any incorrect values
    /// will likely result in invalid tokens.
    fn sign(&self, data: &[u8]) -> Result<Signature, error::Format>;
}
