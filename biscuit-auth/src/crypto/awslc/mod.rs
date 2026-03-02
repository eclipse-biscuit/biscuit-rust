pub mod ed25519;
pub mod secp256r1;

#[cfg(feature = "pem")]
use crate::error::Format;
#[cfg(feature = "pem")]
use aws_lc_rs::signature::ParsedPublicKey;

/// Trait for aws-lc-rs public key types that can produce a ParsedPublicKey for DER export.
#[cfg(feature = "pem")]
pub(crate) trait AwsLcPublicKey: crate::crypto::KeySerialization<Bytes = Vec<u8>> {
    fn parsed(&self) -> Result<ParsedPublicKey, Format>;
}

#[cfg(feature = "pem")]
impl<T> crate::crypto::KeyPemSerialization for T
where
    T: AwsLcPublicKey + crate::crypto::KeySerialization<Bytes = Vec<u8>, String = String>,
{
    fn from_der(bytes: &[u8]) -> Result<Self, Format> {
        use pkcs8::der::Decode;
        use pkcs8::spki::SubjectPublicKeyInfoRef;
        let spki = SubjectPublicKeyInfoRef::from_der(bytes)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        Self::from_bytes(spki.subject_public_key.raw_bytes())
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)
    }

    fn from_pem(str: &str) -> Result<Self, Format> {
        use pkcs8::spki::Document;
        let (label, doc) = Document::from_pem(str)
            .map_err(|e| e.to_string())
            .map_err(Format::InvalidKey)?;
        if label != "PUBLIC KEY" {
            return Err(Format::InvalidKey(format!(
                "unexpected PEM label: expected \"PUBLIC KEY\", got \"{label}\""
            )));
        }
        Self::from_der(doc.as_ref())
    }

    fn to_der(&self) -> Result<Self::Bytes, Format> {
        use aws_lc_rs::encoding::AsDer;
        let parsed = self.parsed()?;
        let der = parsed
            .as_der()
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)?;
        Ok(der.as_ref().to_vec())
    }

    fn to_pem(&self) -> Result<Self::String, Format> {
        use pkcs8::der::pem::encode_string;
        use pkcs8::der::pem::LineEnding;
        let der = self.to_der()?;
        encode_string("PUBLIC KEY", LineEnding::LF, &der)
            .map_err(|e| e.to_string())
            .map_err(Format::PKCS8)
    }
}
