//! # Basic Credential
//!
//! An implementation of the basic credential from the MLS spec.
//!
//! For now this credential uses only RustCrypto.

pub mod sdjwt;
pub mod vc;
pub mod did_resolver;

use core::fmt::Debug;
use openmls_traits::{
    signatures::Signer,
    storage::{self, StorageProvider, CURRENT_VERSION},
    types::{CryptoError, SignatureScheme},
};

use p256::ecdsa::{signature::Signer as P256Signer, Signature, SigningKey};

pub use ssi::did_resolve::DIDResolver;
pub use ssi::jwk::JWK;
pub use ssi::vc::{CredentialOrJWT, Credential, Presentation, LinkedDataProofOptions};

use ssi::jwk::{Params as JWKParams};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};
use openmls_basic_credential::{SignatureKeyPair, StorageId};
use openmls_traits::signatures::SignerError;

/// A signature key pair for the basic credential.
///
/// This can be used as keys to implement the MLS basic credential. It is a simple
/// private and public key pair with corresponding signature scheme.
#[derive(TlsSerialize, TlsSize, TlsDeserialize, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "clonable", derive(Clone))]
pub struct VCIdentity {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
    pub signature_scheme: SignatureScheme,
}

impl Debug for VCIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("key", &"***".to_string())
            .field("signature_scheme", &self.signature_scheme)
            .finish()
    }
}

impl Signer for VCIdentity {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {

        match self.signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = SigningKey::from_bytes(self.private.as_slice().into())
                    .map_err(|_| SignerError::SigningError)?;
                let signature: Signature = k.sign(payload);
                Ok(signature.to_der().to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::try_from(self.private.as_slice())
                    .map_err(|_| SignerError::SigningError)?;
                let signature = k.sign(payload);
                Ok(signature.to_bytes().into())
            }
            _ => Err(SignerError::SigningError),
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}

impl From<VCIdentity> for SignatureKeyPair {
    fn from(vci: VCIdentity) -> Self {
        SignatureKeyPair::from_raw(vci.signature_scheme, vci.private, vci.public)
    }
}

/// Compute the ID for a [`Signature`] in the key store.
fn id(public_key: &[u8], signature_scheme: SignatureScheme) -> Vec<u8> {
    const LABEL: &[u8; 22] = b"RustCryptoSignatureKey";
    let mut id = public_key.to_vec();
    id.extend_from_slice(LABEL);
    let signature_scheme = (signature_scheme as u16).to_be_bytes();
    id.extend_from_slice(&signature_scheme);
    id
}

/*impl MlsEntity for VCIdentity {
    const ID: MlsEntityId = MlsEntityId::SignatureKeyPair;
}*/

impl VCIdentity {
    pub fn new(key: &JWK, signature_scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (private, public) = match &key.params {
            JWKParams::EC(ec) => match signature_scheme {
                SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                    let secret_key = p256::SecretKey::try_from(ec)
                        .map_err(|_| CryptoError::CryptoLibraryError)?;
                    let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                    let pk = signing_key.verifying_key().to_encoded_point(false).as_bytes().into();
                    (signing_key.to_bytes().as_slice().into(), pk)
                },
                _ => panic!("Not implemented.")
            },
            JWKParams::OKP(okp) => match signature_scheme {
                SignatureScheme::ED25519 => {
                    let sk = ed25519_dalek::SigningKey::try_from(okp)
                        .map_err(|_| CryptoError::CryptoLibraryError)?;
                    let pk = sk.verifying_key().to_bytes().into();
                    (sk.to_bytes().into(), pk)
                },
                _ => panic!("Not implemented.")
            },
            _ => panic!("Not implemented.")
        };

        Ok(Self {
            private,
            public,
            signature_scheme,
        })
    }

    /// Create a new signature key pair from the raw keys.
    pub fn from_raw(signature_scheme: SignatureScheme, private: Vec<u8>, public: Vec<u8>) -> Self {
        Self {
            private,
            public,
            signature_scheme,
        }
    }

    pub fn id(&self) -> StorageId {
        StorageId {
            value: id(&self.public, self.signature_scheme),
        }
    }

    /// Store this signature key pair in the key store.
    pub fn store<T>(&self, store: &T) -> Result<(), T::Error>
        where
            T: StorageProvider<CURRENT_VERSION>,
    {
        store.write_signature_key_pair(&self.id(), self)
    }

    /// Read a signature key pair from the key store.
    pub fn read(
        store: &impl StorageProvider<CURRENT_VERSION>,
        public_key: &[u8],
        signature_scheme: SignatureScheme,
    ) -> Option<Self> {
        store
            .signature_key_pair(&StorageId {
                value: id(public_key, signature_scheme),
            })
            .ok()
            .flatten()
    }

    /// Get the public key as byte slice.
    pub fn public(&self) -> &[u8] {
        self.public.as_ref()
    }

    /// Get the public key as byte vector.
    pub fn to_public_vec(&self) -> Vec<u8> {
        self.public.clone()
    }

    /// Get the [`SignatureScheme`] of this signature key.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    #[cfg(feature = "test-utils")]
    pub fn private(&self) -> &[u8] {
        &self.private
    }
}

// Implement entity trait for the signature key pair
impl storage::Entity<CURRENT_VERSION> for VCIdentity {}
impl storage::traits::SignatureKeyPair<CURRENT_VERSION> for VCIdentity {}