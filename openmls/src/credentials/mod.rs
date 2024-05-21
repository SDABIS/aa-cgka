//! # Credentials
//!
//! A [`Credential`] contains identifying information about the client that
//! created it. [`Credential`]s represent clients in MLS groups and are
//! used to authenticate their messages. Each
//! [`KeyPackage`](crate::key_packages::KeyPackage) as well as each client (leaf node)
//! in the group (tree) contains a [`Credential`] and is authenticated.
//! The [`Credential`] must the be checked by an authentication server and the
//! application, which is out of scope of MLS.
//!
//! Clients can create a [`Credential`].
//!
//! The MLS protocol spec allows the [`Credential`] that represents a client in a group to
//! change over time. Concretely, members can issue an Update proposal or a Full
//! Commit to update their [`LeafNode`](crate::treesync::LeafNode), as
//! well as the [`Credential`] in it. The Update has to be authenticated by the
//! signature public key corresponding to the old [`Credential`].
//!
//! When receiving a credential update from another member, applications must
//! query the Authentication Service to ensure that the new credential is valid.
//!
//! There are multiple [`CredentialType`]s, although OpenMLS currently only
//! supports the [`BasicCredential`].

use std::io::{Read, Write};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, VLBytes};
use openmls_vc_credential::{Presentation, LinkedDataProofOptions};

// Private
mod codec;
#[cfg(test)]
mod tests;
use errors::*;
use openmls_vc_credential::sdjwt::{SDJWTManager, SDJWTProofOptions};
use openmls_vc_credential::vc::pk_to_nonce;


use crate::ciphersuite::{SignaturePublicKey};
use crate::extensions::SsiVcRequirementsExtension;

// Public
pub mod errors;

/// CredentialType.
///
/// This enum contains variants for the different Credential Types.
///
/// ```c
/// // See IANA registry for registered values
/// uint16 CredentialType;
/// ```
///
/// **IANA Considerations**
///
/// | Value            | Name                     | R | Ref      |
/// |:-----------------|:-------------------------|:--|:---------|
/// | 0x0000           | RESERVED                 | - | RFC XXXX |
/// | 0x0001           | basic                    | Y | RFC XXXX |
/// | 0x0002           | x509                     | Y | RFC XXXX |
/// | 0x0A0A           | GREASE                   | Y | RFC XXXX |
/// | 0x1A1A           | GREASE                   | Y | RFC XXXX |
/// | 0x2A2A           | GREASE                   | Y | RFC XXXX |
/// | 0x3A3A           | GREASE                   | Y | RFC XXXX |
/// | 0x4A4A           | GREASE                   | Y | RFC XXXX |
/// | 0x5A5A           | GREASE                   | Y | RFC XXXX |
/// | 0x6A6A           | GREASE                   | Y | RFC XXXX |
/// | 0x7A7A           | GREASE                   | Y | RFC XXXX |
/// | 0x8A8A           | GREASE                   | Y | RFC XXXX |
/// | 0x9A9A           | GREASE                   | Y | RFC XXXX |
/// | 0xAAAA           | GREASE                   | Y | RFC XXXX |
/// | 0xBABA           | GREASE                   | Y | RFC XXXX |
/// | 0xCACA           | GREASE                   | Y | RFC XXXX |
/// | 0xDADA           | GREASE                   | Y | RFC XXXX |
/// | 0xEAEA           | GREASE                   | Y | RFC XXXX |
/// | 0xF000  - 0xFFFF | Reserved for Private Use | - | RFC XXXX |
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CredentialType {
    /// A [`BasicCredential`]
    Basic,
    /// An X.509 [`Certificate`]
    X509,
    /// W3C's [`Verifiable Credentials`]
    VC,
    SDJWT,
    BBSVC,
    /// A currently unknown credential.
    Unknown(u16),
}

impl tls_codec::Size for CredentialType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl tls_codec::Deserialize for CredentialType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let mut extension_type = [0u8; 2];
        bytes.read_exact(&mut extension_type)?;

        Ok(CredentialType::from(u16::from_be_bytes(extension_type)))
    }
}

impl tls_codec::Serialize for CredentialType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl From<u16> for CredentialType {
    fn from(value: u16) -> Self {
        match value {
            1 => CredentialType::Basic,
            2 => CredentialType::X509,
            3 => CredentialType::VC,
            4 => CredentialType::SDJWT,
            5 => CredentialType::BBSVC,
            unknown => CredentialType::Unknown(unknown),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(value: CredentialType) -> Self {
        match value {
            CredentialType::Basic => 1,
            CredentialType::X509 => 2,
            CredentialType::VC => 3,
            CredentialType::SDJWT => 4,
            CredentialType::BBSVC => 5,
            CredentialType::Unknown(unknown) => unknown,
        }
    }
}

/// X.509 Certificate.
///
/// This struct contains an X.509 certificate chain.  Note that X.509
/// certificates are not yet supported by OpenMLS.
///
/// ```c
/// struct {
///     opaque cert_data<V>;
/// } Certificate;
/// ```
#[derive(
Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct Certificate {
    cert_data: VLBytes,
}

#[derive(
Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ProofOptions {
    proof_options: VLBytes,
}

/// MlsCredentialType.
///
/// This enum contains variants containing the different available credentials.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum MlsCredentialType {
    /// A [`BasicCredential`]
    Basic(BasicCredential),
    /// An X.509 [`Certificate`]
    X509(Certificate),
    VC(BasicCredential, Certificate, ProofOptions),
    SDJWT(BasicCredential, Certificate, ProofOptions),
    BBSVC(BasicCredential, Certificate, ProofOptions),
}

/// Credential.
///
/// This struct contains MLS credential data, where the data depends on the
/// type. The [`CredentialType`] always matches the [`MlsCredentialType`].
///
/// ```c
/// struct {
///     CredentialType credential_type;
///     select (Credential.credential_type) {
///         case basic:
///             opaque identity<V>;
///
///         case x509:
///             Certificate chain<V>;
///     };
/// } Credential;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Credential {
    credential_type: CredentialType,
    credential: MlsCredentialType,
}

impl Credential {
    /// Returns the credential type.
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    /// Creates and returns a new [`Credential`] of the given
    /// [`CredentialType`] for the given identity.
    /// If the credential holds key material, this is generated and stored in
    /// the key store.
    ///
    /// Returns an error if the given [`CredentialType`] is not supported.
    pub fn new(
        identity: Vec<u8>,
        credential_type: CredentialType,
    ) -> Result<Self, CredentialError> {
        let mls_credential = match credential_type {
            CredentialType::Basic => MlsCredentialType::Basic(BasicCredential {
                identity: identity.into(),
            }),
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: mls_credential,
        };
        Ok(credential)
    }

    pub fn new_from_vp(
        name: String,
        identity: &Presentation,
        proof_options: &LinkedDataProofOptions,
        credential_type: CredentialType,
    ) -> Result<Self, CredentialError> {
        let mls_credential = match credential_type {
            CredentialType::VC => MlsCredentialType::VC(
                BasicCredential {identity: name.into_bytes().into()},
                Certificate {
                    cert_data: serde_json::to_vec(&identity)
                        .map_err(|_| CredentialError::InvalidCredential)?
                        .into(),
                },
                ProofOptions {
                    proof_options: serde_json::to_vec(&proof_options)
                        .map_err(|_| CredentialError::InvalidCredential)?
                        .into(),
                }),
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: mls_credential,
        };
        Ok(credential)
    }

    pub fn new_from_bbs_vc(
        name: String,
        identity: &openmls_vc_credential::Credential,
        proof_options: &LinkedDataProofOptions,
        credential_type: CredentialType,
    ) -> Result<Self, CredentialError> {
        let mls_credential = match credential_type {
            CredentialType::BBSVC => MlsCredentialType::BBSVC(
                BasicCredential {identity: name.into_bytes().into()},
                Certificate {
                    cert_data: serde_json::to_vec(&identity)
                        .map_err(|_| CredentialError::InvalidCredential)?
                        .into(),
                },
                ProofOptions {
                    proof_options: serde_json::to_vec(&proof_options)
                        .map_err(|_| CredentialError::InvalidCredential)?
                        .into(),
                }),
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: mls_credential,
        };
        Ok(credential)
    }

    pub fn new_from_sd_jwt(
        name: String,
        identity: String,
        proof_options: &SDJWTProofOptions,
        credential_type: CredentialType,
    ) -> Result<Self, CredentialError> {
        let mls_credential = match credential_type {
            CredentialType::SDJWT => MlsCredentialType::SDJWT(
                BasicCredential {identity: name.into_bytes().into()},
                Certificate {
                    cert_data: serde_json::to_vec(&identity)
                        .map_err(|_| CredentialError::InvalidCredential)?
                        .into(),
                },
                ProofOptions {
                    proof_options: serde_json::to_vec(&proof_options)
                        .map_err(|_| CredentialError::InvalidCredential)?
                        .into(),
                }),
            _ => return Err(CredentialError::UnsupportedCredentialType),
        };
        let credential = Credential {
            credential_type,
            credential: mls_credential,
        };
        Ok(credential)
    }

    /// Returns the identity of a given credential.
    pub fn identity(&self) -> &[u8] {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => basic_credential.identity.as_slice(),
            // TODO: implement getter for identity for X509 certificates. See issue #134.
            MlsCredentialType::X509(_) => panic!("X509 certificates are not yet implemented."),
            MlsCredentialType::VC(name, _, _) => name.identity.as_slice(),
            MlsCredentialType::SDJWT(name, _, _) => name.identity.as_slice(),
            MlsCredentialType::BBSVC(name, _, _) => name.identity.as_slice(),
        }
    }

}

impl From<MlsCredentialType> for Credential {
    fn from(mls_credential_type: MlsCredentialType) -> Self {
        Credential {
            credential_type: match mls_credential_type {
                MlsCredentialType::Basic(_) => CredentialType::Basic,
                MlsCredentialType::X509(_) => CredentialType::X509,
                MlsCredentialType::VC(..) => CredentialType::VC,
                MlsCredentialType::SDJWT(..) => CredentialType::SDJWT,
                MlsCredentialType::BBSVC(..) => CredentialType::BBSVC,
            },
            credential: mls_credential_type,
        }
    }
}

/// Basic Credential.
///
/// A `BasicCredential` as defined in the MLS protocol spec. It exposes only an
/// `identity` to represent the client.
///
/// Note that this credential does not contain any key material or any other
/// information.
///
/// OpenMLS provides an implementation of signature keys for convenience in the
/// `openmls_basic_credential` crate.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct BasicCredential {
    identity: VLBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A wrapper around a credential with a corresponding public key.
pub struct CredentialWithKey {
    /// The [`Credential`].
    pub credential: Credential,
    /// The corresponding public key as [`SignaturePublicKey`].
    pub signature_key: SignaturePublicKey,
}

impl CredentialWithKey {
    pub fn from_parts(credential: Credential, key: &[u8]) -> Self {
        Self {
            credential,
            signature_key: key.into(),
        }
    }

    pub fn validate(&self) -> Result<(), CredentialError> {
        match &self.credential.credential {
            MlsCredentialType::Basic(_) => {
                Ok(())
            }
            MlsCredentialType::X509(_) => {
                unimplemented!();
            }
            MlsCredentialType::VC(_, cert, proof_options) => {
                log::info!("\t\tType: Verifiable Credential (VC)");
                let vp: Presentation = serde_json::from_slice(cert.cert_data.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;
                let ldpo: LinkedDataProofOptions = serde_json::from_slice(proof_options.proof_options.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;

                //Validate PK???
                openmls_vc_credential::vc::validate_vp(
                    vp.clone(),
                    ldpo.clone(),
                    &self.signature_key.as_slice().into())
                        .map_err(|_| CredentialError::InvalidCredential)

            },
            MlsCredentialType::SDJWT(_, cert, proof_options) => {
                log::info!("\t\tType: JWT with Selective Disclosure (SD_JWT)");
                let presentation: String = serde_json::from_slice(cert.cert_data.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;
                let sd_jwt_proof_options: SDJWTProofOptions = serde_json::from_slice(proof_options.proof_options.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;
                let manager = SDJWTManager::new(None, None);
                manager.verify(presentation, sd_jwt_proof_options.clone()).map_err(|_| CredentialError::InvalidCredential)?;

                let decoded_pk = BASE64_STANDARD.decode(sd_jwt_proof_options.nonce)
                    .map_err(|_| CredentialError::InvalidCredential)?;

                if decoded_pk != self.signature_key.as_slice() {
                    return Err(CredentialError::InvalidCredential)
                }
                Ok(())
            },
            MlsCredentialType::BBSVC(_, cert, proof_options) => {
                log::info!("\t\tType: VC with BBS+ signature (BBS_VC)");
                let vc: openmls_vc_credential::Credential = serde_json::from_slice(cert.cert_data.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;
                let ldpo: LinkedDataProofOptions = serde_json::from_slice(proof_options.proof_options.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;

                //Validate PK???
                let decoded_pk = ldpo.clone().nonce.unwrap_or("".to_string());

                if decoded_pk != pk_to_nonce(self.signature_key.as_slice()) {
                    return Err(CredentialError::InvalidCredential)
                }

                openmls_vc_credential::vc::validate_bbs_vc(
                    vc.clone(),
                    ldpo.clone())
                    .map_err(|_| CredentialError::InvalidCredential)
            },
        }
    }

    pub(crate) fn check_requirements(&self, requirements: &SsiVcRequirementsExtension)
    -> Result<(), CredentialError> {
        match &self.credential.credential {
            MlsCredentialType::VC(_, cert, _) => {
                let vp: Presentation = serde_json::from_slice(cert.cert_data.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;

                for requirement in requirements {
                    requirement.match_requirement_vp(&vp)?;
                }
                Ok(())
            },
            MlsCredentialType::SDJWT(_, cert, proof_options) => {
                let presentation: String = serde_json::from_slice(cert.cert_data.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;
                let sd_jwt_proof_options: SDJWTProofOptions = serde_json::from_slice(proof_options.proof_options.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;

                //log::info!("{}", presentation);

                let manager = SDJWTManager::new(None, None);
                let disclosed_claims = manager.verify(presentation.clone(), sd_jwt_proof_options).expect("Error verifying presentation");
                for requirement in requirements {
                    requirement.match_requirement_sd_jwt(disclosed_claims.clone())?;
                }
                Ok(())
            },
            MlsCredentialType::BBSVC(_, cert, _) => {
                let vc: openmls_vc_credential::Credential = serde_json::from_slice(cert.cert_data.as_slice())
                    .map_err(|_| CredentialError::InvalidCredential)?;

                for requirement in requirements {
                    requirement.match_requirement_bbs_vc(&vc)?;
                }
                Ok(())
            },
            _ => {
                if requirements.is_empty() {
                    Ok(())
                }
                else {
                    Err(CredentialError::UnsupportedCredentialType)
                }
            }
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::{types::SignatureScheme, OpenMlsProvider};

    use super::{Credential, CredentialType, CredentialWithKey};

    /// Convenience function that generates a new credential and a key pair for
    /// it (using the basic credential crate).
    /// The signature keys are stored in the key store.
    ///
    /// Returns the [`Credential`] and the [`SignatureKeyPair`].
    pub fn new_credential(
        provider: &impl OpenMlsProvider,
        identity: &[u8],
        credential_type: CredentialType,
        signature_scheme: SignatureScheme,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let credential = Credential::new(identity.into(), credential_type).unwrap();
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys.store(provider.key_store()).unwrap();

        (
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
            signature_keys,
        )
    }
}
