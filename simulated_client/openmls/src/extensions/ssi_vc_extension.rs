use serde::{Deserialize, Serialize};
use serde_json::Value;
use tls_codec::{VLBytes, TlsDeserialize, TlsSerialize, TlsSize};
use assert_json_diff::*;
use std::str;

use crate::prelude::CredentialError;
use openmls_vc_credential::Presentation;

/// ExternalSender
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///   SignaturePublicKey signature_key;
///   Credential credential;
/// } ExternalSender;
/// ```
#[derive(
Clone, PartialEq, Eq, Debug, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]

// TODO: Define the values inside this structure
pub struct SsiVcRequirement {
    pub(crate) requirement: VLBytes
}

impl SsiVcRequirement {
    /// Creates a new `ExternalSender` instance.
    pub fn new(requirement: Value) -> Result<Self, CredentialError> {
        Ok(Self {
            requirement: serde_json::to_vec(&requirement)
                .map_err(|_| CredentialError::InvalidCredential)?
                .into()
        })
    }

    pub fn get_requirement(&self) -> Value {
        serde_json::from_slice(self.requirement.as_slice())
            .expect("Error with requirement")
    }

    pub fn match_requirement_vp(&self, vp: &Presentation) -> Result<(), CredentialError> {
        let serialized_vc_list = serde_json::to_value(
            vp.verifiable_credential.clone().unwrap().into_iter().collect::<Vec<_>>())
            .map_err(|_| CredentialError::InvalidCredential)?;
        /*let requirement_str = str::from_utf8(&self.requirement)
            .map_err(|_| CredentialError::InvalidCredential)?;

        let serialized_requirement = serde_json::from_str(requirement_str).map_err(|_| CredentialError::InvalidCredential)?;*/
        let mut requirement_in_brackets = "[".to_string();
        requirement_in_brackets.push_str(
            std::str::from_utf8(self.requirement.as_slice()).expect("Error with requirement"));
        requirement_in_brackets.push_str("]");

        let serialized_requirement: Value = serde_json::from_str(requirement_in_brackets.as_str())
            .expect("Error with requirement");

        //log::info!("{:?}", serialized_vc_list);
        //log::info!("{:?}", serialized_requirement);
        //log::info!("{:?}", requirement_str);

        let result = assert_json_matches_no_panic(
            &serialized_vc_list,
            &serialized_requirement,
            Config::new(CompareMode::Inclusive))
            .map_err(|e| {
                log::info!("{}", e);
                CredentialError::InvalidCredential
            })?;

        //log::info!("Correct. \n");

        Ok(result)
    }

    pub fn match_requirement_sd_jwt(&self, presentation: Value) -> Result<(), CredentialError> {

        let serialized_requirement: Value = serde_json::from_slice(self.requirement.as_slice())
            .expect("Error with requirement");
        //log::info!("{}", serde_json::to_string_pretty(&presentation).unwrap());
        //log::info!("{:?}", serialized_requirement);

        let result = assert_json_matches_no_panic(
            &presentation,
            &serialized_requirement,
            Config::new(CompareMode::Inclusive))
            .map_err(|e| {
                log::info!("{}", e);
                CredentialError::InvalidCredential
            })?;

        //log::info!("Correct. \n");

        Ok(result)
    }

    pub fn match_requirement_bbs_vc(&self, vc: &openmls_vc_credential::Credential) -> Result<(), CredentialError> {
        let serialized_vc = serde_json::to_value(vc)
            .map_err(|_| CredentialError::InvalidCredential)?;
        let requirement_str = str::from_utf8(&self.requirement.as_slice())
            .map_err(|_| CredentialError::InvalidCredential)?;

        let serialized_requirement: Value = serde_json::from_str(requirement_str).map_err(|_| CredentialError::InvalidCredential)?;

        //log::info!("{}",serde_json::to_string_pretty(&serialized_vc).unwrap());
        //log::info!("{:?}", serialized_vc);

        let result = assert_json_matches_no_panic(
            &serialized_vc,
            &serialized_requirement,
            Config::new(CompareMode::Inclusive))
            .map_err(|e| {
                log::info!("{}", e);
                CredentialError::InvalidCredential
            })?;

        //log::info!("Correct. \n");

        Ok(result)
    }

}

impl Default for SsiVcRequirement {
    fn default() -> Self {
        SsiVcRequirement::new(serde_json::from_str("{}").unwrap()).unwrap()
    }
}

pub type SsiVcRequirementsExtension = Vec<SsiVcRequirement>;
