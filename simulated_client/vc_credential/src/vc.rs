
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use openmls_traits::{
    types::{CryptoError},
    signatures::{SignerError}
};

use serde_json::Value;
pub use ssi::did_resolve::DIDResolver;
pub use ssi::jwk::JWK;
pub use ssi::vc::{CredentialOrJWT, Credential, Presentation, LinkedDataProofOptions};
pub use ssi::ldp::now_ns;

use ssi::vc::derive_credential;
use crate::did_resolver::AACGKAResolver;

#[tokio::main]
pub async fn issue_vc(
    issuer_key: &JWK,
    resolver: &impl DIDResolver,
    vc: Value,
    verification_method: String,
)
    -> Result<Credential, SignerError> {

    let mut proof_options = LinkedDataProofOptions::default();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    let mut context_loader = ssi::jsonld::ContextLoader::default();

    let mut vc: ssi::vc::Credential = serde_json::from_value(vc).unwrap();
    let proof = futures::executor::block_on(async {
        vc
            .generate_proof(issuer_key, &proof_options, resolver, &mut context_loader)
            .await
    }).unwrap();
    vc.add_proof(proof);

    /*let stdout_writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(stdout_writer, &vc).unwrap();*/

    Ok(vc)
}
#[tokio::main]
pub async fn create_vp(
    key: &JWK,
    vp: Value,
    nonce: String,
    resolver: &impl DIDResolver
)
    -> Result<(Presentation, LinkedDataProofOptions), SignerError> {
    let mut context_loader = ssi::jsonld::ContextLoader::default();

    let mut proof_options = LinkedDataProofOptions::default();
    let verification_method = "did:example:subject#key2".to_string();
    proof_options.verification_method = Some(ssi::vc::URI::String(verification_method));
    proof_options.proof_purpose = Some(ssi::vc::ProofPurpose::Authentication);
    proof_options.challenge = Some("example".to_string());
    proof_options.nonce = Some(nonce);

    let mut vp: Presentation = serde_json::from_value(vp).unwrap();
    let proof = futures::executor::block_on(async {
        vp
            .generate_proof(&key, &proof_options, resolver, &mut context_loader).await
    }).unwrap();
    vp.add_proof(proof);

    //validate_vp(vp.clone(), proof_options.clone()).expect("");
    Ok((vp, proof_options))
}

pub fn get_selectors_from_requirement(
    req: Value,
) -> Result<Vec<String>, SignerError> {

    let first_level_selectors = req.as_object().unwrap().clone();
    if first_level_selectors.is_empty() {
        return Ok(vec![]);
    }

    let selectors = first_level_selectors.get("credentialSubject").unwrap().as_object().unwrap().clone();
    let selectors = selectors.keys().cloned().into_iter().collect();
    Ok(selectors)
}

#[tokio::main]
pub async fn create_derived_credential(
    //key: &JWK,
    vc: &Credential,
    selectors: Vec<String>,
    nonce: String,
    resolver: &impl DIDResolver
)
    -> Result<(Credential, LinkedDataProofOptions), SignerError> {
    let mut context_loader = ssi::jsonld::ContextLoader::default();
    let derived_vc = futures::executor::block_on(async {
        derive_credential(vc, nonce.clone().as_str(), selectors.as_slice(), resolver)
            .await
    }).unwrap();
    //println!("{}", serde_json::to_string_pretty(&derived_vc).unwrap());

    let positions = futures::executor::block_on(async {
        vc
            .get_nquad_positions(selectors.as_slice(), &mut context_loader)
            .await
    }).unwrap();

    let verify_options = LinkedDataProofOptions {
        nonce: Some(String::from(nonce)),
        disclosed_message_indices: Some(positions.into_iter().map(|x| x as usize).collect()),
        ..Default::default()
    };

    Ok((derived_vc,verify_options))
}

pub fn load_key(key_str: &str) -> Result<JWK, SignerError> {
    let key: JWK = serde_json::from_str(key_str).unwrap();

    Ok(key)
}

pub fn load_vc(vc_str: &str) -> Result<CredentialOrJWT, SignerError> {
    let vc_ldp = serde_json::from_str(vc_str).unwrap();
    let vc = CredentialOrJWT::Credential(vc_ldp);

    Ok(vc)
}

#[tokio::main]
pub async fn validate_vp(
    vp: Presentation,
    proof_options: LinkedDataProofOptions,
) -> Result<(), CryptoError> {

    let resolver = AACGKAResolver;
    let mut context_loader = ssi::jsonld::ContextLoader::default();

    for item in vp.verifiable_credential.clone().unwrap() {
        //log::info!("Validating VC in VP... ");
        match item {
            CredentialOrJWT::Credential(vc) => {
                //log::info!("{:#?}", vc);
                let result = futures::executor::block_on(async {
                    vc.verify(None, &resolver, &mut context_loader).await
                });

                if !result.errors.is_empty() {
                    return Err(CryptoError::InvalidSignature);
                }
            },
            CredentialOrJWT::JWT(_) => {
                unimplemented!();
            }
        }
        //println!("Done.");
    }

    //log::info!("\t\tValidating VP's signature... ");
    //let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = futures::executor::block_on(async {
        vp.verify(Some(proof_options.clone()), &resolver, &mut context_loader).await
    });

    if !result.errors.is_empty() {
        return Err(CryptoError::InvalidSignature);
    }
    //println!("Done.");

    Ok(())
}

#[tokio::main]
pub async fn validate_bbs_vc(
    vc: Credential,
    proof_options: LinkedDataProofOptions,
) -> Result<(), CryptoError> {

    let resolver = AACGKAResolver;
    let mut context_loader = ssi::jsonld::ContextLoader::default();

    //log::info!("\t\tValidating VP's signature... ");
    //let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");
    let result = futures::executor::block_on(async {
        vc.verify(Some(proof_options.clone()), &resolver, &mut context_loader).await
    });

    if !result.errors.is_empty() {
        return Err(CryptoError::InvalidSignature);
    }
    //println!("Done.");

    Ok(())
}

pub fn pk_to_nonce(
    pk: &[u8]
) -> String {
    let mut pk_to_edit = pk.to_owned();
    if pk_to_edit[0] > 0x70 {
        pk_to_edit[0] = 0x70;
    }
    BASE64_STANDARD.encode(pk_to_edit)
}
