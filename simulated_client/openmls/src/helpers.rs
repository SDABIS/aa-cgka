
use crate::prelude::*;

use base64::Engine;
use base64::prelude::*;
use openmls_vc_credential::{DIDResolver, JWK};
use openmls_basic_credential::SignatureKeyPair;
use openmls_vc_credential::sdjwt::{SDJWTManager, SDJWTProofOptions};
use openmls_vc_credential::vc::{create_vp, create_derived_credential, get_selectors_from_requirement, pk_to_nonce};
use crate::extensions::ExtensionType::SsiVcRequirements;
use crate::prelude::ProposalType::{AddReqs, RemoveReqs, UpdateReqs};

pub fn create_group_config_with_requirement(
    requirement: Option<SsiVcRequirement>,
) -> MlsGroupCreateConfig {
   /* let requirement = SsiVcRequirement::new(requirement_value)
        .expect("Error creating Requirement");*/
    let mut ssi_vc_requirements = SsiVcRequirementsExtension::new();
    
    if let Some(req) = requirement {
        ssi_vc_requirements.push(req);
    }

    let required_capabilities = RequiredCapabilitiesExtension::new(
        &[SsiVcRequirements],
        &[AddReqs, UpdateReqs, RemoveReqs],
        &[CredentialType::Basic, CredentialType::VC, CredentialType::SDJWT, CredentialType::BBSVC]
    );

    let mut extensions = vec![];
    extensions.push(Extension::RequiredCapabilities(required_capabilities));
    extensions.push(Extension::SsiVcRequirements(ssi_vc_requirements));

    MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(
            Extensions::from_vec(extensions).unwrap()
        ).unwrap()
        .build()
}

/*pub fn message_out_to_group_info(
    out: &MlsMessageOut
) -> Result<VerifiableGroupInfo, Error> {
    let msg =  MlsMessageIn::tls_deserialize(
        &mut out.tls_serialize_detached()
            .map_err(|_| Error)?
            .as_slice()
    )
        .map_err(|_| Error)?;

    match msg.extract() {
        MlsMessageBodyIn::GroupInfo(gi) => Ok(gi.into()),
        _ => Err(Error)
    }
}*/

pub fn parse_in_message(
    mls_message_in: ProtocolMessage,
    group: &mut MlsGroup,
    backend: &impl OpenMlsProvider,
) -> String {

    let processed_message = group.process_message(
        backend,
        mls_message_in
    ).expect("Error processing message");
    let content = processed_message.into_content();

    match content {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            String::from_utf8(app_msg.into_bytes())
                .expect("Error reading application message")
        },
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            let _result = group.merge_staged_commit(backend, *commit)
                .expect("Error processing commit");
            "Processed Commit".to_string()
        }
        _ => panic!("AAA")
    }
}

/*pub fn message_out_to_in(
    out: &MlsMessageOut
) -> Result<ProtocolMessage, Error> {
    let msg =  MlsMessageIn::tls_deserialize(
        &mut out.tls_serialize_detached()
            .map_err(|_| Error)?
            .as_slice()
    )
        .map_err(|_| Error)?;
    match msg.extract() {
        MlsMessageBodyIn::PublicMessage(pm) => Ok(pm.into()),
        MlsMessageBodyIn::PrivateMessage(pm) => Ok(pm.into()),
        _ => {
            Err(Error)
        }
    }
}*/

pub fn generate_basic_credential_with_key(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,

) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(CredentialType::Basic, identity);


    // Store the signature key into the key store so OpenMLS has access
    // to it.
    let signature_keys = SignatureKeyPair::new( signature_algorithm)
        .expect("Error generating a signature key pair.");

    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys in key store.");

    (
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

pub fn generate_vc_credential_with_key(
    name: String,
    identity: &openmls_vc_credential::Credential,
    holder_key: &JWK,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
    resolver: &impl DIDResolver
) -> Result<(CredentialWithKey, SignatureKeyPair), CredentialError> {
    let vp = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": "VerifiablePresentation",
        "holder": "did:example:subject",
        "verifiableCredential": identity
    });

    let signature_keys = SignatureKeyPair::new(signature_algorithm)
        .map_err(|e| CredentialError::LibraryError(LibraryError::unexpected_crypto_error(e)))?;

    signature_keys
        .store(provider.storage())
        .expect("Error storing keys");

    let encoded_pk= pk_to_nonce(signature_keys.public());

    //log::info!("[*] Generating Verifiable Presentation");
    //log::info!("\tHolder Key: {:?}", charlie_key);
    let (vp,proof_options) = create_vp(
        holder_key,
        vp,
        encoded_pk,
        resolver)
    .expect("Error creating VP");
    //log::info!("\tDone. VP: {:?}\n", vp);

    /*let signature_keys = SignatureKeyPair::new( signature_algorithm)
        .expect("Error generating a signature key pair.");

    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys in key store.");*/

    let credential = Credential::new_from_vp(name, &vp, &proof_options)?;

    Ok((
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys.into(),
    ))
}

pub fn generate_sd_jwt_credential_with_key(
    name: String,
    cred_jwt: String,
    requirement: &SsiVcRequirement,
    signature_algorithm: SignatureScheme,
    holder_key_bytes: &[u8],
    issuer_pk: &[u8],
    provider: &impl OpenMlsProvider,
) -> Result<(CredentialWithKey, SignatureKeyPair), CredentialError> {

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    let signature_keys = SignatureKeyPair::new( signature_algorithm)
        .expect("Error generating a signature key pair.");

    signature_keys
        .store(provider.storage())
        .expect("Error storing keys");

    let encoded_pk= BASE64_STANDARD.encode(signature_keys.public());

    let proof_options = SDJWTProofOptions {
        issuer_pk: issuer_pk.to_vec().into(),
        audience: "CGKA Group".to_string(),
        nonce: encoded_pk.clone(),
    };
    let manager = SDJWTManager::new(None, None);
    let presentation = manager.present(
        cred_jwt.clone(),
        requirement.get_requirement().as_object().unwrap().clone(),
        proof_options.clone().audience,
        holder_key_bytes,
        encoded_pk,
    ).map_err(|_| CredentialError::InvalidCredential)?;

    //log::info!("{:?}", requirement.get_requirement());
    //log::info!("{:?}", presentation);

    let credential = Credential::new_from_sd_jwt(
        name,
        presentation.clone(),
        &proof_options,
    )?;

    Ok((
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    ))
}

pub fn generate_bbs_vc_credential_with_key(
    name: String,
    identity: &openmls_vc_credential::Credential,
    //proof_options: &LinkedDataProofOptions,
    requirement: &SsiVcRequirement,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
    resolver: &impl DIDResolver,
) -> Result<(CredentialWithKey, SignatureKeyPair), CredentialError> {
    let signature_keys = SignatureKeyPair::new(signature_algorithm)
        .map_err(|e| CredentialError::LibraryError(LibraryError::unexpected_crypto_error(e)))?;

    signature_keys
        .store(provider.storage())
        .expect("Error storing keys");

    let selectors = get_selectors_from_requirement(
        requirement.get_requirement().clone()
    ).expect("Error generating selectors from requirement");

    //log::info!("{:?}", selectors);
    let encoded_pk= pk_to_nonce(signature_keys.public());
    let (derived_vc, proof_options) = create_derived_credential(
        identity,
        selectors,
        encoded_pk,
        resolver,
    ).expect("Error creating derived credential");

    let credential = Credential::new_from_bbs_vc(name, &derived_vc, &proof_options)?;

    Ok((
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    ))
}

/*pub fn join_through_external_commit(
    group_config_with_requirement: &MlsGroupCreateConfig,
    ratchet_tree: Option<RatchetTreeIn>,
    joiner_signer: &impl Signer,
    joiner_credential_with_key: &CredentialWithKey,
    group_info: VerifiableGroupInfo,
    mut current_mls_groups: Vec<&mut MlsGroup>,
    backend: &impl OpenMlsProvider,
) -> MlsGroup {
    log::info!("[*] Joining by External Commit");

    // Joining by External Commit with GroupInfo
    let (mut joiner_group, joiner_join_msg_out, _group_info) =
        MlsGroup::join_by_external_commit(
            backend,
            joiner_signer,
            ratchet_tree,
            group_info,
            &MlsGroupJoinConfig::default(),
            None, None,
            b"",
            joiner_credential_with_key.clone()
        ).expect("Error joining by external");

    joiner_group.merge_pending_commit(backend).expect("Error Merging pending commit");

    let mls_message_in = message_out_to_in(&joiner_join_msg_out)
        .expect("Error changing out to in");
    //println!("{:?}", mls_message_in);
    for mls_group in current_mls_groups.iter_mut() {
        parse_in_message(mls_message_in.clone(), *mls_group, backend);
    }

    joiner_group
}*/

/*pub fn add_member_through_proposal(
    group_config_with_requirement: &MlsGroupCreateConfig,
    proposer_group: &mut MlsGroup,
    proposer_signer: &impl Signer,
    joiner_key_package: KeyPackage,
    mut current_mls_groups: Vec<&mut MlsGroup>,
    backend: &impl OpenMlsProvider,
    apply_commit: bool,
) -> MlsGroup {
    //println!("[*] Adding fourth member");
    let (mls_message_out, welcome_out, _) = proposer_group
        .add_members(backend, proposer_signer, &[joiner_key_package])
        .expect("Could not add members.");

    if apply_commit {
        proposer_group
            .merge_pending_commit(backend)
            .expect("error merging pending commit");

        let serialized_welcome = welcome_out
            .tls_serialize_detached()
            .expect("Error serializing welcome");
        let welcome_in = match MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
            .expect("An unexpected error occurred.")
            .extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            // We know it's a welcome message, so we ignore all other cases.
            _ => unreachable!("Unexpected message type."),
        };

        let staged_welcome = StagedWelcome::new_from_welcome(
            backend,
            &MlsGroupJoinConfig::default(),
            welcome_in,
            Some(proposer_group.export_ratchet_tree().into()),
        );

        staged_welcome.

        let joiner_group = MlsGroup::new_from_welcome(
            backend,
            &group_config_with_requirement,
            welcome_in,
            Some(proposer_group.export_ratchet_tree().into()),
        )
            .expect("Error joining group from Welcome");

        let mls_message_in = message_out_to_in(&mls_message_out)
            .expect("Error changing out to in");
        for mls_group in current_mls_groups.iter_mut() {
            parse_in_message(mls_message_in.clone(), *mls_group, backend);
        }

        joiner_group
    }
    else {
        proposer_group.clear_pending_commit();
        proposer_group.clone()
    }
}*/