extern crate core;

use openmls::prelude::*;
use openmls_rust_crypto::{OpenMlsRustCrypto};
use std::fmt::Error;
use openmls::prelude::group_info::VerifiableGroupInfo;
use openmls_basic_credential::SignatureKeyPair;

fn message_out_to_in(
    out: &MlsMessageOut
) -> Result<ProtocolMessage, Error> {
    let msg =  MlsMessageIn::tls_deserialize(
        &mut out.tls_serialize_detached()
            .map_err(|_| Error)?
            .as_slice()
    )
        .map_err(|_| Error)?;

    match msg.extract() {
        MlsMessageInBody::PublicMessage(pm) => Ok(pm.into()),
        MlsMessageInBody::PrivateMessage(pm) => Ok(pm.into()),
        _ => {
            Err(Error)
        }
    }
}

fn message_out_to_group_info(
    out: &MlsMessageOut
) -> Result<VerifiableGroupInfo, Error> {
    let msg =  MlsMessageIn::tls_deserialize(
        &mut out.tls_serialize_detached()
            .map_err(|_| Error)?
            .as_slice()
    )
        .map_err(|_| Error)?;

    match msg.extract() {
        MlsMessageInBody::GroupInfo(gi) => Ok(gi.into()),
        _ => Err(Error)
    }
}

// A helper to create and store credentials.
fn generate_credential_with_key(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(identity, credential_type).unwrap();
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    signature_keys
        .store(provider.key_store())
        .expect("Error storing signature keys in key store.");

    (
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}



fn main() {

    fn parse_in_message(
        mut mls_message_in: ProtocolMessage,
        group: &mut MlsGroup,
        backend: &impl OpenMlsProvider,
    ) -> Result<String, Error> {

        let processed_message = group.process_message(
            backend,
            mls_message_in
        ).map_err(|_| Error)?;
        let content = processed_message.into_content();

        match content {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                String::from_utf8(app_msg.into_bytes())
                    .map_err(|_| Error)
            },
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                let result = group.merge_staged_commit(backend, *commit)
                    .map_err(|_| Error)?;
                Ok("Processed Commit".to_string())
            }
            _ => Err(Error)
        }
    }

    // A helper to create key package bundles.
    fn generate_key_package(
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &SignatureKeyPair,
        credential_with_key: CredentialWithKey,
    ) -> KeyPackage {
        KeyPackage::builder()
            // .leaf_node_extensions(...)
            .build(
                CryptoConfig {
                    ciphersuite,
                    version: ProtocolVersion::default(),
                },
                provider,
                signer,
                credential_with_key,
            )
            .unwrap()
    }

// Define cipher suite ...
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
// ... and the crypto backend to use.
    let backend = &OpenMlsRustCrypto::default();

// Now let's create two participants.

// First they need credentials to identify them
    let (sasha_credential_with_key, sasha_signer) = generate_credential_with_key(
        "Sasha".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );

    let (maxim_credential_with_key, maxim_signer) = generate_credential_with_key(
        "Maxim".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );

    let (bob_credential_with_key, bob_signer) = generate_credential_with_key(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    );

// Then they generate key packages to facilitate the asynchronous handshakes
// in MLS

// Generate KeyPackages
    let sasha_key_package = generate_key_package(ciphersuite, backend, &sasha_signer, sasha_credential_with_key.clone());

    let maxim_key_package = generate_key_package(ciphersuite, backend, &maxim_signer, maxim_credential_with_key);

    let bob_key_package = generate_key_package(ciphersuite, backend, &bob_signer, bob_credential_with_key.clone());

// Now Sasha starts a new group ...
    let mut sasha_group = MlsGroup::new(
        backend,
        &sasha_signer,
        &MlsGroupConfig::default(),
        sasha_credential_with_key.clone()
    )
        .expect("An unexpected error occurred.");

    let aaaa = sasha_group.export_group_info(backend.crypto(), &sasha_signer, true).expect("aaa");

    // ... and invites Maxim.
    // The key package has to be retrieved from Maxim in some way. Most likely
    // via a server storing key packages for users.
    let (mls_message_out, welcome_out, _) = sasha_group
        .add_members(backend, &sasha_signer, &[maxim_key_package])
        .expect("Could not add members.");

// Sasha merges the pending commit that adds Maxim.
    sasha_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");

    let serialized_welcome = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    let welcome_in = match MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
        .expect("An unexpected error occurred.")
        .extract() {
        MlsMessageInBody::Welcome(welcome) => welcome,
        // We know it's a welcome message, so we ignore all other cases.
        _ => unreachable!("Unexpected message type."),
    };

    // Now Maxim can join the group.
    let mut maxim_group = MlsGroup::new_from_welcome(
        backend,
        &MlsGroupConfig::default(),
        welcome_in,
        // The public tree is need and transferred out of band.
        // It is also possible to use the [`RatchetTreeExtension`]
        Some(sasha_group.export_ratchet_tree().into()),
    )
        .expect("Error joining group from Welcome");

    let group_info = message_out_to_group_info(
        &sasha_group.export_group_info(backend.crypto(), &sasha_signer, true)
        .expect("Error creating GroupInfo")
    ).expect("Error Parsing GroupInfo");
    println!("{:?}", group_info);

    let (mut bob_group, bob_join_msg_out, group_info) = MlsGroup::join_by_external_commit(
        backend,
        &bob_signer,
        Some(sasha_group.export_ratchet_tree().into()),
        group_info,
        &MlsGroupConfig::default(),
    b"",
        bob_credential_with_key.clone()
    ).expect("Error joining by external");

    bob_group.merge_pending_commit(backend).expect("Error Merging pending commit");

    println!("{:?}", bob_group);


    /*let (mls_message_out, welcome_bob_out, _) = sasha_group
        .add_members(backend, &sasha_signer, &[bob_key_package])
        .expect("Could not add members.");

    let serialized_welcome_bob = welcome_bob_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");

    let welcome_bob_in = match MlsMessageIn::tls_deserialize(&mut serialized_welcome_bob.as_slice())
        .expect("An unexpected error occurred.")
        .extract() {
        MlsMessageInBody::Welcome(welcome) => welcome,
        // We know it's a welcome message, so we ignore all other cases.
        _ => unreachable!("Unexpected message type."),
    };*/

    let mls_message_in = message_out_to_in(&bob_join_msg_out)
        .expect("Error changing out to in");
    let add_bob_in_maxim = parse_in_message(
        mls_message_in.clone(), &mut maxim_group, backend)
        .expect("Error decoding");
    let add_bob_in_sasha = parse_in_message(
        mls_message_in.clone(), &mut sasha_group, backend)
        .expect("Error decoding");

// Sasha merges the pending commit that adds Bob.
    /*sasha_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");

    let mut bob_group = MlsGroup::new_from_welcome(
        backend,
        &MlsGroupConfig::default(),
        welcome_bob_in,
        // The public tree is need and transferred out of band.
        // It is also possible to use the [`RatchetTreeExtension`]
        Some(sasha_group.export_ratchet_tree().into()),
    )
        .expect("Error joining group from Welcome");*/

    let mut msg1 = sasha_group
        .create_message(backend, &sasha_signer, b"aaaa")
        .expect("Error Creating Message");

    let mut msg2 = sasha_group
        .create_message(backend, &sasha_signer, b"bbbb")
        .expect("Error Creating Message");

    let mut msg_bob = bob_group
        .create_message(backend, &bob_signer, b"aaaa")
        .expect("Could not create message");

    println!("{:?}", msg1);
    println!("{:?}", msg2);
    println!("{:?}", msg_bob);

    let original_msg2 = parse_in_message(
        message_out_to_in(&msg2)
            .expect("Error changing out to in")
            .clone(),
        &mut maxim_group, backend)
        .expect("Error decoding");
    let original_msg1 = parse_in_message(
        message_out_to_in(&msg1)
            .expect("Error changing out to in")
            .clone(),
        &mut maxim_group, backend)
        .expect("Error decoding");
    let original_msg_bob = parse_in_message(
        message_out_to_in(&msg_bob)
            .expect("Error changing out to in")
            .clone(),
        &mut maxim_group, backend)
        .expect("Error decoding");

    println!("{:?}", original_msg1);
    println!("{:?}", original_msg2);
    println!("{:?}", original_msg_bob);
    //let dec_message = maxim_group.parse_message(msg, backend);

}

