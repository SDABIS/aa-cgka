extern crate core;

use openmls_vc_credential::DIDWeb;
use openmls::prelude::*;
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls::prelude::ExtensionType::{SsiVcRequirements};
use openmls::prelude::ProposalType::*;
use openmls_traits::signatures::Signer;
use openmls_vc_credential::sdjwt::{SDJWTManager};
use openmls_vc_credential::vc::*;
use openmls::helpers::*;

#[allow(unused_variables)]
fn main() {

    // A helper to create key package bundles.
    fn generate_key_package(
        ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        credential_with_key: CredentialWithKey,
        capabilities: Capabilities,
    ) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
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
    let resolver = DIDWeb;

    let vc = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/ns/credentials/examples/v2",
            "https://w3id.org/security/bbs/v1"
        ],
        "type": ["VerifiableCredential", "ExampleAlumniCredential"],
        "issuer": "did:web:localhost%3A9000:dids:issuer",
        "iss": "-",
        "exp": 1883000000,
        "credentialSchema": {
            "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
            "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
        },
        //"issuanceDate": ssi::ldp::now_ns(),
        "credentialSubject": {
            "name": "did:web:localhost%3A9000:dids:subject",
            "degree": {
                "university": "Example University",
                "name": "Degree in Computer Science",
            }
        }
    });
    //Init issuers keys
    let vc_issuer_sk = load_key(include_str!("../resources/vc/vc_issuer_sk.jwt"))
        .expect("Error loading JWK");
    let bbs_issuer_sk = load_key(include_str!("../resources/bbs/bbsvc_issuer_sk.jwk"))
        .expect("Error loading JWK");
    let sd_jwt_issuer_sk = include_str!("../resources/sdjwt/sd_jwt_issuer_sk").as_bytes();
    let sd_jwt_issuer_pk = "did:web:localhost%3A9000:dids:issuer#key-sdjwt".as_bytes();

    //let sd_jwt_issuer_pk = include_str!("../resources/sdjwt/sd_jwt_issuer_pk.jwk").as_bytes();

    // Init holders keys
    let charlie_key = load_key(include_str!("../resources/vc/vc_subject_sk.jwt"))
        .expect("Error loading JWK");
    let daniel_sk = include_str!("../resources/sdjwt/sd_jwt_holder_sk").as_bytes();
    let daniel_pk = serde_json::from_str(include_str!("../resources/sdjwt/sd_jwt_holder_pk.jwt"))
        .expect("Error loading JWK");

    //Create Verifiable Credential
    println!("[*] Generating Verifiable Credential");
    //println!("\tIssuer Key: {:?}", vc_issuer_sk);
    let verification_method = "did:web:localhost%3A9000:dids:issuer#key1".to_string();
    let charlie_vc = issue_vc(&vc_issuer_sk, &resolver, vc.clone(), verification_method).expect("Error creating VC");
    println!("\tDone. VC: {:?}\n", charlie_vc);

    // SD_JWT Credential
    println!("[*] Generating SD-JWT");
    let sd_jwt_manager = SDJWTManager::new(None, None);
    let mut sd_jwt_issuer = sd_jwt_manager.init_issuer(sd_jwt_issuer_sk);
    let daniel_sd_jwt = sd_jwt_manager.issue_sd_jwt(vc.clone(), daniel_pk, &mut sd_jwt_issuer)
        .expect("Error issuing SD_JWT");
    println!("\tDone. SD-JWT: {:?}\n", daniel_sd_jwt);

    // BBS_VC Credential
    println!("[*] Generating BBS VC");
    let verification_method = "did:web:localhost%3A9000:dids:issuer#key-bbs".to_string();
    let ellen_vc = issue_vc(&bbs_issuer_sk, &resolver, vc.clone(), verification_method).expect("Error creating VC");
    println!("\tDone. BBS VC: {:?}\n", ellen_vc);

    // Now let's create the participants.
    // First they need credentials to identify them
    let (alice_credential_with_key, alice_signer) = generate_basic_credential_with_key(
        "alice".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    let (bob_credential_with_key, bob_signer) = generate_basic_credential_with_key(
        "bob".into(),
        ciphersuite.signature_algorithm(),
        backend,
    );

    let capabilities = Capabilities::new(
        None,
        None,
        Some(&[SsiVcRequirements]),
        Some(&[AddReqs, UpdateReqs, RemoveReqs]),
        Some(&[CredentialType::Basic, CredentialType::X509, CredentialType::VC, CredentialType::SDJWT, CredentialType::BBSVC])
    );

    // Generate KeyPackages
    let alice_key_package = generate_key_package(ciphersuite, backend, &alice_signer, alice_credential_with_key.clone(), capabilities.clone());

    let bob_key_package = generate_key_package(ciphersuite, backend, &bob_signer, bob_credential_with_key.clone(), capabilities.clone());

    println!("[*] Creating MLS Group with requirement");
    let requirement = serde_json::json!({
            //"type": ["VerifiableCredential", "ExampleAlumniCredential"],
            "issuer": "did:web:localhost%3A9000:dids:issuer",
            "credentialSubject": {
                "degree": {
                    "university": "Example University",
                    "name": "Degree in Computer Science",
                }
            }
        });

    let group_config_with_requirement = create_group_config_with_requirement(requirement.clone());
    // Now alice starts a new group ...
    let mut alice_group = MlsGroup::new(
        backend,
        &alice_signer,
        &group_config_with_requirement,
        alice_credential_with_key.clone()
    )
        .expect("An unexpected error occurred.");

    // Removing requirement from the group
    let (mls_message_out, _, _) = alice_group
        .remove_reqs(backend, &alice_signer, &[0])
        .expect("Could not remove requirements");
    alice_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");

    println!("[*] Adding BASIC member");
    // Adding member with "Basic" credential
    let mut bob_group = add_member_through_proposal(
        &group_config_with_requirement,
        &mut alice_group,
        &alice_signer,
        bob_key_package,
        vec![],
        backend,
        true,
    );


    // Adding requirement to the group
    let (mls_message_out, _, _) = alice_group
        .add_new_reqs(backend, &alice_signer, &[requirement])
        .expect("Could not remove requirements");
    alice_group
        .merge_pending_commit(backend)
        .expect("error merging pending commit");
    parse_in_message(message_out_to_in(&mls_message_out).unwrap(), &mut bob_group, backend);

    println!("[*] Adding VC member");

    // CHARLIE: VC credential
    let group_info = message_out_to_group_info(
        &alice_group.export_group_info(backend.crypto(), &alice_signer, false)
        .expect("Error creating GroupInfo")
    ).expect("Error Parsing GroupInfo");
    let (charlie_credential_with_key, charlie_signer) = generate_vc_credential_with_key(
        "charlie".into(),
        &charlie_vc,
        &charlie_key,
        ciphersuite.signature_algorithm(),
        backend,
        &resolver
    );

    // Once the credential is generated, join the group
    let mut charlie_group = join_through_external_commit(
        &group_config_with_requirement,
        Some(alice_group.export_ratchet_tree().into()),
        &charlie_signer,
        &charlie_credential_with_key,
        group_info,
        vec![&mut alice_group, &mut bob_group],
        backend
    );

    println!("[*] Adding SD-JWT member");
    // DANIEL: SD_JWT Credential
    let group_info = message_out_to_group_info(
        &alice_group.export_group_info(backend.crypto(), &alice_signer, false)
            .expect("Error creating GroupInfo")
    ).expect("Error Parsing GroupInfo");
    let requirement = group_info.group_context_extensions().ssi_vc_requirements().unwrap().first().unwrap();
    let (daniel_credential_with_key, daniel_signer) = generate_sd_jwt_credential_with_key(
        "daniel".into(),
        daniel_sd_jwt,
        requirement,
        ciphersuite.signature_algorithm(),
        daniel_sk,
        sd_jwt_issuer_pk,
        backend,
    );

    // Once the credential is generated, join the group
    let daniel_key_package = generate_key_package(ciphersuite, backend, &daniel_signer, daniel_credential_with_key.clone(), capabilities.clone());
    let mut daniel_group = join_through_external_commit(
        &group_config_with_requirement,
        Some(alice_group.export_ratchet_tree().into()),
        &daniel_signer,
        &daniel_credential_with_key,
        group_info,
        vec![&mut alice_group, &mut bob_group, &mut charlie_group],
        backend
    );

    println!("[*] Adding BBS VC member");
    // ELLEN: BBS_VC Credential
    let group_info = message_out_to_group_info(
        &alice_group.export_group_info(backend.crypto(), &alice_signer, false)
            .expect("Error creating GroupInfo")
    ).expect("Error Parsing GroupInfo");
    let requirement = group_info.group_context_extensions().ssi_vc_requirements().unwrap().first().unwrap();
    let (ellen_credential_with_key, ellen_signer) = generate_bbs_vc_credential_with_key(
        "ellen".into(),
        &ellen_vc,
        requirement,
        ciphersuite.signature_algorithm(),
        backend,
        &resolver
    );
    // Once the credential is generated, join the group
    let ellen_key_package = generate_key_package(ciphersuite, backend, &ellen_signer, ellen_credential_with_key.clone(), capabilities.clone());
    let mut ellen_group = join_through_external_commit(
        &group_config_with_requirement,
        Some(alice_group.export_ratchet_tree().into()),
        &ellen_signer,
        &ellen_credential_with_key,
        group_info,
        vec![&mut alice_group, &mut bob_group, &mut charlie_group, &mut daniel_group],
        backend
    );

    println!("[*] Creating Test messages");
    let msg_alice = alice_group
        .create_message(backend, &alice_signer, b"Test Message by Alice")
        .expect("Error Creating Message");

    let msg_ellen = ellen_group
        .create_message(backend, &ellen_signer, b"Test Message by Ellen")
        .expect("Could not create message");

    //println!("\tAlice_msg: {:?}", msg_alice);
    //println!("\tCharlie_msg: {:?}", msg_charlie);

    let original_msg_alice = parse_in_message(
        message_out_to_in(&msg_alice)
            .expect("Error changing out to in")
            .clone(),
        &mut ellen_group, backend);
    let original_msg_ellen = parse_in_message(
        message_out_to_in(&msg_ellen)
            .expect("Error changing out to in")
            .clone(),
        &mut alice_group, backend);

    println!("\tAlice_msg processed by Ellen: {:?}", original_msg_alice);
    println!("\tEllen_msg processed by Alice: {:?}", original_msg_ellen);
    //let dec_message = bob_group.parse_message(msg, backend);

}

