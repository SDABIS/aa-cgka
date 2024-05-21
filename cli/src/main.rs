// #[macro_use]
// extern crate clap;
// use clap::App;

use std::io::{stdin, stdout, StdoutLock, Write};
use std::sync::{Arc, Mutex};
use termion::input::TermRead;
use std::thread;
use std::time::Duration;
use serde_json::Value;
use openmls_vc_credential::DIDWeb;
use openmls_vc_credential::sdjwt::{SDJWTManager, Jwk};
use openmls_vc_credential::vc::{issue_vc, load_key};
use crate::aa_cgka_user::{AACGKAUser, UserType};
use crate::user::User;

mod backend;
mod conversation;
mod file_helpers;
mod identity;
mod networking;
mod openmls_rust_persistent_crypto;
mod persistent_key_store;
mod serialize_any_hashmap;
mod user;
mod aa_cgka_user;

/*const HELP: &str = "
>>> Available commands:
>>>     - update                                update the client state
>>>     - reset                                 reset the server
>>>     - register {client name}                register a new client
>>>     - save {client name}                    serialize and save the client state
>>>     - load {client name}                    load and deserialize the client state as a new client
>>>     - autosave                              enable automatic save of the current client state upon each update
>>>     - create kp                             create a new key package
>>>     - create group {group name}             create a new group
>>>     - group {group name}                    group operations
>>>         - send {message}                    send message to group
>>>         - invite {client name}              invite a user to the group
>>>         - read                              read messages sent to the group (max 100)
>>>         - update                            update the client state

";*/

pub const USER_NUM: u32 = 120;
pub const GROUP_NAME: &str = "group123";
pub const JOIN_CHANCE: f32 = 0.15;
pub const UPDATE_CHANCE: f32 = 0.01;

fn update(client: &mut user::User, group_id: Option<String>, stdout: &mut StdoutLock) {
    let messages = client.update(group_id).expect("Error updating client");
    stdout.write_all(b" >>> Updated client :)\n").unwrap();
    if !messages.is_empty() {
        stdout.write_all(b"     New messages:\n\n").unwrap();
    }
    messages.iter().for_each(|cm| {
    stdout
        .write_all(format!("         {0} from {1}\n", cm.message, cm.author).as_bytes())
        .unwrap();
});
    stdout.write_all(b"\n").unwrap();
}

fn main() {
    pretty_env_logger::init();

    /*let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();*/

    let credential_str = include_str!("../resources/credential.json");
    let vc: Value = serde_json::from_str(credential_str).unwrap();
    let requirement_str = include_str!("../resources/requirement.json");
    let req: Value = serde_json::from_str(requirement_str).unwrap();

    //Init issuers keys
    let vc_issuer_sk = load_key(include_str!("../resources/vc/vc_issuer_sk.jwt"))
        .expect("Error loading JWK");
    let bbs_issuer_sk = load_key(include_str!("../resources/bbs/bbsvc_issuer_sk.jwk"))
        .expect("Error loading JWK");
    let sd_jwt_issuer_sk = include_str!("../resources/sdjwt/sd_jwt_issuer_sk").as_bytes();

    // Init holders keys
    let vc_holder_sk = load_key(include_str!("../resources/vc/vc_subject_sk.jwt"))
        .expect("Error loading JWK");
    let sdjwt_holder_sk = include_str!("../resources/sdjwt/sd_jwt_holder_sk").as_bytes();
    let sdjwt_holder_pk: Jwk = serde_json::from_str(include_str!("../resources/sdjwt/sd_jwt_holder_pk.jwt"))
        .expect("Error loading JWK");

    let verification_method_vc = "did:web:localhost%3A9000:dids:issuer#key1".to_string();
    let verification_method_sdjwt = "did:web:localhost%3A9000:dids:issuer#key-sdjwt".to_string();
    let verification_method_bbs = "did:web:localhost%3A9000:dids:issuer#key-bbs".to_string();
    let resolver = DIDWeb;

    /*stdout
        .write_all(b" >>> Welcome to the OpenMLS CLI :)\nType help to get a list of commands\n\n")
        .unwrap();*/

    let mut group_creator = User::new("CREATOR".to_string());
    group_creator.register();
    group_creator.create_group(GROUP_NAME.to_string());
    group_creator.add_requirement(req, GROUP_NAME.to_string()).unwrap();
    let current_members = Arc::new(Mutex::new(vec![group_creator.username.clone()]));
    let group_creator_mutex = Arc::new(Mutex::new(group_creator));

    let mut users: Vec<AACGKAUser> = Vec::new();

    for i in 0..USER_NUM {
        let name = "User_".to_owned() + &i.to_string();
        let user = match i % 3 {
            0 => {
                let credential = issue_vc(
                    &vc_issuer_sk, &resolver, vc.clone(), verification_method_vc.clone()
                ).expect("Error issuing VC");

                AACGKAUser::new(UserType::VC(credential, vc_holder_sk.clone()), name)
            },
            1 => {
                let sd_jwt_manager = SDJWTManager::new(None, None);
                let mut sd_jwt_issuer = sd_jwt_manager.init_issuer(sd_jwt_issuer_sk);
                let sd_jwt = sd_jwt_manager.issue_sd_jwt(vc.clone(), sdjwt_holder_pk.clone(), &mut sd_jwt_issuer)
                    .expect("Error issuing SD_JWT");
                //println!("Credential of {}: {}", name, sd_jwt);

                AACGKAUser::new(UserType::SDJWT(sd_jwt, sdjwt_holder_sk.to_vec(), verification_method_sdjwt.clone()), name)
            },
            2 => {
                let credential = issue_vc(
                    &bbs_issuer_sk, &resolver, vc.clone(), verification_method_bbs.clone()
                ).expect("Error issuing BBS_VC");
                AACGKAUser::new(UserType::BBSVC(credential), name)
            },
            _ => unreachable!()
        };

        users.push(user);

    }
    let mut threads = Vec::new();
    for user in users {
        let current_members = Arc::clone(&current_members);
        let group_creator_mutex = Arc::clone(&group_creator_mutex);
        let thread = thread::spawn(move || {
            user.run(current_members, group_creator_mutex);
        });
        threads.push(thread);
    }

    for thread in threads {
        thread.join().expect("Error with thread");
    }
}

#[test]
#[ignore]
fn basic_test() {
    // Reset the server before doing anything for testing.
    backend::Backend::default().reset_server();

    const MESSAGE_1: &str = "Thanks for adding me Client1.";
    const MESSAGE_2: &str = "Welcome Client3.";
    const MESSAGE_3: &str = "Thanks so much for the warm welcome! 😊";

    // Create one client
    let mut client_1 = user::User::new("Client1".to_string());

    // Create another client
    let mut client_2 = user::User::new("Client2".to_string());

    // Create another client
    let mut client_3 = user::User::new("Client3".to_string());

    // Update the clients to know about the other clients.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 creates a group.
    client_1.create_group("MLS Discussions".to_string());

    // Client 1 adds Client 2 to the group.
    client_1
        .invite("Client2".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Client 2 retrieves messages.
    client_2.update(None).unwrap();

    // Client 2 sends a message.
    client_2
        .send_msg(MESSAGE_1, "MLS Discussions".to_string())
        .unwrap();

    // Client 1 retrieves messages.
    client_1.update(None).unwrap();

    // Check that Client 1 received the message
    assert_eq!(
        client_1.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_1.to_owned(),
            "Client2".to_owned(),
        )])
    );

    // Client 2 adds Client 3 to the group.
    client_2
        .invite("Client3".to_string(), "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Client 1 sends a message.
    client_1
        .send_msg(MESSAGE_2, "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Check that Client 2 and Client 3 received the message
    assert_eq!(
        client_2.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );
    assert_eq!(
        client_3.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![conversation::ConversationMessage::new(
            MESSAGE_2.to_owned(),
            "Client1".to_owned(),
        )])
    );

    // Client 3 sends a message.
    client_3
        .send_msg(MESSAGE_3, "MLS Discussions".to_string())
        .unwrap();

    // Everyone updates.
    client_1.update(None).unwrap();
    client_2.update(None).unwrap();
    client_3.update(None).unwrap();

    // Check that Client 1 and Client 2 received the message
    assert_eq!(
        client_1.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_1.to_owned(), "Client2".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );
    assert_eq!(
        client_2.read_msgs("MLS Discussions".to_string()).unwrap(),
        Some(vec![
            conversation::ConversationMessage::new(MESSAGE_2.to_owned(), "Client1".to_owned()),
            conversation::ConversationMessage::new(MESSAGE_3.to_owned(), "Client3".to_owned())
        ])
    );
}
