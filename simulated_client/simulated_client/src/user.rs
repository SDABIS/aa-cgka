use std::borrow::Borrow;
use std::thread;
use std::time::Duration;
use std::collections::HashSet;
use std::{cell::RefCell, collections::HashMap, str};
use std::cmp::PartialEq;
use std::ops::Add;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
use chrono::prelude::*;
use cpu_time::ProcessTime;
use ds_lib::{ClientKeyPackages, ContactInfo, GroupMessage, KeyPackageForGroup};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use tls_codec::TlsByteVecU8;
use openmls::framing::errors::MessageDecryptionError;
use openmls::framing::errors::MessageDecryptionError::{AeadError};
use openmls::prelude::group_info::{GroupInfo, VerifiableGroupInfo};
use crate::pubsub::{Broker, mqtt_broker::MqttBroker, gossipsub_broker::GossipSubBroker};
use crate::client_agent::{ActionRecord, CGKAAction, ClientAgent, UserCredential};
use rand::seq::SliceRandom;
use url::Url;
use openmls_vc_credential::did_resolver::AACGKAResolver;
use crate::user_parameters::{AuthorizationPolicy, Directory};

use super::{
    network::backend::Backend, conversation::Conversation, conversation::ConversationMessage,
    identity::Identity, openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto,
    serialize_any_hashmap,
};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Contact {
    username: String,
    group_name: String
}

pub struct StoredWelcome {
    welcome: MlsMessageOut,
    recipients: Vec<String>
}

pub struct Group {
    group_name: String,
    conversation: Conversation,
    mls_group: RefCell<MlsGroup>,
}

#[derive(Debug, Clone)]
pub struct EpochChange {
    pub(crate) timestamp: i64,
    pub(crate) epoch: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct User {
    pub(crate) username: String,
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    pub(crate) contacts: HashMap<Vec<u8>, Contact>,
    #[serde(skip)]
    pub(crate) groups: RefCell<HashMap<String, (Group, Identity)>>,
    group_list: HashSet<String>,
    pub(crate) base_identity: RefCell<Identity>,
    pub(crate) pending_identities: HashMap<KeyPackageRef, (String, Identity)>,
    #[serde(skip)]
    pub(crate) pending_commits: HashMap<String, (Option<GroupInfo>, Option<StoredWelcome>, ActionRecord)>,
    #[serde(skip)]
    backend: Backend,
    #[serde(skip)]
    ds: DeliveryService,
    #[serde(skip)]
    crypto: OpenMlsRustPersistentCrypto,
    autosave_enabled: bool,
    active: HashMap<String, (bool, u64)>,
}

#[derive(PartialEq)]
pub enum PostUpdateActions {
    None,
    Remove,
    Retry,
}

#[derive(Default, Debug)]
pub enum DeliveryService {
    #[default]
    Request,
    PubSubMQTT(Arc<Mutex<MqttBroker>>),
    GossipSub(Arc<Mutex<GossipSubBroker>>, Directory),
}

impl Clone for DeliveryService {
    fn clone(&self) -> Self {
        match self {
            DeliveryService::Request => DeliveryService::Request,
            DeliveryService::PubSubMQTT(broker) => DeliveryService::PubSubMQTT(Arc::clone(broker)),
            DeliveryService::GossipSub(broker, dir) => DeliveryService::GossipSub(Arc::clone(broker), dir.clone()),
        }
    }
}

/*pub enum BrokerType {
    MQTT(Arc<Mutex<Broker>>),
    GossipSub(Arc<Mutex<Broker>>),
}*/

impl User {
    /// Create a new user with the given name and a fresh set of credentials.
    pub fn new(username: String, user_credential: UserCredential, backend_url: Url, ds: DeliveryService) -> Self {
        let crypto = OpenMlsRustPersistentCrypto::default();
        let out = Self {
            username: username.clone(),
            groups: RefCell::new(HashMap::new()),
            group_list: HashSet::new(),
            contacts: HashMap::new(),
            base_identity: RefCell::new(Identity::new(CIPHERSUITE, user_credential, &crypto, username.as_bytes())),
            pending_identities: HashMap::new(),
            pending_commits: HashMap::new(),
            backend: Backend::new(backend_url),
            ds,
            crypto,
            autosave_enabled: false,
            active: HashMap::new(),
        };
        out
    }

    /// Add a key package to the user identity and return the pair [key package
    /// hash ref , key package]
    pub fn add_key_package(&self, identity: &mut Identity, group_name: String) -> (KeyPackageRef, KeyPackage) {

        let kp = identity
            .add_key_package(CIPHERSUITE, &self.crypto, group_name);
        (
            kp.hash_ref(self.crypto.crypto())
                .unwrap(),
            kp,
        )
    }



    /// Get a member
    fn find_member_index(&self, name: String, group: &Group) -> Result<LeafNodeIndex, String> {
        let mls_group = group.mls_group.borrow();
        for Member {
            index,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            if credential.identity() == name.as_bytes() {
                return Ok(index);
            }
        }
        Err("Unknown member".to_string())
    }

    /// Get the key packages fo this user.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackageForGroup)> {
        let mut kps = vec![];
        for (_, (_, identity)) in &self.pending_identities {
            for (hash_ref, kp) in identity.kp.clone() {
                kps.push((hash_ref, kp));
            }
        }

        kps
    }

    pub fn group_exists(&self, group_name: String) -> Result<Option<VerifiableGroupInfo>, String> {

        //TODO
        match self.ds {
            DeliveryService::Request | DeliveryService::PubSubMQTT(_) | DeliveryService::GossipSub(_, Directory::Server) => {
                self.backend.group_exists(group_name)
            }
            DeliveryService::GossipSub(ref broker, Directory::Kademlia) => {
                let broker = broker.lock().unwrap();
                let result = broker.group_exists(group_name.clone())?;
                drop(broker);
                Ok(result)
            }
        }
        //self.backend.group_exists(group_name)
    }

    pub fn get_group_info(&self, group_name: String) -> Result<VerifiableGroupInfo, String> {
        match self.ds {
            DeliveryService::Request | DeliveryService::PubSubMQTT(_) | DeliveryService::GossipSub(_, Directory::Server) => {
                self.backend.group_info(self.username.clone(), group_name)
            }
            DeliveryService::GossipSub(ref broker, Directory::Kademlia) => {
                let broker = broker.lock().unwrap();
                let result = broker.group_info(group_name.clone())?;
                drop(broker);
                Ok(result)
            }
        }

        //self.backend.group_info(self.username.clone(), group_name)
    }

    pub fn consume_key_package(&self, contact: &Contact) -> Result<KeyPackageIn, String> {
        match self.ds {
            DeliveryService::Request | DeliveryService::PubSubMQTT(_) | DeliveryService::GossipSub(_, Directory::Server) => {
                self.backend.consume_key_package(&contact.username.as_bytes())
            }
            DeliveryService::GossipSub(ref broker, Directory::Kademlia) => {

                let broker = broker.lock().unwrap();
                let result = broker.consume_key_package(contact.username.clone())?;
                drop(broker);
                Ok(result)
            }
        }

        //self.backend.consume_key_package(&contact.id)

    }

    /*pub fn register(&self, group_name: String) {

            DSType::Request  => {
                match self.backend.register_client(self) {
                    Ok(r) => log::debug!("Created new user: {:?}", r),
                    Err(e) => log::error!("Error creating user: {:?}", e),
                }
            },
            DSType::PubSub(_) => {
                self.broker.unwrap().subscribe(group_name.clone());
            }
        }
    }*/

    /*pub fn register(&self) -> Result<(), String> {

        let contact_info = match self.ds {
            DeliveryService::Request | DeliveryService::PubSubMQTT(_) => {None}
            DeliveryService::GossipSub(ref broker, _) => {
                let broker = broker.lock().unwrap();
                let contact_info = broker.get_contact_info()?;
                drop(broker);
                Some(contact_info)
            }
        };

         match self.backend.register_identity(self, contact_info) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Error creating user: {:?}", e))
        }
    }*/

    pub fn subscribe_welcome(&mut self) -> Result<(), String> {
        match self.ds {
            DeliveryService::Request => {Ok(())}
            DeliveryService::PubSubMQTT(ref broker) => {
                let mut broker = broker.lock().unwrap();
                broker.subscribe_welcome(self.username.clone())?;
                drop(broker);
                Ok(())
            }

            DeliveryService::GossipSub(ref broker, _) => {
                let mut broker = broker.lock().unwrap();
                broker.subscribe_welcome(self.username.clone())?;
                drop(broker);
                Ok(())
            }
        }
    }

    fn subscribe(&mut self, group_name: String) -> Result <(), String> {
        log::info!("{} -> Subscribing to {}", self.username, group_name);

        match self.ds {
            DeliveryService::Request => {Ok(())}
            DeliveryService::PubSubMQTT(ref broker) => {
                let mut broker = broker.lock().unwrap();
                broker.subscribe(group_name.clone())?;
                drop(broker);
                Ok(())
            }

            DeliveryService::GossipSub(ref broker, _) => {
                let mut broker = broker.lock().unwrap();
                broker.subscribe(group_name.clone())?;
                drop(broker);
                Ok(())
            }
        }
    }

    pub fn unsubscribe(&mut self, group_name: String) -> Result <(), String> {
        log::info!("{} -> Unsubscribing from {}", self.username, group_name);


        match self.ds {
            DeliveryService::Request => {Ok(())}
            DeliveryService::PubSubMQTT(ref broker) => {
                let mut broker = broker.lock().unwrap();
                broker.unsubscribe(group_name.clone())?;
                drop(broker);
                Ok(())
            }
            DeliveryService::GossipSub(ref broker, _)=> {
                let mut broker = broker.lock().unwrap();
                broker.unsubscribe(group_name.clone())?;
                drop(broker);
                Ok(())
            }
        }
    }

    fn mls_recipients (&self, mls_group: &MlsGroup, identity: &Identity) -> Vec<Vec<u8>> {
        let mut recipients = Vec::new();
        //let group_name = from_utf8(mls_group.group_id().as_slice()).unwrap().to_string();
        for Member {
            index: _,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            if identity.identity()
                != credential.identity()
            {
                //log::info!("{:?} {:?}", from_utf8(identity.identity()).unwrap(), from_utf8(credential.identity()).unwrap());
                recipients.push(credential.identity().to_vec());
            }
        }
        recipients
    }

    /// Get a list of clients in the group to send messages to.
    fn recipients(&self, group: &Group, identity: &Identity) -> Vec<Vec<u8>> {

        let mls_group = group.mls_group.borrow();
        self.mls_recipients(mls_group.borrow(), identity)
    }

    pub fn members_of_group(&self, group_name: String) -> Vec<String> {
        let groups = self.groups.borrow();
        let (group, identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Vec::new(),
        };

        let recipients = self.recipients(group, identity);
        recipients.iter().map(|r| from_utf8(r).unwrap().to_string()).collect()
    }

    pub fn number_of_members(&self, group_name: String) -> usize {
        let groups = self.groups.borrow();
        let (group, identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return 1,
        };

        let recipients = self.recipients(group, identity);

        recipients.len()
    }

    pub fn not_members_of_group(&self, group_name: String) -> Vec<String> {
        let groups = self.groups.borrow();
        let (group, identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Vec::new(),
        };

        let recipients = self.recipients(group, identity);

        let mut members = Vec::new();
        for contact in self.contacts.values().filter(|c| c.group_name == group_name) {
            if !recipients.contains(&contact.username.clone().into_bytes()) {
                members.push(contact.username.clone());
            }
        }

        members
    }

    pub fn list_of_groups(&self) -> Vec<String> {
        self.groups.borrow().keys().cloned().collect()
    }

    pub fn crypto(&self) -> &OpenMlsRustPersistentCrypto {
        &self.crypto
    }

    /// Return the last 100 messages sent to the group.
    pub fn read_msgs(
        &self,
        group_name: String,
    ) -> Result<Option<Vec<ConversationMessage>>, String> {
        let groups = self.groups.borrow();
        groups.get(&group_name).map_or_else(
            || Err("Unknown group".to_string()),
            |(g, _)| {
                Ok(g.conversation
                    .get(100)
                    .map(|messages: &[ConversationMessage]| messages.to_vec()))
            },
        )
    }

    pub fn has_identity_for_group(&self, group_name: &str) -> Option<Identity> {
        self.pending_identities.iter().find(|(_, (g, _))| g == group_name)
            .map(|(_, (_, id))| id).cloned()
    }

    /// Create a new key package and publish it to the delivery server
    pub fn create_kp(&mut self, group_info: VerifiableGroupInfo, group_name: String) -> Result<(), String> {

        let now = ProcessTime::now();
        let epoch = group_info.epoch().as_u64();
        let gi_size = group_info.tls_serialized_len();

        let mut identity = self.create_identity_from_group_info(group_info)?;
        /*let mut identity = Identity::new_from_credential(
            CIPHERSUITE,
            &self.crypto,
            cred.credential_with_key(),
            cred.signer(),
            self.username.as_bytes()
        );*/

        let kp = self.add_key_package(&mut identity, group_name.clone());

        let elapsed = now.elapsed().as_micros();
        let kp_size = kp.1.tls_serialized_len();
        let result = match self.ds {
            DeliveryService::Request | DeliveryService::PubSubMQTT(_) | DeliveryService::GossipSub(_, Directory::Server) => {
                let ckp = ClientKeyPackages(
                    vec![kp.clone()]
                        .into_iter()
                        .map(|(b, kp)|
                            (b.as_slice().to_vec().into(), KeyPackageForGroup {
                                key_package: KeyPackageIn::from(kp),
                                group: group_name.clone().into_bytes(),
                            })
                        )
                        .collect::<Vec<(TlsByteVecU8, KeyPackageForGroup)>>()
                        .into(),
                );

                match self.backend.publish_key_packages(&identity, &ckp) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(format!("Error sending new key package: {e:?}"))
                }
            }
            DeliveryService::GossipSub(ref broker, Directory::Kademlia) => {
                let broker = broker.lock().unwrap();
                broker.publish_key_package(self.username.clone(), kp.1)?;
                drop(broker);
                Ok(())
            }
        };

        ClientAgent::write_timestamp(self.username.clone(),
            ActionRecord {
                group_name: group_name.clone(),
                action: CGKAAction::GenKP(kp_size, gi_size),
                epoch_change: EpochChange {
                    timestamp: Utc::now().timestamp_nanos_opt().unwrap(),
                    epoch,
                },
                elapsed_time: elapsed,
            }
        );


        self.pending_identities.insert(kp.0.clone(), (group_name.clone(), identity));

        result
        /*let ckp = ClientKeyPackages(
            vec![kp]
                .into_iter()
                .map(|(b, kp)| (b.into(), KeyPackageIn::from(kp)))
                .collect::<Vec<(TlsByteVecU8, KeyPackageIn)>>()
                .into(),
        );

        match self.backend.publish_key_packages(self, &ckp) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Error sending new key package: {e:?}"))
        }*/

    }

    pub fn _create_identity_for_group(&self, group_name: &str, requirement: Option<SsiVcRequirement>)
        -> Result<Identity, String> {
        let user_credential = self.base_identity.borrow().user_credential.clone();
        //log::info!("{} -> Generating Presentation for credential: {:?}", self.username, user_credential);

        let (credential_with_key, signer) = match &user_credential {
            UserCredential::Basic => {
                //log::info!("\tGenerating Presentation (Basic)");
                generate_basic_credential_with_key(
                    self.username.clone().add("#").add(group_name).into_bytes(),
                    CIPHERSUITE.signature_algorithm(),
                    self.crypto(),
                )
            }
            UserCredential::VC(vc, holder_sk) => {
                //log::info!("{} -> Generating Presentation (VC)", self.username);

                generate_vc_credential_with_key(
                    self.username.clone().add("#").add(group_name),
                    &vc,
                    holder_sk,
                    CIPHERSUITE.signature_algorithm(),
                    self.crypto(),
                    &AACGKAResolver
                ).map_err(|e| format!("Error generating VC Presentation: {e}"))?
            }
            UserCredential::SDJWT(sdjwt, holder_sk, issuer_pk) => {
                //log::info!("{} -> Generating Presentation (SD-JWT)", self.username);


                generate_sd_jwt_credential_with_key(
                    self.username.clone().add("#").add(group_name),
                    sdjwt.clone(),
                    &requirement.unwrap_or_default(),
                    CIPHERSUITE.signature_algorithm(),
                    holder_sk.as_slice(),
                    issuer_pk.as_bytes(),
                    self.crypto(),
                ).map_err(|e| format!("Error generating SD-JWT Presentation: {e}"))?
            }
            UserCredential::BBSVC(vc) => {
                //log::info!("{} -> Generating Presentation (BBS_VC)", self.username);

                generate_bbs_vc_credential_with_key(
                    self.username.clone().add("#").add(group_name),
                    &vc,
                    &requirement.unwrap_or_default(),
                    CIPHERSUITE.signature_algorithm(),
                    self.crypto(),
                    &AACGKAResolver
                ).map_err(|e| format!("Error generating BBS Presentation: {e}"))?
            }
            //_ => {Err("Credential type not supported".to_string())?}
        };

        let identity = Identity::new_from_credential(
            self.crypto(),
            user_credential.clone(),
            credential_with_key,
            signer,
        );

        self.backend.register_identity(&identity, group_name.to_string(), None)?;

        Ok(identity)
    }

    pub fn create_identity_from_group_info(&self, group_info: VerifiableGroupInfo) -> Result<Identity, String> {
        let group_name = from_utf8(group_info.group_id().as_slice()).unwrap();

        let requirement = group_info.group_context_extensions()
            .ssi_vc_requirements().unwrap().first();

        self._create_identity_for_group(group_name, requirement.cloned())
    }

    /// Send an application message to the group.
    pub fn send_application_msg(&mut self, msg: String, group_name: String) -> Result<(), String> {
        if self.pending_commits.contains_key(&group_name) {
            return Err("There is a pending commit".to_string());
        }

        let groups = self.groups.borrow();
        let (group, identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let message_out = group
            .mls_group
            .borrow_mut()
            .create_message(&self.crypto, &identity.signer, msg.as_bytes())
            .map_err(|e| format!("{e}"))?;

        let recipients = match self.ds {
            DeliveryService::Request => self.recipients(group, identity),
            _ => Vec::new()
        };

        self.send_to_ds(group_name.clone(), message_out, &recipients)?;
        
        log::debug!(" >>> send: {:?}", msg);

        // XXX: Need to update the client's local view of the conversation to include
        // the message they sent.

        Ok(())
    }

    pub fn add_contact(&mut self, contact: Contact, contact_info: Option<ContactInfo>) -> Result<(), String> {
        let client_name = contact.username.clone();

        if client_name.split("#").next().unwrap().as_bytes()
            != self.base_identity.borrow().identity()
            && self
            .contacts
            .insert(
                contact.username.clone().into_bytes(),
                contact.clone()
            )
            .is_some()
        {
            //log::trace!("Updated client {}", "");
        }
        else {
            match self.ds {
                DeliveryService::Request | DeliveryService::PubSubMQTT(_) => {},
                DeliveryService::GossipSub(ref broker, _) => {
                    if let Some(contact_info) = contact_info {
                        let broker = broker.lock().unwrap();
                        broker.add_contact(contact_info)?;
                        drop(broker);
                    }
                }
            }
        }
        Ok(())
    }

    /// Update the user clients list.
    /// It updates the contacts with all the clients known by the server
    pub fn update_clients(&mut self) -> Result<(), String> {
        match self.backend.list_clients() {
            Ok(mut v) => {
                for c in v.drain(..) {
                    self.add_contact(Contact {
                        username: c.client_name,
                        group_name: c.group_name,
                    },
                    c.contact_info)?;
                }
            }
            Err(e) => log::debug!("update_clients::Error reading clients from DS: {:?}", e),
        }
        log::debug!("update::Processing clients done, contact list is:");
        for contact_id in self.contacts.borrow().keys() {
            log::debug!(
                "update::Parsing contact {:?}",
                from_utf8(contact_id).unwrap()
            );
        }

        Ok(())
    }

    fn process_protocol_message(&mut self, message: ProtocolMessage, sender: String)
                                    -> Result<(Option<ActionRecord>, PostUpdateActions, Option<GroupId>), String>
    {
        let processed_message: ProcessedMessage;
        let group_name = from_utf8(message.group_id().as_slice()).unwrap();
        let mut groups = self.groups.borrow_mut();

        let (group, identity) = match groups.get_mut(group_name) {
            Some(g) => g,
            None => {
                log::error!(
                    "{} -> Error getting group {:?} for a message. Dropping message.",
                    self.username,
                    message.group_id()
                );
                //return Err("error".to_string());
                return Ok((None, PostUpdateActions::None, None));
            }
        };

        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();

        let group_epoch = group.mls_group.borrow_mut().epoch().as_u64();
        let message_epoch = message.epoch().as_u64();

        let mut epoch_change = EpochChange {timestamp, epoch: message_epoch};

        if group_epoch < message_epoch {
            //log::info!("{} -> DESYNC: Group: {} \\\\ Message: {}", self.username, group_epoch, message_epoch);

            // User has become desync-ed
            let message_type = message.content_type();

            if ContentType::Application == message_type
                || ContentType::Proposal == message_type {
                return Ok((None, PostUpdateActions::None, None));
            }

            let previous_state = self.active.insert(group_name.to_string(), (false, message_epoch+1));
            epoch_change.epoch +=1;

            if let Some((active, epoch)) = previous_state {
                if active {
                    log::info!("{} -> Has become DESYNC-ED in {} by message sent by {}.", self.username, group_name, sender);
                }
                if epoch == message_epoch || active {
                    // Keep logging received messages for the current epoch
                    let action_record = ActionRecord {
                        group_name: group_name.to_string(),
                        action: CGKAAction::Process(sender),
                        epoch_change,
                        elapsed_time: 0,
                    };
                    return Ok((Some(action_record), PostUpdateActions::None, None));
                }
                else {
                    // Ignore messages from previous epochs
                    return Ok((None, PostUpdateActions::None, None));

                }
            }

        }

        // Empezar a medir
        let now = ProcessTime::now();

                    // Process the message and release the borrow on mls_group as soon as possible
        {
            let mut mls_group = group.mls_group.borrow_mut();
            processed_message = match mls_group.process_message(&self.crypto, message.clone()) {
                Ok(msg) => msg,
                Err(e) => {
                    // Conflict
                    if ProcessMessageError::ValidationError(ValidationError::WrongEpoch) == e
                        || ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(AeadError)) == e
                        || ProcessMessageError::ValidationError(ValidationError::InvalidSignature) == e
                        || ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(MessageDecryptionError::GenerationOutOfBound)) == e
                    {

                        if ContentType::Application == message.content_type() {
                            return Ok((None, PostUpdateActions::None, None));
                        }

                        log::info!("{} -> CONFLICT IN {} by message sent by {}.", self.username, group.group_name, sender);

                        return Ok((None, PostUpdateActions::None, None));
                    }
                    else {
                        log::error!(
                    "{} -> Error processing unverified message: {:?} -  Dropping message.",
                    self.username, e);
                        return Err(e.to_string());

                    }
                }
            };
        } // mls_group borrow ends here

        let processed_message_credential: Credential = processed_message.credential().clone();

        let sender_name = from_utf8(processed_message_credential.identity()).unwrap();

        let action = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {

                let conversation_message = ConversationMessage::new(
                    String::from_utf8(application_message.into_bytes()).unwrap().clone(),
                    sender_name.to_string(),
                );
                log::info!("{} RECEIVED APPLICATION MESSAGE by {}", self.username, conversation_message.author);

                /*if group_name.is_none() || group_name.clone().unwrap() == group.group_name {
                    messages_out.push(conversation_message.clone());
                }*/
                group.conversation.add(conversation_message);

                None
            }
            ProcessedMessageContent::ProposalMessage(proposal_ptr) => {
                log::info!("{} PROCESSED PROPOSAL from {} IN {}.", self.username, sender_name, group.group_name);
                //log::info!("{:?}", *proposal_ptr);

                group.mls_group.borrow_mut().store_pending_proposal(
                    self.crypto().storage(),
                    *proposal_ptr)
                    .map_err(|e| format!("Error storing proposal: {e}"))?;
                Some(CGKAAction::StoreProp(sender.clone()))
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal_ptr) => {
                // intentionally left blank.
                None
            }
            ProcessedMessageContent::StagedCommitMessage(commit_ptr) => {

                let mut remove_proposal: bool = false;
                if commit_ptr.self_removed() {
                    remove_proposal = true;
                }
                epoch_change.epoch += 1;
                let mut mls_group = group.mls_group.borrow_mut();
                let result = match mls_group.merge_staged_commit(&self.crypto, *commit_ptr) {
                    Ok(()) => {

                        //If there was a pending commit for this group, remove it
                        if let Some((_,_,c)) = self.pending_commits.remove(group_name) {
                            match c.action {
                                CGKAAction::Propose(_) => {},
                                _ => {
                                    self.undo_commit(&mls_group, identity)?;
                                }
                            }
                        }

                        /*if let DSType::GossipSub = self.ds_type {
                            self._publish_group_info(&mls_group, None)?;
                        }*/

                        if remove_proposal {
                            log::debug!("update::Processing StagedCommitMessage removing {} from group {} ", self.username, group.group_name);

                            let elapsed = now.elapsed().as_micros();

                            return Ok((
                                Some(ActionRecord {
                                    group_name:group_name.to_string(),
                                    epoch_change: EpochChange {
                                        epoch: group_epoch + 1, timestamp
                                    },
                                    action: CGKAAction::Process(sender.clone()),
                                    elapsed_time: elapsed
                                } ),
                                PostUpdateActions::Remove,
                                Some(mls_group.group_id().clone()),
                            ));
                        }
                        CGKAAction::Process(sender.clone())
                    }
                    Err(e) => return Err(e.to_string()),
                };

                log::info!("{} PROCESSED COMMIT from {} IN {}. Epoch: {})", self.username, sender_name, group.group_name,
                    mls_group.epoch().as_u64());

                Some(result)
            }
        };

        let elapsed = now.elapsed().as_micros();

        let action_record = match action {
            Some(action_record) => Some(ActionRecord {
                group_name: group_name.to_string(),
                action: action_record,
                epoch_change,
                elapsed_time: elapsed
            }),
            None => None
        };
        Ok((action_record, PostUpdateActions::None, None))
    }

    pub fn process_in_message(&mut self, message: MlsMessageIn, sender: String)
        -> Result<Option<ActionRecord>, String>{
        log::debug!("Reading message format {:#?} ...", message.wire_format());

        if sender == self.username {
            let group_name = from_utf8(message.clone().into_protocol_message().unwrap().group_id().as_slice()).unwrap().to_string();
            log::debug!("{} -> Received message sent by self", self.username);
            self.confirm_commit(group_name.clone())?;
            return Ok(None);
        }

        match message.clone().extract() {
            MlsMessageBodyIn::Welcome(welcome) => {
                // Join the group. (Later we should ask the user to
                // approve first ...)
                let (group_name, epoch_change, elapsed_time) = self.join_group(welcome)?;
                self.active.insert(group_name.clone(), (true, 0));

                self.subscribe(group_name.clone())?;
                //self.create_kp()?;

                let welcome_size = message.tls_serialized_len();

                let action_record = ActionRecord {
                    group_name: group_name.clone(),
                    epoch_change,
                    action: CGKAAction::Welcome(sender.clone(), welcome_size),
                    elapsed_time,
                };
                Ok(Some(action_record))
            }
            MlsMessageBodyIn::PrivateMessage(private_message) => {
                match self.process_protocol_message(private_message.into(), sender.clone()) {
                    Ok(p) => {
                        if p.1 == PostUpdateActions::Remove {
                            return match p.2 {
                                Some(gid) => {
                                    self.unsubscribe(from_utf8(gid.as_slice()).unwrap().to_string())
                                        .map_err(|e| format!("Error unsubscribing: {e}"))?;
                                    let mut grps = self.groups.borrow_mut();
                                    grps.remove_entry(from_utf8(gid.as_slice()).unwrap());
                                    self.group_list
                                        .remove(from_utf8(gid.as_slice()).unwrap());

                                    Ok(p.0)
                                }
                                None => {
                                    Err("update::Error post update remove must have a group id".to_string())
                                }
                            }
                        }
                        else if p.1 == PostUpdateActions::Retry {
                            log::info!("{} -> RETRYING COMMIT", self.username);
                            return self.process_in_message(message.into(), sender);
                        }

                        Ok(p.0)
                    }
                    Err(e) => {
                        //log::error!("{e}");
                        Err(e)
                    }
                }
            },
            MlsMessageBodyIn::PublicMessage(public_message) => {
                //log::debug!("PUBLIC MESSAGE RECEIVED: {:?}", message);
                match self.process_protocol_message(public_message.into(), sender.clone()) {
                    Ok((epoch_change, post_update_actions, _)) => {
                        if post_update_actions == PostUpdateActions::Retry {
                            log::info!("{} -> RETRYING COMMIT", self.username);
                            return self.process_in_message(message.into(), sender);
                        }
                        Ok(epoch_change)
                    }
                    Err(e) => {
                        log::error!("{e}");
                        Err(e)
                    }
                }
//                    process_protocol_message(message.into()).expect("Error processing message");
            }
            _ => panic!("Unsupported message type"),
        }
    }

    /// Update the user. This involves:
    /// * retrieving all new messages from the server
    /// * update the contacts with all other clients known to the server
    pub fn update(
        &mut self
    ) -> Result<Vec<ConversationMessage>, String> {
        log::debug!("Updating {} ...", self.username);

        let messages_out: Vec<ConversationMessage> = Vec::new();

        log::debug!("update::Processing messages for {} ", self.username);
        // Go through the list of messages and process or store them.

        for message in self.backend.recv_msgs(self)?.drain(..) {
            let sender = from_utf8(message.sender()).unwrap().split("#").next().unwrap().to_string();
            self.process_in_message(message.msg.clone(), sender)?;
        }
        log::debug!("update::Processing messages done");

        self.update_clients()?;
        Ok(messages_out)
    }

    /*pub fn leave_group(&mut self, group_name: String) -> Result<(), String> {
        // Get the group ID

        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(&group_name) {
            Some(g) => g,
            None => return Err(format!("No group with name {group_name} known.")),
        };

        // Remove operation on the mls group
        let (remove_message, group_info) = group
            .mls_group
            .borrow_mut()
            .leave_group(&self.backend, &self.identity.borrow().signer)
            .map_err(|e| format!("Failed to remove member from group - {e}"))?;

        // First, send the MlsMessage remove commit to the group.
        log::trace!("Sending commit");
        let group = groups.get_mut(&group_name).unwrap(); // XXX: not cool.
        let group_recipients = self.recipients(group);

        let msg = GroupMessage::new(remove_message.into(), &group_recipients);
        self.backend.send_msg(&msg)?;

        // Second, process the removal on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.crypto)
            .expect("error merging pending commit");

        drop(groups);

        Ok(())
    }*/
    /// Create a group with the given name.
    pub fn create_group(&mut self, group_name: String, requirement: Option<SsiVcRequirement>) -> Result<(), String> {
        self.subscribe(group_name.clone())?;
        log::debug!("{} creates group {}", self.username, group_name);
        let group_id = group_name.as_bytes();
        let mut group_aad = group_id.to_vec();
        group_aad.extend(b" AAD");

        let identity = self._create_identity_for_group(&group_name, requirement.clone())?;

        /*let identity = Identity::new_from_credential(
            CIPHERSUITE,
            &self.crypto,
            cred.credential_with_key(),
            cred.signer(),
            self.username.as_bytes()
        );*/

        let group_config = create_group_config_with_requirement(requirement.clone());

        let now = ProcessTime::now();
        let mut mls_group = MlsGroup::new_with_group_id(
            &self.crypto,
            &identity.signer,
            &group_config,
            GroupId::from_slice(group_id),
            identity.credential_with_key.clone()
        )
        .expect("Failed to create MlsGroup");
        let elapsed = now.elapsed().as_micros();
        //println!("{:?}", now.elapsed());
        mls_group.set_aad(group_aad);

        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let epoch = mls_group.epoch().as_u64();

        let group = Group {
            group_name: group_name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        if self.groups.borrow().contains_key(&group_name) {
            panic!("Group '{}' existed already", group_name);
        }
        self.active.insert(group_name.clone(), (true, 0));

        self._publish_group_info(&group.mls_group.borrow(), &identity, None)?;
        self.groups.borrow_mut().insert(group_name.clone(), (group, identity));

        ClientAgent::write_timestamp(self.username.clone(), ActionRecord {
            epoch_change: EpochChange{
                timestamp, epoch
            },
            group_name: group_name.clone(),
            action: CGKAAction::Create,
            elapsed_time: elapsed
        });

        Ok(())
    }

    /// Invite user with the given name to the group.
    pub fn invite(&mut self, name: String, group_name: String) -> Result<EpochChange, String> {
        // First we need to get the key package for {id} from the DS.
        let contact = match self.contacts.values().find(|c| c.username == name) {
            Some(v) => v,
            None => return Err(format!("No contact with name {name} known.")),
        };

        // Reclaim a key package from the server
        let joiner_key_package = self.consume_key_package(&contact)?;

        let now = ProcessTime::now();
        // Build a proposal with this key package and do the MLS bits.
        let (out_messages, welcome, new_group_info) = {
            let mut groups = self.groups.borrow_mut();
            let (group, identity) = match groups.get_mut(&group_name) {
                Some(g) => g,
                None => return Err(format!("No group with name {group_name} known.")),
            };

            let result = group
                .mls_group
                .borrow_mut()
                .add_members(
                    &self.crypto,
                    &identity.signer,
                    &[joiner_key_package.into()],
                )
                .map_err(|e| format!("Failed to add member to group - {e}"))?;

            result
        };
        let elapsed = now.elapsed().as_micros();

        let stored_welcome = StoredWelcome {
            welcome: welcome.clone(),
            recipients: vec![name.clone()]
        };


        let size = out_messages.tls_serialized_len();
        // Second, process the invitation on our end.
        let epoch_change = self.post_process_commit(
            group_name.clone(),
            out_messages,
            new_group_info,
            Some(stored_welcome),
            CGKAAction::Invite(name.clone(), size),
            elapsed
        )?;

        Ok(epoch_change)
    }

    pub fn propose(&mut self, action: CGKAAction, group_name: String) -> Result<(), String> {

        let proposal = {
            let groups = self.groups.borrow();
            let (group, _identity) = match groups.get(&group_name) {
                Some(g) => g,
                None => return Err("Unknown group".to_string()),
            };

            match action.clone() {
                CGKAAction::Update(_) => {
                    let leaf_node_parameters = LeafNodeParameters::default();
                    Propose::Update(leaf_node_parameters)
                }
                CGKAAction::Invite(user, _) => {
                    for prop in group.mls_group.borrow_mut().pending_proposals() {
                        match prop.proposal() {
                            Proposal::Add(p) => {
                                if user.eq(from_utf8(p.key_package().leaf_node().credential().identity()).unwrap()) {
                                    return Err("There is already a pending proposal to add this user.".to_string());
                                }
                            }
                            _ => {}
                        }
                    }

                    let contact = match self.contacts.values().find(|c| c.username == user) {
                        Some(v) => v,
                        None => return Err(format!("No contact with name {user} known.")),
                    };

                    // Reclaim a key package from the server
                    let joiner_key_package = self.consume_key_package(&contact)?;
                    //mls_group.propose_add_member(&self.crypto, &self.identity.borrow().signer, &joiner_key_package.into())
                    Propose::Add(joiner_key_package.into())
                }
                CGKAAction::Remove(user, _) => {
                    Propose::Remove(self.find_member_index(user, group)?.u32())
                }
                _ => { unreachable!() }
            }
        };

        let now = ProcessTime::now();
        let (out_message, _) = {
            let groups = self.groups.borrow();
            let (group, identity) = match groups.get(&group_name) {
                Some(g) => g,
                None => return Err("Unknown group".to_string()),
            };

            let result = group
                .mls_group
                .borrow_mut()
                .propose(&self.crypto, &identity.signer, proposal, ProposalOrRefType::Proposal)
                .map_err(|e| format!("{e}"))?;

            result
        };

        let elapsed = now.elapsed().as_micros();

        let size = out_message.tls_serialized_len();

        let action = match action {
            CGKAAction::Update(_) => CGKAAction::Update(size),
            CGKAAction::Invite(user, _) => CGKAAction::Invite(user, size),
            CGKAAction::Remove(user, _) => CGKAAction::Remove(user, size),
            _ => {unreachable!()}
        };

        let _epoch_change = self.post_process_commit(
            group_name.clone(),
            out_message,
            None,
            None,
            CGKAAction::Propose(Box::new(action)),
            elapsed
        )?;
        Ok(())
    }

    pub fn pending_proposals(&mut self, group_name: String) -> Result<usize, String> {
        let invalid_proposals = self.invalid_proposals(group_name.clone())?;

        let groups = self.groups.borrow();
        let (group, _identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let num = group.mls_group.borrow().pending_proposals().count() - invalid_proposals.len();

        Ok(num)
    }

    fn invalid_proposals(&self, group_name: String) -> Result<Vec<QueuedProposal>, String> {
        let groups = self.groups.borrow();
        let (group, _identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let invalid_proposals = {
            let mls_group = group.mls_group.borrow();
            mls_group.pending_proposals().cloned().filter(
                |p| {
                    if let Proposal::Remove(prop) = p.proposal() {
                        if prop.removed() == mls_group.own_leaf_index() {
                            return true;
                        }
                    }
                    return false;
                }
            ).collect::<Vec<QueuedProposal>>()
        };

        Ok(invalid_proposals)
    }

    pub fn commit_to_proposals(&mut self, group_name: String, amount: usize) -> Result<EpochChange, String> {

        let ((out_message, welcome, new_group_info), new_users, elapsed) = {
            let invalid_proposals = self.invalid_proposals(group_name.clone())?;

            let groups = self.groups.borrow();
            let (group, identity) = match groups.get(&group_name) {
                Some(g) => g,
                None => return Err("Unknown group".to_string()),
            };

            for prop in invalid_proposals {
                group.mls_group.borrow_mut().remove_pending_proposal(
                    self.crypto.storage(),
                    &prop.proposal_reference()
                )
                    .map_err(|e| format!("Failed to remove proposal: {:?}", e))?;
            }
            let proposals_to_remove = {
                let pending_proposals = group.mls_group.borrow_mut().pending_proposals().cloned().collect::<Vec<QueuedProposal>>();
                let amount_to_remove = pending_proposals.len() - amount;

                pending_proposals.choose_multiple(
                    &mut rand::thread_rng(),
                    amount_to_remove
                ).cloned().collect::<Vec<QueuedProposal>>()
            };
            for prop in proposals_to_remove {
                group.mls_group.borrow_mut().remove_pending_proposal(
                    self.crypto.storage(),
                    &prop.proposal_reference()
                )
                    .map_err(|e| format!("Failed to remove proposal: {:?}", e))?;
            }

            let new_users = group.mls_group.borrow_mut().pending_proposals()
                .filter_map(|p| {
                    if let Proposal::Add(add) = p.proposal() {
                        // Intentar convertir la identidad a UTF-8 y devolverla como String
                        from_utf8(add.key_package().leaf_node().credential().identity())
                            .ok()
                            .map(|identity| identity.to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>();

            let now = ProcessTime::now();
            let result = group
                .mls_group
                .borrow_mut()
                .commit_to_pending_proposals(
                    &self.crypto,
                    &identity.signer,
                )
                .map_err(|e| format!("{e}"))?;

            let elapsed = now.elapsed().as_micros();
            (result, new_users, elapsed)
        };

        let stored_welcome = match welcome {
            Some(welcome) => Some(StoredWelcome {
                welcome: welcome.clone(),
                recipients: new_users
            }),
            None => None,
        };

        let size = out_message.tls_serialized_len();

        let epoch_change = self.post_process_commit(
            group_name.clone(),
            out_message,
            new_group_info,
            stored_welcome,
            CGKAAction::Commit(amount, size),
            elapsed
        )?;
        Ok(epoch_change)
    }
    pub fn update_state(&mut self, group_name: String) -> Result<EpochChange, String> {

        let now = ProcessTime::now();

        // Get the group ID
        let (update_message, _welcome, new_group_info) = {
            let mut groups = self.groups.borrow_mut();
            let (group, identity) = match groups.get_mut(&group_name) {
                Some(g) => g,
                None => return Err(format!("No group with name {group_name} known.")),
            };

            // Remove operation on the mls group
            let result = group
                .mls_group
                .borrow_mut()
                .self_update(&self.crypto, &identity.signer, LeafNodeParameters::default())
                .map_err(|e| format!("Failed to self update - {e}"))?;

            (result.commit().clone(), result.welcome().cloned(), result.group_info().cloned())
        };
        let elapsed = now.elapsed().as_micros();

        let size = update_message.tls_serialized_len();
        let epoch_change = self.post_process_commit(
            group_name.clone(),
            update_message,
            new_group_info,
            None,
            CGKAAction::Update(size),
            elapsed
        )?;
        Ok(epoch_change)
    }

    /// Remove user with the given name from the group.
    pub fn remove(&mut self, name: String, group_name: String) -> Result<EpochChange, String> {

        let now = ProcessTime::now();
        let (remove_message, _welcome, new_group_info) = {
            let mut groups = self.groups.borrow_mut();
            let (group, identity) = match groups.get_mut(&group_name) {
                Some(g) => g,
                None => return Err(format!("No group with name {group_name} known.")),
            };

            // Get the client leaf index

            let leaf_index = match self.find_member_index(name.clone(), group) {
                Ok(l) => l,
                Err(e) => return Err(e),
            };

            // Remove operation on the mls group
            let result = group
                .mls_group
                .borrow_mut()
                .remove_members(&self.crypto, &identity.signer, &[leaf_index])
                .map_err(|e| format!("Failed to remove member from group - {e}"))?;

            result
        };
        let elapsed = now.elapsed().as_micros();

        let size = remove_message.tls_serialized_len();
        let epoch_change = self.post_process_commit(
            group_name.clone(),
            remove_message,
            new_group_info,
            None,
            CGKAAction::Remove(name.clone(), size),
            elapsed
        )?;

        Ok(epoch_change)
    }

    pub fn publish_group_info(&self, group_name: String) -> Result<(), String> {
        let groups = self.groups.borrow();
        let (group, identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let result = self._publish_group_info(&group.mls_group.borrow(), identity, None);

        result
    }
    
    fn _publish_group_info(&self, group: &MlsGroup, identity: &Identity, group_info: Option<GroupInfo>) -> Result<(), String> {
        let group_info = match group_info {
            Some(gi) => gi.into(),
            None => {
                group.export_group_info(&self.crypto, &identity.signer, true)
                    .map_err(|e| format!("Failed to export group info - {e}"))?
                    .into_verifiable_group_info().unwrap()
            }
        };

        let group_name = from_utf8(group.group_id().as_slice()).unwrap().to_string();

        // Finally, send GroupInfo.
        log::trace!("Sending new group info");
        match self.ds {
            DeliveryService::Request | DeliveryService::PubSubMQTT(_) | DeliveryService::GossipSub(_, Directory::Server) => {
                self.backend
                    .publish_group_info(self.username.clone(), group_name, group_info)
            }
            
            DeliveryService::GossipSub(ref broker, Directory::Kademlia) => {
                    let broker = broker.lock().unwrap();
                    broker.publish_group_info(group_name, group_info)?;
                    drop(broker);
                    Ok(())
            }
        }
    }

    pub fn external_join(&mut self, group_name: String, group_info: VerifiableGroupInfo) -> Result<EpochChange, String> {
        log::info!("{} -> Joining group {}", self.username, group_name);
        self.subscribe(group_name.clone()).unwrap();

        let identity = match self.has_identity_for_group(group_name.clone().as_str()) {
            Some(i) => i,
            None => {
                self.create_identity_from_group_info(group_info.clone())?
            }
        };
        /*let identity = Identity::new_from_credential(
            CIPHERSUITE,
            &self.crypto,
            cred.credential_with_key(),
            cred.signer(),
            self.username.as_bytes()
        );*/

        //self.update_clients();
        // First we need to get the group info for {id} from the DS.
        let group_id = group_name.as_bytes();
        let mut group_aad = group_id.to_vec();
        group_aad.extend(b" AAD");
        let gi_size = group_info.tls_serialized_len();


        // Build a proposal with this key package and do the MLS bits.
        //let mut groups = self.groups.borrow_mut();
        let group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let now = ProcessTime::now();
        let (new_mls_group, out_messages, new_group_info) = MlsGroup::join_by_external_commit(
            &self.crypto,
            &identity.signer,
            None,
            group_info,
            &group_config,
            None, None,
            group_aad.as_slice(),
            identity.credential_with_key.clone()
        ).expect("Error creating external join message");

        let elapsed = now.elapsed().as_micros();

        let new_group = Group {
            group_name: group_name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(new_mls_group),
        };

        self.active.insert(group_name.clone(), (true, 0));

        {
            let mut groups = self.groups.borrow_mut();
            /*match groups.insert(group_name.clone(), new_group) {
                Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
                None => Ok(()),
            }?;*/
            groups.insert(group_name.clone(), (new_group, identity));
        }

        let commit_size = out_messages.tls_serialized_len();

        let epoch_change = self.post_process_commit(
            group_name.clone(),
            out_messages,
            new_group_info,
            None,
            CGKAAction::Join(commit_size, gi_size),
            elapsed
        )?;

        //let new_group = groups.get_mut(&group_name).unwrap();

        Ok(epoch_change)
    }

    fn post_process_commit(
        &mut self,
        group_name: String,
        msg_out: MlsMessageOut,
        group_info: Option<GroupInfo>,
        welcome: Option<StoredWelcome>,
        action: CGKAAction,
        elapsed_time: u128
    ) -> Result<EpochChange, String> {
        let groups = self.groups.borrow();
        let (group, identity) = groups.get(&group_name).expect("Group should be present after mutable borrow.");
        let mls_group = group.mls_group.borrow_mut();

        if !matches!(action, CGKAAction::Propose(..)) {
            // Sleep 1 sec to give time to new users to subscribe
            if !matches!(self.ds, DeliveryService::GossipSub(..)) {
                thread::sleep(Duration::from_secs(1));
            }
        }

        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        //Correcting the fact that commit is pending
        let epoch = mls_group.epoch().as_u64();

        let action_record = ActionRecord {
            action: action.clone(),
            group_name: group_name.clone(),
            epoch_change: EpochChange {
                timestamp,
                epoch
            },
            elapsed_time
        };

        log::trace!("Sending commit");
        let group_recipients = match self.ds {
            DeliveryService::Request => {self.mls_recipients(&mls_group, identity)}
            _ => {Vec::new()}
        };

        self.send_to_ds(group_name.clone(), msg_out, &group_recipients)?;
        self.pending_commits.insert(group_name.clone(), (group_info.clone(), welcome, action_record));

        /*if let DeliveryService::Request = self.ds {
            self.confirm_commit(group_name.clone())?;
        }*/

        Ok(EpochChange {
            timestamp,
            epoch
        })
    }

    /// Join a group with the provided welcome message.
    fn join_group(&mut self, welcome: Welcome) -> Result<(String, EpochChange, u128), String> {
        log::debug!("{} joining group ...", self.username);


        //TODO
        //let mut ident = self.identity.borrow_mut();
        let identity = welcome
            .secrets()
            .iter()
            .find_map(|secret| {
                let key_package_hash = &secret.new_member();
                if self.pending_identities.contains_key(key_package_hash) {
                    let mut identity = self.pending_identities.remove(key_package_hash).unwrap().1;

                    if identity.kp.contains_key(key_package_hash.as_slice()) {
                        identity.kp.remove(key_package_hash.as_slice());
                    }

                    Some(identity)
                } else {
                    None
                }
            })
            .ok_or("Received Welcome but corresponding identity does not exist")?;

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let now = ProcessTime::now();

        let staged_welcome = StagedWelcome::new_from_welcome(&self.crypto, &group_config, welcome, None)
            .map_err(|e| format!("Error staging Welcome: {:?}", e))?;

        let mut mls_group = staged_welcome.into_group(&self.crypto)
            .map_err(|e| format!("Error joining group: {:?}", e))?;

        let elapsed = now.elapsed().as_micros();

        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();
        let epoch = mls_group.epoch().as_u64();

        let group_id = mls_group.group_id().to_vec();
        // XXX: Use Welcome's encrypted_group_info field to store group_name.
        let group_name = String::from_utf8(group_id.clone()).unwrap();
        let group_aad = group_name.clone() + " AAD";

        mls_group.set_aad(group_aad.as_bytes().to_vec());

        let group = Group {
            group_name: group_name.clone(),
            conversation: Conversation::default(),
            mls_group: RefCell::new(mls_group),
        };

        log::trace!("   {}", group_name);

        /*match self.groups.borrow_mut().insert(group_name.clone(), group) {
            Some(old) => Err(format!("Overrode the group {:?}", old.group_name)),
            None => Ok((group_name, EpochChange {
                timestamp,
                epoch
            })),
        }*/

        self.groups.borrow_mut().insert(group_name.clone(), (group, identity));

        Ok((
            group_name,
            EpochChange {
                timestamp,
                epoch
            },
            elapsed
        ))
    }

    fn send_to_ds(&self, group_name: String, message_out: MlsMessageOut, recipients: &Vec<Vec<u8>>) -> Result<(), String> {

        let msg = GroupMessage::new(message_out.into(),self.username.clone().into(), recipients);
        match self.ds {
            DeliveryService::Request => {
                self.backend.send_msg(&msg)
            }
            DeliveryService::PubSubMQTT(ref broker)  => {
                let broker = broker.lock().unwrap();
                broker.send_msg(&msg, group_name.clone())
            }
            DeliveryService::GossipSub(ref broker, _) => {
                let broker = broker.lock().unwrap();
                broker.send_msg(&msg, group_name.clone())
            }
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }


    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /*pub fn add_broker(&mut self, broker: Arc<Mutex<Broker>>) {
        self.broker = Some(broker);
    }*/

    pub fn group_list(&self) -> Vec<String> {
        self.groups.borrow().keys().cloned().collect()
    }



    pub(crate) fn confirm_commit(&mut self, group_name: String) -> Result<(), String>{
        // Get and remove from the pending commits
        let (group_info, stored_welcome, action_record) = match self.pending_commits.remove(&group_name) {
            Some(gi) => gi,
            None => return Ok(()),
        };

        if let Some(stored_welcome) = stored_welcome {
            let StoredWelcome {welcome, recipients} = stored_welcome;

            for recipient in recipients {
                let msg = GroupMessage::new(welcome.clone().into(),self.username.clone().into(), &[recipient.clone().into_bytes()]);

                match self.ds {
                    DeliveryService::Request => {
                        log::trace!("Sending welcome");
                        self.backend
                            .send_welcome(&msg)?;
                    }
                    DeliveryService::PubSubMQTT(ref broker) => {
                        let broker = broker.lock().unwrap();
                        broker.send_welcome(&msg, recipient.clone())?;
                        drop(broker)
                    }
                    DeliveryService::GossipSub(ref broker, _) => {
                        let broker = broker.lock().unwrap();
                        broker.send_welcome(&msg, recipient.clone())?;
                        drop(broker)
                    }
                }
            }
        }

        //log::info!("{} -> Confirming commit", self.username);
        let edited_record = match action_record.clone().action {
            CGKAAction::Propose(_) => {action_record},
            _ => {
                {
                    let groups = self.groups.get_mut();
                    let (group, _identity) = match groups.get_mut(&group_name) {
                        Some(g) => g,
                        None => return Err(format!("No group with name {group_name} known.")),
                    };

                    let mut mls_group = group.mls_group.borrow_mut();

                    let now = ProcessTime::now();
                    mls_group
                        .merge_pending_commit(&self.crypto)
                        .expect("error merging pending commit");

                    let elapsed = now.elapsed().as_micros();
                }


                let groups = self.groups.borrow();
                let (group, identity) = groups.get(&group_name).expect("Group should be present after mutable borrow.");
                let mls_group = group.mls_group.borrow();
                self._publish_group_info(&mls_group, identity, group_info.into())?;

                // "Epoch" was calculated while the commit was pending
                ActionRecord {
                    epoch_change: EpochChange {
                        epoch: action_record.epoch_change.epoch + 1,
                        ..action_record.epoch_change.clone()
                    },
                    ..action_record
                }
            }
        };

        ClientAgent::write_timestamp(self.username.clone(), edited_record);

        Ok(())

    }

    fn undo_commit(&self, mls_group: &MlsGroup, identity: &Identity) -> Result<(), String> {
        log::info!("{} -> undoing commit", self.username);
        self._publish_group_info(mls_group, identity, None)

    }

    pub fn is_authorised(&self, group_name: String, authorization_policy: AuthorizationPolicy) -> Result<bool, String> {

        // If the user is desync, not authorised
        if !self.active.get(&group_name).unwrap_or(&(false, 0)).0 {
            log::info!("{} -> Desync-ed, cannot issue updates", self.username);
            return Ok(false);
        }

        let groups = self.groups.borrow();
        let (group, _identity) = match groups.get(&group_name) {
            Some(g) => g,
            None => return Err("Unknown group".to_string()),
        };

        let mls_group = group.mls_group.borrow();

        let leaf_node_index = mls_group.own_leaf_index().u32();

        match authorization_policy {
            AuthorizationPolicy::Random => Ok(true),
            AuthorizationPolicy::First => {
                Ok(leaf_node_index == 0)
            }
            AuthorizationPolicy::Last => {
                Ok(leaf_node_index == mls_group.members().count() as u32 - 1)
            }
        }
    }
}
