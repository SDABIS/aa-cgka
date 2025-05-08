use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::{io, select};
use libp2p::{gossipsub, noise, rendezvous, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId, Swarm, kad};
use libp2p::kad::store::RecordStore;

use crate::user::{EpochChange, User};
use std::hash::{Hash, Hasher};
use chrono::Utc;
use futures::StreamExt;
use kad::QueryResult;
use libp2p::kad::{GetRecordOk, PeerRecord, QueryId, Record, RecordKey, StoreInserts};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::behaviour::toggle;
use tls_codec::Deserialize;
use tokio::sync::mpsc::{Receiver};
use tokio::sync::oneshot;
use ds_lib::ContactInfo;
use openmls::messages::group_info::VerifiableGroupInfo;
use crate::client_agent::{ActionRecord, CGKAAction, ClientAgent};
use crate::pubsub::parse_message;
use crate::user_parameters::{Directory, GossipSubConfig};
use std::thread;

#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub rendezvous: rendezvous::client::Behaviour,
    pub kademlia: toggle::Toggle<kad::Behaviour<MemoryStore>>,
}

const NAMESPACE: &str = "rendezvous";


#[derive(Debug)]
pub enum GossipSubQueueMessage {
    Message(String, Vec<u8>),
    Subscribe(String, String),
    Unsubscribe(String, String),
    Publish(String, String, Vec<u8>),
    Get(String, oneshot::Sender<Result<Vec<u8>, String>>, bool),
    Peek(String, oneshot::Sender<Result<Vec<u8>, String>>),
    AddPeer(ContactInfo),
    ContactInfo(oneshot::Sender<Result<ContactInfo, String>>),
}

pub struct GossipSubUpdater {
    user_name: String,
    users: HashMap<String, Arc<Mutex<User>>>,
    subscriptions: HashMap<String, Vec<String>>,
    key: libp2p::identity::Keypair,
    command_receiver: Receiver<GossipSubQueueMessage>,
    pending_get_requests: HashMap<QueryId, (oneshot::Sender<Result<Vec<u8>, String>>, bool)>,
    config: GossipSubConfig,
}

impl GossipSubUpdater {
    pub fn new(user_name: String, users: HashMap<String, Arc<Mutex<User>>>, config: GossipSubConfig, rx: Receiver<GossipSubQueueMessage>) -> Self {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let mut subscriptions = HashMap::new();
        for user_name in users.keys() {
            subscriptions.insert(user_name.clone(), Vec::new());
        }

        /*let rendezvous_point_address: Multiaddr = "/dns/rendezvous/tcp/62649".parse::<Multiaddr>().unwrap();
        let rendezvous_point: PeerId = "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        .parse()
        .unwrap();*/

        Self {
            user_name,
            users,
            subscriptions,
            key,
            command_receiver: rx,
            pending_get_requests: HashMap::new(),
            config,
        }
    }

    /*pub fn identity(&self) -> Option<(String, String)> {
        match self.multiaddr {
            Some(ref multiaddr) => Some((self.key.public().to_peer_id().to_base58(), multiaddr.to_string())),
            None => None
        }
    }*/

    #[tokio::main]
    pub async fn run(&mut self) {

        let rendezvous_point_address: Multiaddr = self.config.rendezvous_address.clone().parse::<Multiaddr>().unwrap();
        let rendezvous_point: PeerId = self.config.rendezvous_id.clone()
        .parse()
        .unwrap();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(self.key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            ).expect("Failed to create TCP")
            .with_dns().expect("Failed to create DNS")
            //.with_quic()
            .with_behaviour(|key| {
                // To content-address message, we can take the hash of message and use it as an ID.
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };

                // Set a custom gossipsub configuration
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .max_transmit_size(20 * 1024 * 1024)
                    .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                    .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                    .allow_self_origin(true)
                    .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                    .build()
                    .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

                // build a gossipsub network behaviour
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                let rendezvous = rendezvous::client::Behaviour::new(key.clone());

                let kademlia = match self.config.directory {
                    Directory::Server => {
                        toggle::Toggle::from(None)
                    }
                    Directory::Kademlia => {
                        let mut kademlia_config = kad::Config::default();

                        kademlia_config.set_record_filtering(StoreInserts::FilterBoth);
                        kademlia_config.set_periodic_bootstrap_interval(Some(Duration::from_secs(30)));
                        kademlia_config.set_query_timeout(Duration::from_secs(10));
                        //kademlia_config.set_replication_interval(Some(Duration::from_secs(10)));
                        //kademlia_config.set_publication_interval(Some(Duration::from_secs(20)));

                        let kademlia = kad::Behaviour::with_config(
                            key.public().to_peer_id(),
                            MemoryStore::new(key.public().to_peer_id()),
                            kademlia_config.clone(),
                        );
                        toggle::Toggle::from(Some(kademlia))
                    }
                };

                Ok(MyBehaviour { gossipsub, rendezvous,  kademlia })
            }).expect("Error generating behaviour")

            //.with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))

            .build();


        if let Directory::Kademlia = self.config.directory {
            swarm.behaviour_mut().kademlia.as_mut().unwrap().set_mode(Some(kad::Mode::Server));
        }

        let addr: Multiaddr = ("/ip4/".to_owned() + self.config.address.as_str() + "/tcp/0").parse().unwrap();

        swarm.listen_on(addr).expect("Error starting Listen");

        swarm.select_next_some().await;
        let mut added_address = false;
        let mut connected_to_rendezvous = false;
        let mut registered = false;

        swarm.dial(rendezvous_point_address.clone()).unwrap();
        let mut discover_tick = tokio::time::interval(Duration::from_secs(240));
        let mut cookie = None;

        loop {
            select! {
                Some(msg) = self.command_receiver.recv() => {
                    self.handle_command(&mut swarm, msg);
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        log::info!("{} -> Local node is listening on {}", self.user_name, address);
                        // Register our external address. Needs to be done explicitly
                        swarm.add_external_address(address);
                        added_address= true;
                        
                        if connected_to_rendezvous && !registered {
                            registered = true;
                            swarm.behaviour_mut().rendezvous.register(
                                rendezvous::Namespace::from_static("rendezvous"),
                                rendezvous_point.clone(),
                                Some(60 * 60 * 4),
                            ).expect("Failed to register");
                        }
                    }

                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == rendezvous_point => {
                        connected_to_rendezvous = true;
                        
                        if added_address && !registered {
                            registered = true;
                            swarm.behaviour_mut().rendezvous.register(
                                rendezvous::Namespace::from_static("rendezvous"),
                                rendezvous_point.clone(),
                                None,
                            ).expect("Failed to register");
                        }
                        log::info!("Connection established with rendezvous point {}", peer_id);
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Rendezvous(rendezvous_event)) => {
                        self.handle_rendezvous_event(&mut swarm, rendezvous_event, &mut cookie);
                    },
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub_event)) => {
                        self.handle_gossipsub_event(gossipsub_event);
                    }

                    SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(kademlia_event)) => {
                        self.handle_kademlia_event(&mut swarm, kademlia_event);
                    }

                    _ => {}
                },

                _ = discover_tick.tick() => {
                    //log::info!("{} -> Requesting Rendezvous...", self.user_name);
                    swarm.behaviour_mut().rendezvous.discover(
                            Some(rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap()),
                        cookie.clone(),
                        None,
                        rendezvous_point.clone()
                    )
                }
            }
        }
    }


    fn handle_command(&mut self, swarm: &mut Swarm<MyBehaviour>, msg: GossipSubQueueMessage) {
        match msg {
            GossipSubQueueMessage::Message(topic_str, message) => {
                let topic = gossipsub::IdentTopic::new(topic_str.clone());
                //log::info!("{} -> About to send to topic: {:?}", self.user_name, topic);

                match swarm.behaviour_mut().gossipsub.publish(topic.clone(), message.clone()) {
                    Err(e) => {
                        log::error!("Error publishing message: {:?}", e);
                    }
                    _ => {}
                }

                self.deliver_to_users(topic_str, message);

            }
            GossipSubQueueMessage::Subscribe(user, topic) => {
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());
                swarm.behaviour_mut().gossipsub.subscribe(&topic_hash).unwrap();

                self.subscriptions.get_mut(&user).unwrap().push(topic);
            }
            GossipSubQueueMessage::Unsubscribe(user,topic) => {
                let topic_hash = gossipsub::IdentTopic::new(topic.clone());
                swarm.behaviour_mut().gossipsub.unsubscribe(&topic_hash);

                self.subscriptions.get_mut(&user).unwrap().retain(|sub| !sub.eq(&topic));
            }

            GossipSubQueueMessage::Publish(_name, key, value) => {
                log::info!("{} -> Publishing record with key: {key}", self.user_name);
                let kad_key = kad::RecordKey::new(&key);
                let record = kad::Record {
                    key: kad_key.clone(),
                    value: value.clone(),
                    publisher: None,
                    expires: None,
                };

                /*if key.contains("group_info") {
                    //log::info!("{:?}", key);
                    let group_name = from_utf8(kad_key.as_ref()).unwrap().split("/").last().unwrap().to_string();
                    match self.write_timestamp(name, group_name, value, CGKAAction::SetRecord) {
                        Ok(_) => {}
                        Err(e) => { log::error!("Error writing timestamp: {:?}", e); }
                    }
                }*/

                let _query_id = swarm.behaviour_mut().kademlia.as_mut().unwrap()
                    .put_record(record, kad::Quorum::All)
                    .expect("Failed to store record locally.");

                //log::info!("{} -> New Query: {:?}", self.user_name, swarm.behaviour_mut().kademlia.store_mut().get(&kad_key).unwrap());

                /*swarm.behaviour_mut().kademlia
                    .start_providing(kad_key.clone())
                    .expect("Failed to start providing record.");*/
            }

            GossipSubQueueMessage::Get(key, response, remove) => {
                if let Directory::Kademlia = self.config.directory {
                    let kad_key = RecordKey::new(&key);
                    //log::info!("{} -> Requesting record with key: {key}", self.user_name);
                    let result = swarm.behaviour_mut().kademlia.as_mut().unwrap().get_record(kad_key);
                    self.pending_get_requests.insert(result, (response, remove));
                }
                else {
                    match response.send(Err("Directory was not configured as Kademlia".to_string())) {
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("Error sending response: {:?}", e);
                        }
                    }
                }
            }
            GossipSubQueueMessage::Peek(key, response) => {
                if let Directory::Kademlia = self.config.directory {
                    let kad_key = RecordKey::new(&key);
                    let result = swarm.behaviour_mut().kademlia.as_mut().unwrap().get_record(kad_key);
                    self.pending_get_requests.insert(result, (response, false));
                }

                else {
                    match response.send(Err("Directory was not configured as Kademlia".to_string())) {
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("Error sending response: {:?}", e);
                        }
                    }
                }

            }

            GossipSubQueueMessage::AddPeer(_contact_info) => {
                /*log::info!("Adding peer: {:?}", contact_info);
                let peer_id: PeerId = contact_info.peer_id.parse().unwrap();
                let multiaddr: Multiaddr = contact_info.multiaddr.parse().unwrap();
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);*/
            }

            GossipSubQueueMessage::ContactInfo(sender) => {
                // Obtain multiaddr
                let multiaddr = Swarm::listeners(&swarm).collect::<Vec<&Multiaddr>>()
                    .first().unwrap().clone().to_string();

                let contact_info = ContactInfo {
                    peer_id: self.key.clone().public().to_peer_id().to_base58(),
                    multiaddr,
                };

                match sender.send(Ok(contact_info)) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Error sending response: {:?}", e);
                    }
                }
            }
        }
    }
    fn handle_rendezvous_event(&mut self, swarm: &mut Swarm<MyBehaviour>, event: rendezvous::client::Event, cookie: &mut Option<rendezvous::Cookie>) {
        match event {
            rendezvous::client::Event::Registered {
                namespace,
                ttl,
                rendezvous_node,
            } => {
                let rendezvous_point: PeerId = self.config.rendezvous_id.clone()
                    .parse()
                    .unwrap();

                log::debug!(
                     "Registered for namespace '{}' at rendezvous point {} for the next {} seconds",
                     namespace,
                     rendezvous_node,
                     ttl
                 );
                 swarm.behaviour_mut().rendezvous.discover(
                    Some(rendezvous::Namespace::new(NAMESPACE.to_string()).unwrap()),
                    cookie.clone(),
                    None,
                    rendezvous_point.clone()
                )

            }
            rendezvous::client::Event::RegisterFailed {
                rendezvous_node,
                namespace,
                error,
            } => {
                tracing::error!(
                    "Failed to register: rendezvous_node={}, namespace={}, error_code={:?}",
                    rendezvous_node,
                    namespace,
                    error
                );
            }

            rendezvous::client::Event::Discovered {
                registrations,
                cookie: new_cookie,
                ..
            } => {
                cookie.replace(new_cookie);

                for registration in registrations {
                    let peer_id = registration.record.peer_id();
                    log::debug!("{} -> Discovered peer {:?} with addresses {:?}", self.user_name, peer_id, registration.record.addresses());

                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    if let Directory::Kademlia = self.config.directory {
                        for address in registration.record.addresses() {
                            swarm.behaviour_mut().kademlia.as_mut().unwrap().add_address(&peer_id, address.clone());
                        }
                    }
                }
            }

            _ => {}
        }
    }

    pub fn write_timestamp(&self, user_name: String, group_name: String, serialized_group_info: Vec<u8>, action: CGKAAction) -> Result<(), String> {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap();

        if serialized_group_info.is_empty() {
            return Ok(());
        }

        let group_info = match VerifiableGroupInfo::tls_deserialize(&mut serialized_group_info.as_slice()) {
            Ok(gi) => gi,
            Err(e) => {
                return Err(format!("Error deserializing group info for Latency measure: {:?}", e));
            }
        };

        let epoch = group_info.group_context().epoch().as_u64();
        let epoch_change = EpochChange {
            timestamp,
            epoch,
        };
        let action_record = ActionRecord {
            group_name,
            epoch_change,
            action,
            elapsed_time: 0,
        };

        ClientAgent::write_timestamp(self.user_name.clone(), action_record);

        Ok(())
    }
    fn handle_gossipsub_event(&self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source: _,
                message_id: _id,
                message,
            } => {
                /*log::info!(
                    "{} -> Got message with id: {id} from peer: {peer_id} for topic: {}",
                    self.user_name,
                    message.topic.to_string()
                );*/
                self.deliver_to_users(message.topic.to_string(), message.data);
            }
            _ => {}
        }
    }

    fn handle_kademlia_event(&mut self, swarm: &mut Swarm<MyBehaviour>, event: kad::Event) {
        match event {
            kad::Event::OutboundQueryProgressed { id, result, .. } => {
                if let Some((sender, remove_entry)) = self.pending_get_requests.remove(&id) {
                    match result {
                        QueryResult::PutRecord(a) => {
                            log::info!("Put Record: {:?}",a);
                        }

                        QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord { record, .. }))) => {
                            let Record { key, value, .. } = record;

                            if remove_entry {
                                /*println!(
                                    "Got record {:?}",
                                    std::str::from_utf8(key.as_ref()).unwrap(),
                                );*/
                                if value.is_empty() {
                                    //log::info!("{} -> Record not found: {:?}", self.user_name, key);
                                    match sender.send(Err(format!("Error 403 for {:?}", key))) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            log::error!("Error sending response: {:?}", e);
                                        }
                                    }
                                } else {
                                    //Remove previous GroupInfo
                                    let kad_key = kad::RecordKey::new(&key);
                                    let record = kad::Record {
                                        key: kad_key.clone(),
                                        value: Vec::new(),
                                        publisher: None,
                                        expires: None,
                                    };

                                    swarm.behaviour_mut().kademlia.as_mut().unwrap()
                                        .put_record(record, kad::Quorum::All)
                                        .expect("Failed to store record locally.");

                                    log::info!("{} -> Got record: {:?}", self.user_name, key);
                                    match sender.send(Ok(value)) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            log::error!("Error sending response: {:?}", e);
                                        }
                                    }
                                }
                            } else {
                                match sender.send(Ok(value)) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        log::error!("Error sending response: {:?}", e);
                                    }
                                }
                            }
                        }
                        QueryResult::GetRecord(Ok(a)) => {
                            log::info!("{:?}",a);
                            match sender.send(Err(format!("Record not found: {:?}", a))) {
                                Ok(_) => {}
                                Err(e) => {
                                    log::error!("Error sending response: {:?}", e);
                                }
                            }
                        }
                        QueryResult::GetRecord(Err(e)) => {
                            match sender.send(Err(format!("Error getting record: {:?}", e))) {
                                Ok(_) => {}
                                Err(e) => {
                                    log::error!("Error sending response: {:?}", e);
                                }
                            }
                        }
                        //_ => {}
                        a => {log::info!("MAYBE: {:?}",a);}
                    }
                }
            }

            kad::Event::InboundRequest { request } => {
                if let kad::InboundRequest::PutRecord { record: Some(record), .. } = request.clone() {
                    swarm.behaviour_mut().kademlia.as_mut().unwrap().store_mut().put(record.clone()).unwrap();
                    let Record { key, value: _value, .. } = record;
                    /*if from_utf8(key.as_ref()).unwrap().contains("group_info") {
                        //log::info!("{}: Received put record: {:?}", self.user_name, key);


                        //let group_name = from_utf8(key.as_ref()).unwrap().split("/").last().unwrap().to_string();
                        match self.write_timestamp(group_name, value, CGKAAction::RecvRecord) {
                            Ok(_) => {}
                            Err(e) => {log::error!("Error writing timestamp: {:?}", e);}
                        }
                    }*/
                }
                //log::info!("INBOUND: {:?}", request);
            }
            _other => {}
        }
    }

    fn deliver_to_users(&self, topic: String, message: Vec<u8>) {
        for (username, subscriptions) in &self.subscriptions {
            //log::info!("{} -> Receive message for topic {}. Subscribed to {:?}", username, topic, subscriptions);
            if subscriptions.contains(&topic) {
                let user = self.users.get(username).unwrap();

                let user_thread = Arc::clone(user);
                let topic_thread = topic.to_string().clone();
                let username_thread = username.clone();
                let mut message_thread = message.clone();

                thread::spawn(move || {
                    let mut user = user_thread.lock().unwrap();
                    parse_message(&mut message_thread, topic_thread, username_thread, &mut user).expect("Error processing message");
                    drop(user);
                });

            }
        }
    }
}