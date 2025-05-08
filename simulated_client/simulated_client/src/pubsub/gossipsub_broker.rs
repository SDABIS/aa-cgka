use std::{thread};
//use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Duration;
use futures::executor::block_on;
//use libp2p::{gossipsub, mdns, noise, tcp, yamux};

use ds_lib::*;
use openmls::prelude::*;
use tokio::sync::mpsc::Sender;
use openmls::prelude::group_info::{VerifiableGroupInfo};
use crate::pubsub::Broker;
use crate::pubsub::gossipsub_updater::GossipSubQueueMessage;
use tls_codec::{Serialize, Deserialize};

#[derive(Debug)]
pub struct GossipSubBroker {
    username: String,
    tx: Sender<GossipSubQueueMessage>
}

impl Broker for GossipSubBroker {

    fn subscribe(&mut self, group_name: String) -> Result<(), String> {

        let topic = format!("cgka/group/{group_name}");
        let tx = self.tx.clone();
        let name = self.username.clone();

        thread::spawn(move || {
            tx.blocking_send(GossipSubQueueMessage::Subscribe(name, topic))
                .map_err(|e| format!("Error sending to queue: {:?}", e)).expect("Error subscribing");
        }).join().expect("Thread panicked");

        Ok(())
    }

    fn unsubscribe(&mut self, group_name: String) -> Result<(), String> {

        let topic = format!("cgka/group/{group_name}");
        let tx = self.tx.clone();
        let name = self.username.clone();

        thread::spawn(move || {
            tx.blocking_send(GossipSubQueueMessage::Unsubscribe(name, topic))
                .map_err(|e| format!("Error sending to queue: {:?}", e)).expect("Error unsubscribing");
        }).join().expect("Thread panicked");

        Ok(())
    }

    fn subscribe_welcome(&mut self, user_name: String) -> Result<(), String> {

        let username = user_name.split("#").next().unwrap().to_string();


        let topic = format!("cgka/welcome/{username}");
        let tx = self.tx.clone();
        let name = self.username.clone();

        thread::spawn(move || {
            tx.blocking_send(GossipSubQueueMessage::Subscribe(name, topic)).expect("Error subscribing to welcome");
        }).join().expect("Thread panicked");

        Ok(())
    }

    fn send_welcome(&self, welcome_msg: &GroupMessage, user_name: String) -> Result<(), String> {
        let serialized_msg = welcome_msg.tls_serialize_detached().unwrap();

        //log::info!("Sending Welcome to {}", username);
        let topic = format!("cgka/welcome/{user_name}");

        let tx = self.tx.clone();
        thread::spawn(move || {
            tx.blocking_send(GossipSubQueueMessage::Message(topic, serialized_msg))
                .map_err(|e| format!("Error sending to queue: {:?}", e)).expect("Error sending welcome");
        }).join().expect("Thread panicked");

        Ok(())
    }

    /// Send a group message.
    #[tokio::main]
    async fn send_msg(&self, group_msg: &GroupMessage, group_name: String) -> Result<(), String> {

        let serialized_msg = group_msg.tls_serialize_detached().unwrap();
        //log::info!("Sending {} bytes", serialized_msg.len());
        let topic = format!("cgka/group/{group_name}");

        self.tx.send(GossipSubQueueMessage::Message(topic, serialized_msg))
            .await
            .map_err(|e| format!("Error sending to queue: {:?}", e))?;

        Ok(())
    }
}

impl GossipSubBroker {
    pub fn add_contact(&self, contact_info: ContactInfo) -> Result<(), String> {
        let tx = self.tx.clone();
        thread::spawn(move || {
            tx.blocking_send(GossipSubQueueMessage::AddPeer(contact_info))
                .map_err(|e| format!("Error sending to queue: {:?}", e))
        }).join().expect("Thread panicked")
    }

    #[tokio::main]
    pub async fn get_contact_info(&self) -> Result<ContactInfo, String> {

        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<ContactInfo, String>>();


        self.tx.send(GossipSubQueueMessage::ContactInfo(sender))
            .await
            .map_err(|e| format!("Error sending to queue: {:?}", e))?;

        let response =
            async_std::future::timeout(Duration::from_secs(5), receiver)
                .await.map_err(|e| format!("Timeout on request: {:?}", e))?
                .map_err(|e| format!("Error receiving from channel: {:?}", e))??;


        Ok(response)

    }

    pub fn publish_group_info(&self, group_name: String, group_info: VerifiableGroupInfo) -> Result<(), String> {
        let serialized_msg = group_info.tls_serialize_detached()
            .map_err(|e| format!("Error serializing Group Info: {:?}", e))?;
        self.publish("group_info/".to_string() + &group_name, serialized_msg)?;

        Ok(())
    }

    pub fn publish_key_package(&self, user_name: String, key_package: KeyPackage) -> Result<(), String> {
        let serialized_msg = key_package.tls_serialize_detached()
            .map_err(|e| format!("Error serializing Key Package: {:?}", e))?;

        self.publish("key_package/".to_string() + &user_name, serialized_msg)?;

        Ok(())
    }

    #[tokio::main]
    pub async fn group_exists(&self, group_name: String) -> Result<Option<VerifiableGroupInfo>, String> {

        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<Vec<u8>, String>>();
        let key = "group_info/".to_string() + &group_name;
        let tx = self.tx.clone();

        let response = thread::spawn(move || {
            block_on(async {
                tx.send(GossipSubQueueMessage::Peek(key, sender)).await.expect("Error sending to queue");
                async_std::future::timeout(Duration::from_secs(5), receiver)
                    .await
                    .map_err(|e| format!("Timeout on request: {:?}", e))?
                    .map_err(|e| format!("Error receiving from channel: {:?}", e))?
            })
        }).join().expect("Thread panicked");

        match response {
            Ok(a) => {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut a.as_slice())
                    .map_err(|e| format!("Error deserializing group info: {:?}", e))?;
                Ok(Some(group_info))
            },
            Err(e) => {
                if e.contains("NotFound") {
                    Ok(None)
                } else {
                    log::error!("Error checking group existence: {}", e);
                    Err(e)
                }
            }
        }
    }

    pub fn group_info(&self, group_name: String) -> Result<VerifiableGroupInfo, String> {

        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<Vec<u8>, String>>();
        let key = "group_info/".to_string() + &group_name;
        let tx = self.tx.clone();

        let response = thread::spawn(move || {
            block_on(async {
                tx.send(GossipSubQueueMessage::Get(key, sender, true)).await.expect("Error sending to queue");
                let response =
                    async_std::future::timeout(Duration::from_secs(5), receiver)
                        .await.map_err(|e| format!("Timeout on request: {:?}", e))?
                        .map_err(|e| format!("Error receiving from channel: {:?}", e))?;

                response
            })
        }).join().expect("Thread panicked")?;

        let group_info = VerifiableGroupInfo::tls_deserialize(&mut response.as_slice()).map_err(|e| format!("Error deserializing group info: {:?}", e))?;

        Ok(group_info)
    }

    #[tokio::main]
    pub async fn consume_key_package(&self, group_name: String) -> Result<KeyPackageIn, String> {

        let (sender, receiver) = tokio::sync::oneshot::channel::<Result<Vec<u8>, String>>();

        let key = "key_package/".to_string() + &group_name;
        log::info!("Consuming key package for {}", key);
        self.tx.send(GossipSubQueueMessage::Get(key, sender, false))
            .await
            .map_err(|e| format!("Error sending to queue: {:?}", e))?;

        let response =
            async_std::future::timeout(Duration::from_secs(5), receiver)
                .await.map_err(|e| format!("Timeout on request: {:?}", e))?
                .map_err(|e| format!("Error receiving from channel: {:?}", e))??;
        log::info!("Key package obtained");
        let kp = KeyPackageIn::tls_deserialize(&mut response.as_slice()).map_err(|e| format!("Error deserializing group info: {:?}", e))?;

        Ok(kp)
    }

    fn publish(&self, key: String, serialized_msg: Vec<u8>) -> Result<(), String> {

        let tx = self.tx.clone();
        let name = self.username.clone();
        thread::spawn(move || {
            tx.blocking_send(GossipSubQueueMessage::Publish(name, key, serialized_msg))
                .map_err(|e| format!("Error sending to queue: {:?}", e))
        }).join().expect("Thread panicked")
    }
}

impl GossipSubBroker {
    pub fn new(username: String, tx: Sender<GossipSubQueueMessage>) -> Self {
        Self {
            username,
            tx
        }
    }
}
