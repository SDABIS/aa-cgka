use std::{thread};
use futures::executor::block_on;
//use libp2p::{gossipsub, mdns, noise, tcp, yamux};
use rumqttc::{AsyncClient, QoS};

use ds_lib::*;
use openmls::prelude::*;
use tokio::sync::mpsc::Sender;
use crate::pubsub::Broker;
use crate::pubsub::gossipsub_updater::GossipSubQueueMessage;
use tls_codec::Serialize;
#[derive(Debug)]
pub enum BrokerType {
    Mqtt(AsyncClient),
    P2P(Sender<GossipSubQueueMessage>),
}

#[derive(Debug)]
pub struct MqttBroker {
    async_client: AsyncClient
}

impl Broker for MqttBroker {
    fn subscribe(&mut self, group_name: String) -> Result<(), String> {

       let topic = format!("cgka/group/{group_name}");
       block_on(async {
           self.async_client.subscribe(topic.clone(), QoS::ExactlyOnce)
               .await
       }).map_err(|e| format!("Error subscribing: {:?}", e))?;

       Ok(())
   }

    fn unsubscribe(&mut self, group_name: String) -> Result<(), String> {
        let topic = format!("cgka/group/{group_name}");

        block_on(async {
            self.async_client.unsubscribe(topic.clone())
                .await
        }).map_err(|_| "Error unsubscribing")?;

        Ok(())
    }

    fn subscribe_welcome(&mut self, user_name: String) -> Result<(), String> {

        let topic = format!("cgka/welcome/{user_name}");

        block_on(async {
            self.async_client.subscribe(topic.clone(), QoS::ExactlyOnce)
                .await
        }).map_err(|e| format!("Error subscribing: {:?}", e))?;

        Ok(())
    }

    fn send_welcome(&self, welcome_msg: &GroupMessage, user_name: String) -> Result<(), String> {
        let serialized_msg = welcome_msg.tls_serialize_detached().unwrap();

        // Remove the "#" from the client id
        let username = user_name.split("#").next().unwrap().to_string();

        log::info!("Sending Welcome to {}", user_name);
        let topic = format!("cgka/welcome/{username}");

        let client = self.async_client.clone();
        thread::spawn(move || {
            block_on(async {
                client.publish(topic, QoS::ExactlyOnce, false,  serialized_msg)
                    .await
            }).map_err(|e| format!{"Error publishing Welcome: {:?}", e}).expect("Error sending welcome");
        }).join().expect("Thread panicked");

        Ok(())
    }

    /// Send a group message.
    #[tokio::main]
    async fn send_msg(&self, group_msg: &GroupMessage, group_name: String) -> Result<(), String> {

        let serialized_msg = group_msg.tls_serialize_detached().unwrap();
        //log::info!("Sending {} bytes", serialized_msg.len());
        let topic = format!("cgka/group/{group_name}");

        self.async_client.publish(topic, QoS::ExactlyOnce, false,  serialized_msg)
            .await.map_err(|e| format!{"Error publishing message: {:?}", e})?;


        Ok(())
    }
}

impl MqttBroker {
    pub fn new_from_client(async_client: AsyncClient) -> Self{
        Self {
            async_client
        }
    }
}