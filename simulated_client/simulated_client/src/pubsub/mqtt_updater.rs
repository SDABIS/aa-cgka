use std::sync::{Arc, Mutex};
use rumqttc::{Event, EventLoop};
use crate::pubsub::parse_message;
use crate::user::User;

pub struct MqttUpdater {
    user_name: String,
    user: Arc<Mutex<User>>,
    event_loop: EventLoop,
}

impl MqttUpdater {
    pub fn new(user_name: String, user: Arc<Mutex<User>>, event_loop: EventLoop) -> Self {
        Self {
            user_name,
            user,
            event_loop,
        }
    }

    #[tokio::main]
    pub async fn run(&mut self) {
        loop {
            let event = self.event_loop.poll().await;
            if let Ok(notification) = event
            {
                //self.process_protocol_message()
                match notification {
                    Event::Incoming(packet) => {
                        match packet {
                            rumqttc::Packet::Publish(publish) => {
                                //log::info!("Received = {:?}", publish);
                                let mut user = self.user.lock().unwrap();
                                match parse_message(&mut publish.payload.to_vec(), publish.topic.clone(), self.user_name.clone(), &mut user) {
                                    Ok(_) => {}
                                    //Err(e) => {log::error!("Error parsing message: {}, trusting everything goes OK...", e);}
                                    Err(e) => panic!("Error parsing message: {}", e)
                                }

                                drop(user);
                            }
                            _ => {}
                        }
                    }
                    Event::Outgoing(_) => {}
                }
            }
            else {
                let error = event.unwrap_err();
                log::error!("Connection error: {:?}", error);
                panic!("Connection error: {:?}", error);
            }
        }
    }

}