use std::str::from_utf8;
use tls_codec::{Deserialize};
use ds_lib::GroupMessage;
use crate::client_agent::{ClientAgent};
use crate::user::{User};

pub mod mqtt_updater;
pub mod gossipsub_updater;
pub mod mqtt_broker;
pub mod gossipsub_broker;

pub fn parse_message(message: &mut Vec<u8>, topic: String, user_name: String, user: &mut User) -> Result<(), String> {
    let message = GroupMessage::tls_deserialize(&mut message.as_slice()).unwrap();
    let sender = from_utf8(message.sender()).unwrap().to_string();

    let recipients = message.recipients.clone().iter()
        .map(|r| from_utf8(r.as_slice()).unwrap().to_string()
            .split("#").next().unwrap().to_string()
        ).collect::<Vec<String>>();

    if !recipients.contains(&user_name) && topic.starts_with("cgka/welcome") {
        //log::info!("{} -> RECIPIENTS {:?}", user_name, recipients);
        return Ok(());
    }
    /*let user = {
        if topic.starts_with("cgka/welcome/") {
            active_users.get_mut("").unwrap()
        }
        else {
            // Obtain the group name from the topic (cgka/group/{group_name})
            // Obtain the group
            let user = match active_users.get_mut(&group_name) {
                Some(u) => u,
                None => {
                    //log::info!{"{} -> Received message from topic {}", self.user_name, topic};
                    active_users.get_mut("").unwrap()
                }
            };

            //log::info!("{} ==? {}", sender, user_name);
            user
        }
    };*/

    match user.process_in_message(message.msg, sender.clone()) {
        Ok(action_record) => {
            if let Some(record) = action_record {
                ClientAgent::write_timestamp(user_name.clone(), record);
            }
            Ok(())
        }
        Err(e) => {
            log::error!("Error processing message from: {}: {}",sender, e);
            Err(e)
        },
    }
}

pub trait Broker {
    fn subscribe(&mut self, group_name: String) -> Result<(), String>;
    fn unsubscribe(&mut self, group_name: String) -> Result<(), String>;
    fn subscribe_welcome(&mut self, user_name: String) -> Result<(), String>;
    fn send_welcome(&self, welcome_msg: &GroupMessage, user_name: String) -> Result<(), String>;
    fn send_msg(&self, group_msg: &GroupMessage, group_name: String) -> Result<(), String>;
}
