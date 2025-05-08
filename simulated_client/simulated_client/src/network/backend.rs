use std::str::from_utf8;
use std::thread;
use tls_codec::{Deserialize, TlsVecU32};
use url::Url;

use super::{
    networking::{get, post},
    super::user::User,
};

use ds_lib::*;
use openmls::prelude::*;
use openmls::prelude::group_info::VerifiableGroupInfo;
use crate::identity::Identity;

#[derive(Clone, Debug)]
pub struct Backend {
    ds_url: Url,
}

impl Backend {
    pub fn new(url: Url) -> Self {
        Self {
            // There's a public DS at https://mls.franziskuskiefer.de
            ds_url: url
        }
    }
    /// Register a new client with the server.
    pub fn register_identity(&self, identity: &Identity, group_name: String, contact_info: Option<ContactInfo>) -> Result<String, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/register");

        let name = from_utf8(identity.identity()).unwrap().to_string();
        let client_info = ClientInfo::new(
            name,
            group_name.clone(),
            identity.kp.clone(),
                /*.into_iter()
                .map(|(b, kp)| (b, KeyPackageForGroup {
                    key_package: KeyPackageIn::from(kp),
                    group: group_name.clone().into_bytes(),
                }))
                .collect(),*/
            contact_info
        );
        let response = post(&url, &client_info)?;

        Ok(String::from_utf8(response).unwrap())
    }

    /// Get a list of all clients with name, ID, and key packages from the
    /// server.
    pub fn list_clients(&self) -> Result<Vec<ClientInfo>, String> {
        let mut url = self.ds_url.clone();
        url.set_path("/clients/list");

        let response = get(&url)?;
        match TlsVecU32::<ClientInfo>::tls_deserialize(&mut response.as_slice()) {
            Ok(clients) => Ok(clients.into()),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Get and reserve a key package for a client.
    pub fn consume_key_package(&self, client_id: &[u8]) -> Result<KeyPackageIn, String> {
        let mut url = self.ds_url.clone();
        let path = "/clients/key_package/".to_string()
            + &base64::encode_config(client_id, base64::URL_SAFE);
        url.set_path(&path);

        let response = get(&url)?;
        match KeyPackageIn::tls_deserialize(&mut response.as_slice()) {
            Ok(kp) => Ok(kp),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    /// Publish client additional key packages
    pub fn publish_key_packages(&self, identity: &Identity, ckp: &ClientKeyPackages) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        let path = "/clients/key_packages/".to_string()
            + &base64::encode_config(identity.identity(), base64::URL_SAFE);
        url.set_path(&path);

        // The response should be empty.
        let ckp = ckp.clone();
        thread::spawn(move || {
            let _response = post(&url,&ckp).expect("Error in POST");
        }).join().expect("Thread panicked");
        Ok(())
    }

    pub(crate) fn group_exists(&self, group_name: String) -> Result<Option<VerifiableGroupInfo>, String> {
        let mut url = self.ds_url.clone();
        let path = "/groups/peek/".to_string()
            + &base64::encode_config(group_name, base64::URL_SAFE);
        url.set_path(&path);
        //url.set_query(Some(&format!("username={}", username)));

        match get(&url) {
            Ok(response) => {
                match VerifiableGroupInfo::tls_deserialize(&mut response.as_slice()) {
                    Ok(gi) => Ok(Some(gi)),
                    Err(e) => Err(format!("Error decoding server response: {e:?}")),
                }
            },
            Err(e) => {
                if e.contains("204") {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub fn group_info(&self, username: String, group_name: String) -> Result<VerifiableGroupInfo, String> {
        let mut url = self.ds_url.clone();
        let path = "/groups/group_info/".to_string()
            + &base64::encode_config(group_name, base64::URL_SAFE);
        url.set_path(&path);
        url.set_query(Some(&format!("username={}", username)));

        let response = get(&url)?;
        match VerifiableGroupInfo::tls_deserialize(&mut response.as_slice()) {
            Ok(gi) => Ok(gi),
            Err(e) => Err(format!("Error decoding server response: {e:?}")),
        }
    }

    pub fn publish_group_info(&self, username: String, group_name: String, group_info: VerifiableGroupInfo) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        let path = "/groups/group_info/".to_string()
            + &base64::encode_config(group_name, base64::URL_SAFE);
        url.set_path(&path);
        url.set_query(Some(&format!("username={}", username)));
        //log::info!("{url}");
        thread::spawn(move || {
            let _response = post(&url,&group_info).expect("Error in POST");
        }).join().expect("Thread panicked");
        Ok(())
    }

    /// Send a welcome message.
    pub fn send_welcome(&self, welcome_msg: &GroupMessage) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/welcome");

        // The response should be empty.
        let _response = post(&url, welcome_msg)?;
        Ok(())
    }

    /// Send a group message.
    pub fn send_msg(&self, group_msg: &GroupMessage) -> Result<(), String> {
        let mut url = self.ds_url.clone();
        url.set_path("/send/message");

        // The response should be empty.
        let _response = post(&url, group_msg)?;
        Ok(())
    }

    /// Get a list of all new messages for the user.
    pub fn recv_msgs(&self, user: &User) -> Result<Vec<GroupMessage>, String> {
        let mut url = self.ds_url.clone();
        let path = "/recv/".to_string()
            + &base64::encode_config(user.base_identity.borrow().identity(), base64::URL_SAFE);
        url.set_path(&path);

        let response = get(&url)?;
        match TlsVecU32::<GroupMessage>::tls_deserialize(&mut response.as_slice()) {
            Ok(r) => Ok(r.into()),
            Err(e) => Err(format!("Invalid message list: {e:?}")),
        }
    }

    /// Reset the DS.
    pub fn reset_server(&self) {
        let mut url = self.ds_url.clone();
        url.set_path("reset");
        get(&url).unwrap();
    }
}

impl Default for Backend {
    fn default() -> Self {
        Self {
            // There's a public DS at https://mls.franziskuskiefer.de
            ds_url: Url::parse("http://localhost:8080").unwrap(),
        }
    }
}
