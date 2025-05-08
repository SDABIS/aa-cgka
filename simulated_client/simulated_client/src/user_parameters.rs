
use config::Config;
use url::Url;
use openmls::prelude::CredentialType;

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
pub enum DSType {
    Request,
    PubSubMQTT(String),
    GossipSub(GossipSubConfig),
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
pub enum Directory {
    Server,
    Kademlia
}

#[derive(Clone, Debug, PartialEq)]
pub enum Paradigm {
    Commit,
    Propose
}
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizationPolicy {
    Random,
    First,
    Last
}

impl From<String> for AuthorizationPolicy {
    fn from(policy: String) -> Self {
        match policy.as_str() {
            "first" => AuthorizationPolicy::First,
            "last" => AuthorizationPolicy::Last,
            _ => AuthorizationPolicy::Random,
        }
    }
}

impl From<String> for Paradigm {
    fn from(paradigm: String) -> Self {
        match paradigm.as_str() {
            "propose" => Paradigm::Propose,
            _ => Paradigm::Commit,
        }
    }
}

impl From<String> for Directory {
    fn from(dir: String) -> Self {
        match dir.as_str() {    
            "kademlia" => Directory::Kademlia,
            _ => Directory::Server,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Clone, Debug)]
pub struct GossipSubConfig {
    pub(crate) address: String,
    pub(crate) directory: Directory,
    pub(crate) rendezvous_address: String,
    pub(crate) rendezvous_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserParameters {
    pub(crate) delivery_service: DSType,
    pub(crate) server_url: Url,

    pub(crate) credential_type: CredentialType,
    pub(crate) external_join: bool,
    pub(crate) join_chance: f64,
    pub(crate) issue_update_chance: f64,
    pub(crate) message_chance: f64,
    pub(crate) message_length_min: usize,
    pub(crate) message_length_max: usize,
    pub(crate) scale: bool,

    pub(crate) sleep_millis_min: i64,
    pub(crate) sleep_millis_max: i64,
    pub(crate) groups: Vec<String>,
    pub(crate) auth_policy: AuthorizationPolicy,

    pub(crate) invite_chance: f64,
    pub(crate) remove_chance: f64,
    pub(crate) update_chance: f64,

    pub(crate) paradigm: Paradigm,
    pub(crate) proposals_per_commit: usize,

    pub(crate) mqtt_url: String,

}

impl GossipSubConfig {
    pub fn new_from_settings(settings: &Config) -> Result<Self, String> {
        let default = GossipSubConfig::default();


        let address = settings.get_string("gossipsub.address").unwrap_or(default.address);
        let directory = settings.get_string("gossipsub.directory")
            .map(|dir| Directory::from(dir)).unwrap_or(default.directory);

        let rendezvous_address = settings.get_string("gossipsub.rendezvous_address").unwrap_or(default.rendezvous_address);
        let rendezvous_id = settings.get_string("gossipsub.rendezvous_id").unwrap_or(default.rendezvous_id);

        Ok(Self {
            address,
            directory,
            rendezvous_address,
            rendezvous_id
        })
    }
}

impl UserParameters {
    pub fn new_from_settings(settings: &Config) -> Result<Self, String> {
        let default = UserParameters::default();

        let mqtt_url = settings.get_string("mqtt.url").unwrap_or(default.mqtt_url);
        let delivery_service = settings.get_string("cgka.ds").map(|ds| match ds.as_str() {
            "mqtt" => {
                DSType::PubSubMQTT(mqtt_url.clone())
            },
            "gossipsub" => {
                let gossipsub_config = GossipSubConfig::new_from_settings(settings).unwrap();
                DSType::GossipSub(gossipsub_config)
            },
            _ => DSType::Request,
        }).unwrap_or(default.delivery_service);

        let server_url = settings.get_string("http_server.url").map(|url| Url::parse(&url).unwrap())
            .unwrap_or(default.server_url);

        let external_join = settings.get_bool("cgka.external_join").unwrap_or(default.external_join);
        let credential_type = settings.get_string("cgka.credential_type")
            .map(|cred| CredentialType::from(cred))
            .unwrap_or(default.credential_type);

        let join_chance = settings.get_float("cgka.join_chance").unwrap_or(default.join_chance);
        let issue_update_chance = settings.get_float("cgka.issue_update_chance").unwrap_or(default.issue_update_chance);
        let message_chance = settings.get_float("cgka.message_chance").unwrap_or(default.message_chance);
        let message_length_min = settings.get_int("cgka.message_length_min").unwrap_or(default.message_length_min as i64) as usize;
        let message_length_max = settings.get_int("cgka.message_length_max").unwrap_or(default.message_length_max as i64) as usize;
        let sleep_millis_min = settings.get_int("cgka.sleep_millis_min").unwrap_or(default.sleep_millis_min);
        let sleep_millis_max = settings.get_int("cgka.sleep_millis_max").unwrap_or(default.sleep_millis_max);

        let groups = settings.get_array("cgka.groups")
            .map(|groups| groups.iter().map(|g| g.to_string()).collect())
            .unwrap_or(default.groups);

        let auth_policy = settings.get_string("cgka.auth_policy")
            .map(|policy| AuthorizationPolicy::from(policy))
            .unwrap_or(default.auth_policy);
        let scale = settings.get_bool("cgka.scale").unwrap_or(false);

        let paradigm = settings.get_string("paradigm.paradigm")
            .map(|paradigm| Paradigm::from(paradigm))
            .unwrap_or(default.paradigm);

        let proposals_per_commit = settings.get_int("paradigm.proposals_per_commit").unwrap_or(default.proposals_per_commit as i64) as usize;
        let invite_chance = settings.get_float("paradigm.invite_chance").unwrap_or(default.invite_chance);
        let remove_chance = settings.get_float("paradigm.remove_chance").unwrap_or(default.remove_chance);
        let update_chance = settings.get_float("paradigm.update_chance").unwrap_or(default.update_chance);

        if invite_chance + remove_chance + update_chance > 1.0 {
            return Err(String::from("The sum of \"invite_chance\", \"remove_chance\", \"update_chance\" cannot be greater than 1.0"));
        }

        Ok(Self {
            delivery_service,
            server_url,

            credential_type,
            external_join,
            join_chance,
            issue_update_chance,
            message_chance,
            message_length_min,
            message_length_max,
            sleep_millis_min,
            sleep_millis_max,
            groups,
            auth_policy,
            scale,

            invite_chance,
            remove_chance,
            update_chance,
            paradigm,
            proposals_per_commit,

            mqtt_url,
        })
    }
}

impl Default for GossipSubConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            rendezvous_address: "/dns/rendezvous/tcp/62649".to_string(),
            rendezvous_id: "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".to_string(),
            directory: Directory::Kademlia,
        }
    }
}

impl Default for UserParameters {
    fn default() -> Self {
        Self {
            delivery_service: DSType::Request,
            server_url: Url::parse("http://localhost:8080").unwrap(),
            external_join: false,

            credential_type: CredentialType::Basic,
            join_chance: 0.05,
            issue_update_chance: 0.05,
            message_chance: 0.4,
            message_length_min: 200,
            message_length_max: 2000,
            scale: false,
            sleep_millis_min: 10000,
            sleep_millis_max: 30000,
            groups: vec!["group_AAA".to_string()],
            auth_policy: AuthorizationPolicy::Random,
            invite_chance: 0.6,
            remove_chance: 0.1,
            update_chance: 0.3,
            paradigm: Paradigm::Commit,
            proposals_per_commit: 2,

            mqtt_url: "tcp://localhost:1883".to_string(),
        }
    }
}