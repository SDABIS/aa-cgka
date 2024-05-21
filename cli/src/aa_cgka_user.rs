use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use rand::Rng;
use openmls::helpers::{generate_basic_credential_with_key, generate_bbs_vc_credential_with_key};
use openmls::prelude::{generate_sd_jwt_credential_with_key, generate_vc_credential_with_key};
use openmls_traits::types::Ciphersuite;
use openmls_vc_credential::{DIDWeb, JWK};
use crate::{GROUP_NAME, JOIN_CHANCE, UPDATE_CHANCE};
use crate::user::{CIPHERSUITE, User};

pub enum UserType {
    Basic,
    VC(openmls_vc_credential::Credential, JWK),
    SDJWT(String, Vec<u8>, String),
    BBSVC(openmls_vc_credential::Credential)
}

pub struct AACGKAUser {
    user_type: UserType,
    base_user: User,
}

impl AACGKAUser {
    pub fn new(
        user_type: UserType,
        name: String
    ) -> AACGKAUser {
        let user = User::new(name);

        AACGKAUser {
            user_type,
            base_user: user
        }
    }

    pub fn run(&self, current_members: Arc<Mutex<Vec<String>>>, group_creator: Arc<Mutex<User>>) {
        log::info!("Starting user {}", self.base_user.username);
        let mut user_opt: Option<User> = None;
        let mut rng = rand::thread_rng();
        let mut left_group = false;

        loop {
            /*let millis = rng.gen_range(1000..10000);
            thread::sleep(Duration::from_millis(millis));*/

            thread::sleep(Duration::from_secs(1));

            let mut current_members = current_members.lock().unwrap();


            if let Some(user) = &mut user_opt {
                //log::info!("Requesting updates for {}", self.base_user.username);
                user.update(Some(GROUP_NAME.to_string())).expect("Error updating group");

                /*if rng.gen::<f32>() < UPDATE_CHANCE {
                    let new_req = serde_json::from_str(include_str!("../resources/different_requirement.json")).expect("Error loading new requirement");

                    let mut current_members = current_members.lock().unwrap();
                    user.update(Some(GROUP_NAME.to_string())).expect("Error updating group");
                    user.modify_req(0, &new_req, GROUP_NAME.to_string()).unwrap();
                    drop(current_members);

                    log::info!("{} UPDATED REQUIREMENTS", self.base_user.username);
                }*/

                /*if rng.gen::<f32>() < JOIN_CHANCE {
                    user_opt = None;
                    //user.remove(self.base_user.username.clone(), GROUP_NAME.to_string()).unwrap();
                    log::info!("{} left group", self.base_user.username);
                    left_group = true;
                }*/

            } else {
                let mut chance = JOIN_CHANCE;
                if left_group { chance = chance * 10.0}
                if rng.gen::<f32>() < chance {
                    log::info!("{} IS JOINING GROUP", self.base_user.username);
                    let group_info = self.base_user.get_group_info(GROUP_NAME.to_string()).expect("Error obtaining group info");
                    log::info!("\tGroup Info downloaded");
                    let (credential_with_key, signer) = match &self.user_type {
                        UserType::Basic => {
                            log::info!("\tGenerating Presentation (Basic)");
                            generate_basic_credential_with_key(
                                self.base_user.username.clone().into_bytes(),
                                CIPHERSUITE.signature_algorithm(),
                                self.base_user.crypto(),
                            )
                        }
                        UserType::VC(vc, holder_sk) => {
                            log::info!("\tGenerating Presentation (VC)");

                            generate_vc_credential_with_key(
                                self.base_user.username.clone(),
                                &vc,
                                holder_sk,
                                CIPHERSUITE.signature_algorithm(),
                                self.base_user.crypto(),
                                &DIDWeb
                            )
                        }
                        UserType::SDJWT(sdjwt, holder_sk, issuer_pk) => {
                            log::info!("\tGenerating Presentation (SD-JWT)");
                            let requirement = group_info.group_info.group_context_extensions().ssi_vc_requirements().unwrap().first().unwrap();

                            generate_sd_jwt_credential_with_key(
                                self.base_user.username.clone(),
                                sdjwt.clone(),
                                requirement,
                                CIPHERSUITE.signature_algorithm(),
                                holder_sk.as_slice(),
                                issuer_pk.as_bytes(),
                                self.base_user.crypto(),
                            )
                        }
                        UserType::BBSVC(vc) => {
                            log::info!("\tGenerating Presentation (BBS_VC)");
                            let requirement = group_info.group_info.group_context_extensions().ssi_vc_requirements().unwrap().first().unwrap();

                            generate_bbs_vc_credential_with_key(
                                self.base_user.username.clone(),
                                &vc,
                                requirement,
                                CIPHERSUITE.signature_algorithm(),
                                self.base_user.crypto(),
                                &DIDWeb
                            )
                        }
                    };

                    log::debug!("\t{}'s Presentation: {:?}", self.base_user.username, credential_with_key.credential);

                    let mut new_user = User::new_from_credential(
                        self.base_user.username.clone(),
                        signer.clone().into(),
                        credential_with_key
                    );
                    /*new_user.external_join(GROUP_NAME.to_string(), group_info).expect("Error performing external join");
                    current_members.push(self.base_user.username.clone());
                    user_opt = Some(new_user);*/

                    let mut creator = group_creator.lock().unwrap();

                    new_user.register();
                    new_user.create_kp();
                    creator.update(Some(GROUP_NAME.to_string())).unwrap();
                    creator.invite(new_user.username.clone(), GROUP_NAME.to_string()).unwrap();
                    new_user.update(Some(GROUP_NAME.to_string())).unwrap();
                    drop(creator);
                    user_opt = Some(new_user)
                }
            }
            drop(current_members);
        }
    }
}