use std::collections::HashMap;
use ds_lib::KeyPackageForGroup;
use openmls::prelude::{*};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use crate::client_agent::UserCredential;
use super::{openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto, serialize_any_hashmap};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    #[serde(
        serialize_with = "serialize_any_hashmap::serialize_hashmap",
        deserialize_with = "serialize_any_hashmap::deserialize_hashmap"
    )]
    pub(crate) kp: HashMap<Vec<u8>, KeyPackageForGroup>,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) user_credential: UserCredential,
    pub(crate) signer: SignatureKeyPair,
}

impl Identity {
    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        user_credential: UserCredential,
        crypto: &OpenMlsRustPersistentCrypto,
        id: &[u8],
    ) -> Self {
            let credential = Credential::new(CredentialType::Basic, id.to_vec());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        let credential_with_key = CredentialWithKey {
            credential,
            signature_key: signature_keys.to_public_vec().into(),
        };
        signature_keys.store(crypto.storage()).unwrap();

        Self {
            kp: HashMap::new(),
            user_credential,
            credential_with_key,
            signer: signature_keys,
        }
    }

    pub(crate) fn new_from_credential(
        crypto: &OpenMlsRustPersistentCrypto,
        user_credential: UserCredential,
        credential_with_key: CredentialWithKey,
        signature_keys: SignatureKeyPair,
    ) -> Self {
        signature_keys.store(crypto.storage()).unwrap();

        Self {
            kp: HashMap::new(),
            user_credential,
            credential_with_key,
            signer: signature_keys,
        }
    }

    /// Create an additional key package using the credential_with_key/signer bound to this identity
    pub fn  add_key_package(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
        group_name: String
    ) -> KeyPackage {
        let key_package = KeyPackage::builder()
            .leaf_node_capabilities(
                Capabilities::default()
            )
            .key_package_extensions(
                Extensions::single(Extension::LastResort(LastResortExtension::default()))
            )
            .build(
                ciphersuite,
                crypto,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .unwrap().key_package().clone();

        self.kp.insert(
            key_package
                .hash_ref(crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            KeyPackageForGroup {
                group: group_name.into_bytes(),
                key_package: KeyPackageIn::from(key_package.clone())
            }
        );
        key_package
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential_with_key.credential.identity()
    }
}
