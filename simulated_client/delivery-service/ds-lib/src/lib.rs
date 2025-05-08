//! # OpenMLS Delivery Service Library
//!
//! This library provides structs and necessary implementations to interact with
//! the OpenMLS DS.
//!
//! Clients are represented by the `ClientInfo` struct.

use std::collections::{HashMap, HashSet};

use openmls::prelude::{key_package_in::*, tls_codec, MlsMessageIn};
use openmls::prelude::tls_codec::{
    TlsByteSliceU16, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8, TlsDeserialize, TlsSerialize,
    TlsSize, TlsVecU32,
};


/// Information about a client.
/// To register a new client create a new `ClientInfo` and send it to
/// `/clients/register`.
#[derive(Debug, Default, Clone)]
pub struct ClientInfo {
    pub client_name: String,
    pub group_name: String,
    pub key_packages: ClientKeyPackages,
    pub contact_info: Option<ContactInfo>,
    /// map of reserved key_packages [group_id, key_package_hash]
    pub reserved_key_pkg_hash: HashSet<Vec<u8>>,
    pub id: Vec<u8>,
    pub msgs: Vec<GroupMessage>,
    pub welcome_queue: Vec<GroupMessage>,
}

/// The DS returns a list of key packages for a client as `ClientKeyPackages`.
/// This is a tuple struct holding a vector of `(Vec<u8>, KeyPackage)` tuples,
/// where the first value is the key package hash (output of `KeyPackage::hash`)
/// and the second value is the corresponding key package.
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ClientKeyPackages(pub TlsVecU32<(TlsByteVecU8, KeyPackageForGroup)>);


#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ContactInfo {
    pub peer_id: String,
    pub multiaddr: String,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct KeyPackageForGroup {
    pub key_package: KeyPackageIn,
    pub group: Vec<u8>,
}

impl ClientInfo {
    /// Create a new `ClientInfo` struct for a given client name and vector of
    /// key packages with corresponding hashes.
    pub fn new(client_name: String, group_name: String, mut key_packages: HashMap<Vec<u8>, KeyPackageForGroup>, contact_info: Option<ContactInfo>) -> Self {
        Self {
            client_name: client_name.clone(),
            group_name,
            key_packages: ClientKeyPackages(
                key_packages
                    .drain()
                    .map(|(e1, e2)| (e1.into(), e2))
                    .collect::<Vec<(TlsByteVecU8, KeyPackageForGroup)>>()
                    .into(),
            ),
            contact_info,
            reserved_key_pkg_hash: HashSet::new(),
            id: client_name.into_bytes(),
            msgs: Vec::new(),
            welcome_queue: Vec::new(),
        }
    }

    /// Acquire a key package from the client's key packages
    /// Mark the key package hash ref as "reserved key package"
    /// The reserved hash ref will be used in DS::send_welcome and removed once welcome is distributed
    pub fn consume_kp(&mut self) -> Result<KeyPackageIn, String> {
        if self.key_packages.0.len() == 0 {
            // We keep one keypackage to handle ClientInfo serialization/deserialization issues
            return Err("No more keypackage available".to_string());
        }
        match self.key_packages.0.get(self.key_packages.0.len() - 1) {
            Some(c) => {
                self.reserved_key_pkg_hash.insert(c.clone().0.into_vec());
                Ok(c.1.key_package.clone())
            }
            None => {
                Err("No more keypackage available".to_string())
            },
        }
    }
}

/// An core group message.
/// This is an `MLSMessage` plus the list of recipients as a vector of client
/// names.
#[derive(Debug, Clone)]
pub struct GroupMessage {
    pub msg: MlsMessageIn,
    pub sender: TlsByteVecU32,
    pub recipients: TlsVecU32<TlsByteVecU32>,
}

impl GroupMessage {
    /// Create a new `GroupMessage` taking an `MlsMessageIn` and slice of
    /// recipient names.
    pub fn new(msg: MlsMessageIn, sender: Vec<u8>, recipients: &[Vec<u8>]) -> Self {
        Self {
            msg,
            sender: sender.into(),
            recipients: recipients
                .iter()
                .map(|r| r.clone().into())
                .collect::<Vec<TlsByteVecU32>>()
                .into(),
        }
    }

    pub fn sender(&self) -> &[u8] {
        self.sender.as_slice()
    }
}

impl tls_codec::Size for ClientInfo {
    fn tls_serialized_len(&self) -> usize {
        TlsByteSliceU16(self.client_name.as_bytes()).tls_serialized_len()
            + TlsByteSliceU16(self.group_name.as_bytes()).tls_serialized_len()
            + self.key_packages.tls_serialized_len()
            + self.contact_info.tls_serialized_len()
    }
}

impl tls_codec::Serialize for ClientInfo {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = TlsByteSliceU16(self.client_name.as_bytes()).tls_serialize(writer)?;
        let written = TlsByteSliceU16(self.group_name.as_bytes()).tls_serialize(writer).map(|l| l + written)?;
        let written = self.key_packages.tls_serialize(writer).map(|l| l + written)?;
        self.contact_info.tls_serialize(writer).map(|l| l + written)
    }
}

impl tls_codec::Deserialize for ClientInfo {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let client_name =
            String::from_utf8_lossy(TlsByteVecU16::tls_deserialize(bytes)?.as_slice()).into();
        let group_name =
            String::from_utf8_lossy(TlsByteVecU16::tls_deserialize(bytes)?.as_slice()).into();
        let mut key_packages: Vec<(TlsByteVecU8, KeyPackageForGroup)> =
            TlsVecU32::<(TlsByteVecU8, KeyPackageForGroup)>::tls_deserialize(bytes)?.into();
        let key_packages = key_packages
            .drain(..)
            .map(|(e1, e2)| (e1.into(), e2))
            .collect();
        let contact_info = Option::<ContactInfo>::tls_deserialize(bytes)?;

        Ok(Self::new(client_name, group_name, key_packages, contact_info))
    }
}

impl tls_codec::Size for GroupMessage {
    fn tls_serialized_len(&self) -> usize {
        self.msg.tls_serialized_len() + self.sender.tls_serialized_len() + self.recipients.tls_serialized_len()
    }
}

impl tls_codec::Serialize for GroupMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.msg.tls_serialize(writer)?;
        written += self.sender.tls_serialize(writer)?;
        written += self.recipients.tls_serialize(writer)?;

        Ok(written)
    }
}
impl tls_codec::Deserialize for GroupMessage {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let msg = MlsMessageIn::tls_deserialize(bytes)?;
        let sender = TlsByteVecU32::tls_deserialize(bytes)?;
        let recipients = TlsVecU32::<TlsByteVecU32>::tls_deserialize(bytes)?;
        Ok(Self { msg, sender, recipients })
    }
}

impl tls_codec::Size for ContactInfo {
    fn tls_serialized_len(&self) -> usize {
        TlsByteVecU8::from_slice(self.peer_id.as_bytes()).tls_serialized_len()
         + TlsByteVecU8::from_slice(self.multiaddr.as_bytes()).tls_serialized_len()
    }
}


impl tls_codec::Serialize for ContactInfo {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = TlsByteVecU8::from_slice(self.peer_id.as_bytes()).tls_serialize(writer)?;
        written += TlsByteVecU8::from_slice(self.multiaddr.as_bytes()).tls_serialize(writer)?;

        Ok(written)
    }
}

impl tls_codec::Deserialize for ContactInfo {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let peer_id = String::from_utf8(TlsByteVecU8::tls_deserialize(bytes)?.into_vec()).unwrap();
        let multiaddr = String::from_utf8(TlsByteVecU8::tls_deserialize(bytes)?.into_vec()).unwrap();
        Ok(Self { peer_id, multiaddr })
    }
}