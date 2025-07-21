use aws_lc_rs::signature::Signature as awsSig;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct TahiniCertificate {
    pub service_name: ServiceName,
    pub policy_hash: PolicyHash,
    pub binary_hash: BinHash,
    pub signature: Signature,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[allow(unused)]
pub struct BinHash(pub String);

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[allow(unused)]
pub struct Signature(pub String);

impl From<awsSig> for Signature {
    fn from(value: awsSig) -> Self {
        Signature(hex::encode(value.as_ref()))
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[allow(unused)]
pub struct PolicyHash(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DynamicAttestationReport {
    pub certificate: TahiniCertificate,
    pub nonce: u128,
    pub service_name: ServiceName,
    pub current_bin_hash: BinHash,
    pub server_key_share: Vec<u8>,
    pub client_id: ClientId,
    pub signature: Signature,
}

#[derive(Serialize, Debug)]
pub struct DynamicAttestationData<'a> {
    pub cert: &'a TahiniCertificate,
    pub nonce: u128,
    pub service_name: ServiceName,
    pub current_bin_hash: BinHash,
    pub server_key_share: Vec<u8>,
    pub client_id: ClientId,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
pub struct ServiceName(pub String);

impl ServiceName {
    pub fn to_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for ServiceName {
    fn from(value: String) -> Self {
        ServiceName(value)
    }
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct BinaryName(pub(crate) String);


#[cfg(feature="attest")]
#[derive(Debug)]
pub enum AttestErrors {
    IoError(std::io::Error),
    ServiceMismatchError,
    NetworkError(tarpc::client::RpcError),
    AttestDataMalformedError(serde_json::Error),
    ConfigError(String),
    CryptoError,
    InvalidAttestation,
}

pub type AttestResult<T> = Result<T, AttestErrors>;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ClientId(pub(crate) usize);

impl Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<usize> for ClientId {
    fn from(value: usize) -> Self {
        ClientId(value)
    }
}

impl From<ClientId> for usize {
    fn from(value: ClientId) -> Self {
        value.0
    }
}
