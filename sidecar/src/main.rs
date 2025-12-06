use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::Ed25519KeyPair;
use fizz_rs::VerificationInfo;
use futures::StreamExt;
use hoodini_core::certificate::{CertificateLoader, CertificateProvider};
use hoodini_core::service::{compute_local_share, derive_key_from_shares, AttestationService};
use hoodini_core::types::{
    BinHash, ClientId, DynamicAttestationData, DynamicAttestationReport, ServiceName,
};
use hoodini_sidecar::{hash_bin, CredentialManager};
use std::collections::HashMap;
use std::future::Future;
use std::io::Read;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use tarpc::serde_transport::new as new_transport;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Json;
use tokio::net::TcpListener;
use tokio_util::codec::LengthDelimitedCodec;

use tokio::sync::{Mutex, RwLock};

mod config;

static SERVER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Clone)]
pub struct SideCarServer {
    //For a given binary_name, gives its hash
    service_bin_map: Arc<RwLock<HashMap<ServiceName, BinHash>>>,
    //Stuff that loads certificates from disk for attestation
    certificate_server: Arc<RwLock<CertificateLoader>>,
    //Runtime attestation signing key
    signing_key: Arc<RwLock<Ed25519KeyPair>>,
    //For a given binary_name, give the functional service living inside
    service_mapping: Arc<RwLock<HashMap<ServiceName, ServiceName>>>,
    //For a given service, yields the public credential verif info
    service_verif_info: Arc<RwLock<HashMap<ServiceName, VerificationInfo>>>,
}

//Load runtime attestation signing key from disk
fn load_signing_attestation_key(path: &Path) -> Ed25519KeyPair {
    let mut file = std::fs::File::open(path).expect("Couldn't find signing key file");
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)
        .expect("Couldn't read key file");
    Ed25519KeyPair::from_pkcs8(&contents).expect("Couldn't parse key bytes")
}

impl SideCarServer {
    pub fn new(
        certificate_config_path: &Path,
        key_path: &Path,
        mapping: HashMap<ServiceName, ServiceName>,
    ) -> Self {
        Self {
            service_bin_map: Arc::new(RwLock::new(HashMap::new())),
            certificate_server: Arc::new(RwLock::new(
                CertificateLoader::from_config(certificate_config_path)
                    .expect("Couldn't generate certificate handler for the sidecar"),
            )),
            signing_key: Arc::new(RwLock::new(load_signing_attestation_key(key_path))),
            service_mapping: Arc::new(RwLock::new(mapping)),
            service_verif_info: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    //Registers mapping bin_name -> bin_hash
    pub async fn register_running_service(&mut self, service_name: ServiceName, hash: BinHash) {
        let mut map = self.service_bin_map.write().await;
        map.insert(service_name, hash);
    }

    pub async fn register_verif_info(
        &mut self,
        service_name: ServiceName,
        verif_info: VerificationInfo,
    ) {
        let mut map = self.service_verif_info.write().await;
        map.insert(service_name, verif_info);
    }

    //Debugging purposes
    pub async fn show_running_binaries(&self) {
        println!("{:#?}", self.service_bin_map.read().await);
    }
}

impl AttestationService for SideCarServer {
    async fn attest_binary(
        self,
        _context: tarpc::context::Context,
        service_name: ServiceName,
        nonce: u128,
    ) -> DynamicAttestationReport {
        let bin_map = self.service_bin_map.read().await;

        let bin = bin_map
            .get(&service_name)
            .expect("Binary doesn't exist in sidecar map");

        let certificate_handler = self.certificate_server.read().await;

        println!(
            "We are requested certificate for service {:?}",
            service_name
        );
        let certificate = certificate_handler.get_certificate(&service_name).unwrap();

        let verif_info_handler = self.service_verif_info.read().await;
        let verif_info = verif_info_handler.get(&service_name).unwrap();

        let signing_data = DynamicAttestationData {
            cert: certificate,
            nonce,
            service_name: service_name.clone(),
            current_bin_hash: bin.clone(),
            delegated_credential_info: verif_info.clone(),
        };

        let sign_data_u8 =
            serde_json::to_vec(&signing_data).expect("Couldn't transform signing data to bytes");
        let signer = self.signing_key.read().await;
        let sig = signer.sign(&sign_data_u8).into();

        DynamicAttestationReport {
            certificate: certificate.clone(),
            current_bin_hash: bin.clone(),
            nonce,
            service_name,
            delegated_credential_info: verif_info.clone(),
            signature: sig,
        }
    }
}

async fn wait_upon(fut: impl Future<Output = ()>) {
    fut.await
}

#[tokio::main]
#[allow(unreachable_code)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("In sidecar main");
    let listener = TcpListener::bind(&(SERVER_ADDRESS, 4000)).await.unwrap();
    let codec_builder = LengthDelimitedCodec::builder();

    let config = config::SideCarConfig::new(Path::new("./sidecar_config.toml"));
    let mut server = SideCarServer::new(
        config.get_certificate_config_path(),
        config.get_key_path(),
        config.yield_mapping(),
    );

    let mut credential_manager = CredentialManager::new("sidecar_cert.pem", "sidecar_key.pem");

    let binaries = config.get_binaries();

    //Reads binaries from disk, hashes them, and registers them
    for (bin_name, bin_setup) in binaries.into_iter() {
        let hash = hash_bin(Path::new(&bin_setup.bin_path.clone())).expect("Couldn't hash binary");
        // let service_name = config
        //     .get_service_name(&bin_name)
        //     .expect("Binary -> Service name mapping doesn't exist")
        //     .0
        //     .as_str();
        let verif_info = credential_manager
            .launch_binary(bin_setup.bin_path, bin_setup.run_path, &bin_name.0.as_str())
            .expect("Couldn't launch binary and generated credentials for it");
        server
            .register_running_service(bin_name.clone(), hash)
            .await;
        server.register_verif_info(bin_name, verif_info).await;
    }

    //Make non mutable after setup
    let server = server;
    server.show_running_binaries().await;

    //Expose sidecar to clients (usual tarpc way)
    loop {
        let (stream, _peer_addr) = listener.accept().await.unwrap();
        println!("Accepted a connection");
        let framed = codec_builder.new_framed(stream);

        let transport = new_transport(framed, Json::default());
        let fut = BaseChannel::with_defaults(transport)
            .execute(server.clone().serve())
            .for_each(wait_upon);
        tokio::spawn(fut);
    }
    unreachable!()
}
