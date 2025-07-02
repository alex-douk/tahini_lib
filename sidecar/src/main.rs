use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use std::future::Future;
use std::mem::size_of;
use aws_lc_rs::signature::Ed25519KeyPair;
use futures::StreamExt;
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use tahini_attest::loader::{CertificateLoader, CertificateProvider};
use tahini_attest::service::{AttestationService, compute_local_share, derive_key_from_shares};
use tahini_attest::sidecar::{FifoWriterHandle, hash_bin, launch_binary};
use tahini_attest::types::{
    BinHash, ClientId, DynamicAttestationData, DynamicAttestationReport, ServiceName,
};
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
    //For given service, yields the pipe write handler
    service_key_passing_sessions: Arc<Mutex<HashMap<ServiceName, FifoWriterHandle>>>,
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
            service_key_passing_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    //Registers mapping bin_name -> bin_hash
    pub async fn register_running_service(&mut self, service_name: ServiceName, hash: BinHash) {
        let mut map = self.service_bin_map.write().await;
        map.insert(service_name, hash);
    }

    //Debugging purposes
    pub async fn show_running_binaries(&self) {
        println!("{:#?}", self.service_bin_map.read().await);
    }

    //Registers bin_name -> pipe handler
    pub async fn setup_service_key_channel(
        &mut self,
        service_name: ServiceName,
        handler: FifoWriterHandle,
    ) {
        let mut map = self.service_key_passing_sessions.lock().await;
        match map.insert(service_name.clone(), handler) {
            None => println!("Registered service {}", &service_name),
            Some(_) => panic!("Service shouldn't be registered for the sidecar"),
        }
    }
}

impl AttestationService for SideCarServer {
    //API exposed to client.
    //Does the following (functionally):
    //Generates client session key (via key agreement protocol)
    //Generates client ID
    //Generates attestation report
    //Signs attestation report
    //Sends (client_id, session_key) to server via pipe
    //Returns (client_id, server_key_share, attestation_report) to client
    async fn attest_binary(
        self,
        _context: tarpc::context::Context,
        service_name: ServiceName,
        nonce: u128,
        key_share: Vec<u8>,
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

        let mut usize_b = [0u8; size_of::<usize>()];
        let rng = SystemRandom::new();
        rng.fill(&mut usize_b).expect("Couldn't generate client id");
        let client_id = ClientId::from(usize::from_be_bytes(usize_b));

        let (sk, pk) = compute_local_share();
        let usable_key = derive_key_from_shares(sk, key_share);

        let signing_data = DynamicAttestationData {
            cert: certificate,
            nonce,
            service_name: service_name.clone(),
            current_bin_hash: bin.clone(),
            server_key_share: pk.as_ref().to_vec(),
            client_id: client_id.clone(),
        };

        let sign_data_u8 =
            serde_json::to_vec(&signing_data).expect("Couldn't transform signing data to bytes");
        let signer = self.signing_key.read().await;
        let sig = signer.sign(&sign_data_u8).into();

        println!("Trying to access handler for service {}", &service_name);
        let mut locked_session_handler = self.service_key_passing_sessions.lock().await;
        locked_session_handler
            .get_mut(
                self.service_mapping
                    .read()
                    .await
                    .get(&service_name)
                    .expect("Provided binary is not registered"),
            )
            .expect("Service should have a handler but didn't")
            .write_session_key(&usable_key.to_vec(), &client_id)
            .expect("Couldn't write session to service pipe");
        drop(locked_session_handler);
        DynamicAttestationReport {
            certificate: certificate.clone(),
            current_bin_hash: bin.clone(),
            nonce,
            service_name,
            server_key_share: pk.as_ref().to_vec(),
            client_id,
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

    let binaries = config.get_binaries();

    //Reads binaries from disk, hashes them, and registers them
    for (bin_name, bin_setup) in binaries.into_iter() {
        let hash = hash_bin(Path::new(&bin_setup.bin_path.clone())).expect("Couldn't hash binary");
        let handler =
            launch_binary(bin_setup.bin_path, bin_setup.run_path).expect("Couldn't start binary");
        server
            .setup_service_key_channel(
                config
                    .get_service_name(&bin_name)
                    .expect("Binary->Service mapping does not exist")
                    .clone(),
                handler,
            )
            .await;
        server.register_running_service(bin_name, hash).await;
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
