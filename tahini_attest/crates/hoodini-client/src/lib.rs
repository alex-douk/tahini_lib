use std::{
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    u128,
};

use aws_lc_rs::{
    aead::{AES_256_GCM, RandomizedNonceKey},
    signature::UnparsedPublicKey,
};
use serde::Deserialize;
use tarpc::{context, tokio_serde::formats::Json};
use toml::{Table, Value};

pub use hoodini_core::{
    certificate::{CertificateLoader, CertificateProvider},
    service::{AttestationServiceClient, compute_local_share, derive_key_from_shares},
    types::{
        AttestErrors, AttestResult, ClientId, DynamicAttestationData, ServiceName,
        TahiniCertificate,
    },
};

pub struct DynamicAttestationVerifier {
    //Certificate handler
    certificate_handler: CertificateLoader,
    //Allowed public keys for runtime attestation verification
    allowed_keys: UnparsedPublicKey<Vec<u8>>,
    //Config for connecting to sidecar
    sidecar_host: SidecarHost,
}

struct SidecarHost {
    hostname: IpAddr,
    port: u16,
}

impl DynamicAttestationVerifier {
    pub fn from_config(config_path: &Path) -> AttestResult<Self> {
        let contents =
            std::fs::read_to_string(config_path).map_err(|e| AttestErrors::IoError(e))?;
        let data: Config =
            toml::from_str(&contents).map_err(|e| AttestErrors::ConfigError(e.to_string()))?;
        data.into_verifier()
    }

    ///Verify remote certificate against the one from disk
    pub fn verify_certificate(&self, remote_certificate: &TahiniCertificate) -> bool {
        let key = self.certificate_handler.get_key();
        if key.is_none() {
            return false;
        }
        let local_certificate = self
            .certificate_handler
            .get_certificate(&remote_certificate.service_name);
        if local_certificate.is_none() {
            return false;
        }

        let local_certificate = local_certificate.unwrap();
        local_certificate == remote_certificate
    }

    ///Main function for client-side verification.
    ///This function is invoked by the Tahini Tarpc wrapper (living in Sesame currently)
    ///In order:
    ///Generate local_key_share
    ///Connect to sidecar to get (client_id, server_key_share, attestation_report)
    ///Verify attestation
    ///Finish key agreement protocol
    ///Return client_id and key to the Tahini tarpc client handler 
    pub async fn verify_binary(
        &self,
        service_name: ServiceName,
    ) -> AttestResult<(ClientId, RandomizedNonceKey)> {
        let mut dest = [0u8; 16];
        if aws_lc_rs::rand::fill(&mut dest).is_err() {
            return Err(AttestErrors::CryptoError);
        }
        let nonce = u128::from_be_bytes(dest);

        let bin_name = self.certificate_handler.get_reverse_mapping(&service_name);
        if bin_name.is_none() {
            return Err(AttestErrors::ServiceMismatchError);
        }

        let bin_name = bin_name.expect("Binary reverse lookup should exist");

        let (sk, pkey) = compute_local_share();
        let host = (self.sidecar_host.hostname, self.sidecar_host.port);
        let stream = tarpc::serde_transport::tcp::connect(host, Json::default);
        let client = AttestationServiceClient::new(Default::default(), stream.await.unwrap());
        let report = client
            .spawn()
            .attest_binary(
                context::current(),
                bin_name.clone(),
                nonce,
                pkey.as_ref().to_vec(),
            )
            .await
            .map_err(|e| AttestErrors::NetworkError(e))?;
        let certificate = report.certificate;
        if self.verify_certificate(&certificate) == false {
            println!("Certificate is not verified");
            return Err(AttestErrors::InvalidAttestation);
        }
        if report.current_bin_hash != certificate.binary_hash {
            println!("Mismatch of hashes");
            return Err(AttestErrors::InvalidAttestation);
        }

        let client_id = report.client_id;
        let server_key_share = report.server_key_share.clone();
        let usable_key = derive_key_from_shares(sk, server_key_share);
        let aes_key = RandomizedNonceKey::new(&AES_256_GCM, &usable_key)
            .expect("Couldn't generate the AES session key client side");

        let attestation_data = DynamicAttestationData {
            cert: &certificate,
            nonce,
            service_name: bin_name.clone(),
            current_bin_hash: certificate.binary_hash.clone(),
            client_id: client_id.clone(),
            server_key_share: report.server_key_share,
        };

        let sign_data_u8 =
            serde_json::to_vec(&attestation_data).expect("Couldnt serialize attestation data");

        self.allowed_keys
            .verify(
                &sign_data_u8,
                &hex::decode(report.signature.0).expect("Non hex signature"),
            )
            .map(|_| {
                println!("Signature was verified for bin{:?}", bin_name);
                (client_id, aes_key)
            }).map_err(|_| AttestErrors::InvalidAttestation)
    }
}

#[derive(Deserialize)]
struct Config {
    certificates: Table,
    keys: KeyConfig,
    sidecar: SidecarConfig,
    service_mapping: Table,
}

#[derive(Deserialize)]
struct KeyConfig {
    certificate_key: String,
    attestation_key: String,
}

#[derive(Deserialize)]
#[allow(unused)]
struct SidecarConfig {
    host: String,
    port: u16,
}

impl Config {
    fn into_verifier(self) -> AttestResult<DynamicAttestationVerifier> {
        let mut loader = CertificateLoader::new();

        let path = Path::new(&self.keys.certificate_key);
        loader.load_certificate_key(path)?;
        let path = Path::new(&self.keys.attestation_key);
        let mut file = File::open(path).map_err(|e| AttestErrors::IoError(e))?;
        let mut pkey_bytes: Vec<u8> = Vec::new();
        file.read_to_end(&mut pkey_bytes)
            .map_err(|e| AttestErrors::IoError(e))?;
        //Hacky: Last 32-bytes of DER format are key bytes. aws-lc-rs requires straight key
        //material
        let key_material = &pkey_bytes[pkey_bytes.len() - 32..];
        let allowed_keys =
            UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, key_material.to_vec());

        for (bin_name, service_name) in self.service_mapping.into_iter() {
            loader.register_bin_mapping(
                ServiceName(bin_name),
                ServiceName(service_name.as_str().unwrap().to_string()),
            );
        }
        for (service_name, v) in self.certificates.into_iter() {
            match v {
                Value::String(certif_path) => {
                    let path = Path::new(&certif_path);
                    loader.register_service(path, ServiceName(service_name))?;
                }
                _ => {
                    return Err(AttestErrors::ConfigError(
                        "Certificate path is malformed".to_string(),
                    ));
                }
            }
        }
        Ok(DynamicAttestationVerifier {
            certificate_handler: loader,
            allowed_keys,
            sidecar_host: SidecarHost {
                hostname: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: self.sidecar.port,
            },
        })
    }
}
