use aws_lc_rs::signature::UnparsedPublicKey;
use serde::Deserialize;
use std::{collections::HashMap, fs::File, io::Read, path::Path};
use toml::{Table, Value};

use crate::types::{AttestErrors, AttestResult, ServiceName, TahiniCertificate};

#[derive(Default)]
pub struct CertificateLoader {
    certificates: HashMap<ServiceName, TahiniCertificate>,
    accepted_keys: Option<UnparsedPublicKey<Vec<u8>>>,
    //FIXME: Lazy to handle types and propagate it everywhere. The value field of the map should be
    //BinaryName. The goal is for the client to be able to supply a ServiceName via a generated
    //Tahini Client stub, and this gets handled internally. Other solution is to segment
    //certificates per service...
    service_to_bin: HashMap<ServiceName, ServiceName>,
}

impl CertificateLoader {
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            accepted_keys: None,
            service_to_bin: HashMap::new(),
        }
    }

    ///Registers the certificate for a given Tahini service to the loader.
    ///Only supports loading from filesystem.
    pub fn register_service(
        &mut self,
        path: &Path,
        service_name: ServiceName,
    ) -> AttestResult<bool> {

        let file = File::open(path).map_err(|e| AttestErrors::IoError(e))?;
        let certificate: TahiniCertificate =
            serde_json::from_reader(file).map_err(|e| AttestErrors::AttestDataMalformedError(e))?;
        if service_name != certificate.service_name {
            return Err(AttestErrors::ServiceMismatchError);
        }
        Ok(self
            .certificates
            .insert(service_name.clone(), certificate)
            .is_none())
        // match self.service_to_bin.get(&service_name) {
        //     None => {
        //             println!(
        //                 "Got a mismatch : no locally held for {:?} vs certificate {:?}", service_name, certificate.service_name
        //             );
        //         return Err(AttestErrors::ServiceMismatchError)}
        //     ,
        //     Some(serv) => {
        //         if serivi != certificate.service_name {
        //             println!(
        //                 "Got a mismatch : locally held {:?} vs certificate {:?}",
        //                 serv, certificate.service_name
        //             );
        //             return Err(AttestErrors::ServiceMismatchError);
        //         }
        //         Ok(self
        //             .certificates
        //             .insert(serv.clone(), certificate)
        //             .is_none())
        //     }
        // }
    }

    //Loads a public key to verify certificates
    pub fn load_certificate_key(&mut self, path: &Path) -> AttestResult<bool> {
        if self.accepted_keys.is_some() {
            return Ok(false);
        }
        let mut file = File::open(path).map_err(|e| AttestErrors::IoError(e))?;
        let mut pkey_bytes: Vec<u8> = Vec::new();
        file.read_to_end(&mut pkey_bytes)
            .map_err(|e| AttestErrors::IoError(e))?;
        //Hacky: Last 32-bytes of DER format are key bytes. aws-lc-rs requires straight key
        //material
        let key_material = &pkey_bytes[pkey_bytes.len() - 32..];
        let pkey = UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, key_material.to_vec());
        self.accepted_keys = Some(pkey);
        Ok(true)
    }

    pub fn get_key(&self) -> &Option<UnparsedPublicKey<Vec<u8>>> {
        &self.accepted_keys
    }

    pub fn from_config(config_path: &Path) -> AttestResult<Self> {
        let contents =
            std::fs::read_to_string(config_path).map_err(|e| AttestErrors::IoError(e))?;
        let data: Config =
            toml::from_str(&contents).map_err(|e| AttestErrors::ConfigError(e.to_string()))?;
        data.into_loader()
    }

    //FIXME: This method should not exist. It is an artifact of not including service names in the
    //manifest, and having to retrieve them post-hoc. If the manifest includes the actual service
    //name for which it is generate, this method should be removed.
    pub fn register_bin_mapping(&mut self, bin: ServiceName, service: ServiceName) {
        self.service_to_bin.insert(service, bin);
    }

    pub fn get_reverse_mapping(&self, service_name: &ServiceName) -> Option<&ServiceName> {
        self.service_to_bin.get(service_name)
    }
}

#[derive(Deserialize, Debug)]
struct Config {
    certificates: Table,
    keys: Option<KeyConfig>,
    service_mapping: Table,
}

#[derive(Deserialize, Debug)]
struct KeyConfig {
    path: String,
}

impl Config {
    fn into_loader(self) -> AttestResult<CertificateLoader> {
        let mut loader = CertificateLoader::new();
        if self.keys.is_some() {
            let key_path = self.keys.unwrap().path;
            let path = Path::new(&key_path);
            loader.load_certificate_key(path)?;
        }
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
        Ok(loader)
    }
}

pub trait CertificateProvider {
    fn get_certificate(&self, service_name: &ServiceName) -> Option<&TahiniCertificate>;
}

impl CertificateProvider for CertificateLoader {
    fn get_certificate(&self, service_name: &ServiceName) -> Option<&TahiniCertificate> {
        self.certificates.get(service_name)
    }
}
