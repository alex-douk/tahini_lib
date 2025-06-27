use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use tahini_attest::types::{BinaryName, ServiceName};
use toml::{Table, Value};

#[derive(Deserialize)]
pub(crate) struct SideCarConfig {
    binaries: Table,
    certificates_config: CertificateConfig,
    signing_key: KeyConfig,
    service_mapping: HashMap<ServiceName, ServiceName>
}

#[derive(Deserialize)]
pub(crate) struct KeyConfig {
    path: String,
}

#[derive(Deserialize)]
pub(crate) struct CertificateConfig {
    path: String,
}

pub(crate) struct BinaryConfig {
    pub bin_path: String,
    pub run_path: String,
}

impl SideCarConfig {
    pub fn new(path: &Path) -> Self {
        let contents = std::fs::read_to_string(path).expect("Couldn't find sidecar config file");
        let data: SideCarConfig = toml::from_str(&contents).expect("Couldn't parse it into TOML");
        data
    }

    pub fn get_key_path(&self) -> &Path {
        Path::new(&self.signing_key.path)
    }

    pub fn get_certificate_config_path(&self) -> &Path {
        Path::new(&self.certificates_config.path)
    }

    pub fn get_binaries(&self) -> HashMap<ServiceName, BinaryConfig> {
        let mut hashmap = HashMap::new();
        for (k, v) in self.binaries.iter() {
            match v {
                Value::Table(map) => {
                    let conf = BinaryConfig {
                        bin_path: map
                            .get("bin_path")
                            .expect("Couldn't find path to binary file")
                            .as_str().unwrap().to_string(),
                        run_path: map
                            .get("run_path")
                            .expect("Couldn't find path to runtime directory")
                            .as_str().unwrap().to_string(),

                    };
                    hashmap.insert(k.clone().into(), conf);
                }
                _ => panic!("Binary path is not a string"),
            }
        }
        hashmap
    }


    pub fn yield_mapping(&self) -> HashMap<ServiceName, ServiceName> {
        self.service_mapping.clone()
    }

    pub fn get_service_name(&self, binary_name: &ServiceName) -> Option<&ServiceName> {
        self.service_mapping.get(&binary_name)
    }
}
