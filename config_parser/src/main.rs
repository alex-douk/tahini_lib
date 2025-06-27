use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};
use toml::Table;

#[derive(clap::Parser)]
struct CliArgs {
    #[arg(short = 'm', long = "project_metadata")]
    metadata_path: PathBuf,
    #[arg(short = 'c', long = "certificate_dir_path")]
    certificate_path: PathBuf,
    #[arg(short = 'k', long = "signing_key_path")]
    key_signing_path: PathBuf,
    #[arg(short = 'C', long = "certif_config_path")]
    certif_config_path: PathBuf,
}

#[derive(Deserialize)]
struct MetadataConfig {
    binaries: Table,
    service_mapping: Table,
}

#[derive(Serialize)]
struct CertificateConfig {
    certificates: Table,
    service_mapping: Table,
}

#[derive(Serialize)]
struct RuntimeConfig {
    binaries: Table,
    certificates_config: CertifConfForRuntime,
    signing_key: KeyConf,
    service_mapping: Table,
}

#[derive(Serialize)]
struct CertifConfForRuntime {
    path: String,
}

#[derive(Serialize)]
struct KeyConf {
    path: String,
}

impl MetadataConfig {
    fn parse_to_cert_conf(&self, cert_path: &PathBuf) -> CertificateConfig {
        let mut table = Table::new();
        for keys in self.binaries.keys() {
            let cert_name = format!("{}_certificate.json", keys);
            let full_path = cert_path.join(cert_name);
            table.insert(
                keys.to_string(),
                toml::Value::String(full_path.to_str().unwrap().to_string()),
            );
        }
        CertificateConfig {
            certificates: table,
            service_mapping: self.service_mapping.clone(),
        }
    }
    fn parse_to_runtime_conf(self, args: CliArgs) -> RuntimeConfig {
        println!("We got binary map :{:?}", self.binaries);
        RuntimeConfig {
            binaries: self.binaries,
            certificates_config: CertifConfForRuntime {
                path: args.certif_config_path.to_str().unwrap().to_string(),
            },
            signing_key: KeyConf {
                path: args.key_signing_path.to_str().unwrap().to_string(),
            },
            service_mapping: self.service_mapping,
        }
    }
}

fn main() -> Result<(), ()> {
    let args = CliArgs::parse();
    let contents =
        std::fs::read_to_string(&args.metadata_path).expect("Couldn't read metadata file provided");
    let base_config: MetadataConfig = toml::from_str(&contents).expect("Toml file malformed");

    let cert_conf = base_config.parse_to_cert_conf(&args.certificate_path);
    let runtime_conf = base_config.parse_to_runtime_conf(args);

    let mut cert_file =
        File::create("./certificate_config.toml").expect("Couldn't create config file");
    cert_file
        .write(
            toml::to_string_pretty(&cert_conf)
                .expect("Cert config is malformed TOML")
                .as_bytes(),
        )
        .expect("Couldn't write cert config to file");

    let mut runtime_file =
        File::create("./sidecar_config.toml").expect("Couldn't create config file");
    runtime_file
        .write(
            toml::to_string(&runtime_conf)
                .expect("Cert config is malformed TOML")
                .as_bytes(),
        )
        .expect("Couldn't write cert config to file");

    Ok(())
}
