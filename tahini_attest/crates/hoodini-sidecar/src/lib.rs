use std::{
    collections::HashMap,
    ffi::CString,
    fs::File,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use fizz_rs::{Certificate, CredentialGenerator};
use sha2::{Digest, Sha256};

use hoodini_core::types::{BinHash, ServiceName};

pub struct CredentialManager(pub fizz_rs::CredentialGenerator);

impl CredentialManager {
    pub fn new(cert_path: &str, key_path: &str) -> Self {
        let cert = Certificate::load_from_files(cert_path, key_path)
            .expect("Couldn't load certificate for sidecar");
        Self(CredentialGenerator::new(cert).expect("Couldn't generated cred manager for sidecar"))
    }
}

impl CredentialManager {
    pub fn launch_binary<P: AsRef<Path>>(
        &mut self,
        bin_path: P,
        dir_to_run: P,
        service_name: &str,
    ) -> Result<fizz_rs::VerificationInfo, ()> {
        let credential = self.0.generate(service_name, 86400).map_err(|_| ())?;
        let verif_info = credential.verification_info();

        Command::new(bin_path.as_ref())
            .current_dir(dir_to_run)
            // .arg("--fifo_path")
            .env("TAHINI_CREDENTIAL", serde_json::to_string(&credential).expect("Couldn't forward the credential to service"))
            .spawn()
            .expect("Couldn't start process");
        Ok(verif_info)
    }
}
pub fn hash_bins<P: AsRef<Path>>(bin_paths: Vec<P>) -> io::Result<HashMap<ServiceName, BinHash>> {
    let mut map = HashMap::new();
    for binary in bin_paths {
        let bin_hash = hash_bin(&binary)?;
        let bin_name = binary.as_ref().file_name().unwrap().to_str().unwrap();
        map.insert(bin_name.to_string().into(), bin_hash);
    }
    Ok(map)
}

pub fn hash_bin<P: AsRef<Path>>(bin_path: P) -> io::Result<BinHash> {
    let file = File::open(bin_path).expect("Can't find file");
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(BinHash(hex::encode(result)))
}
