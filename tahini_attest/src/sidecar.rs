use std::{
    cell::OnceCell,
    collections::HashMap,
    ffi::CString,
    fs::File,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use aws_lc_rs::{
    aead::{Aad, RandomizedNonceKey, AES_256_GCM},
    error::Unspecified,
    kdf::{get_sskdf_hmac_algorithm, sskdf_hmac},
    rand::SecureRandom
};
use sha2::{Digest, Sha256};

use crate::types::{
    BinHash, ClientId,
    ServiceName,
};


pub fn launch_binary<P: AsRef<Path>>(bin_path: P, dir_to_run: P) -> Result<FifoWriterHandle, ()> {
    let fifo_path = format_fifo_path(&dir_to_run);
    create_fifo(&fifo_path);
    let (mut fifo_handle, kek_hex) = FifoWriterHandle::new(&fifo_path);

    Command::new(bin_path.as_ref())
        .current_dir(dir_to_run)
        .arg("--fifo_path")
        .arg(format!("{}", fifo_path.to_str().unwrap()))
        .arg("--kek_hex")
        .arg(format!("{}", kek_hex))
        .spawn()
        .expect("Couldn't start process");

    fifo_handle.enable_fifo();
    Ok(fifo_handle)
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

pub fn format_fifo_path<P: AsRef<Path>>(dir_to_run: P) -> PathBuf {
    dir_to_run.as_ref().join("sidecar_fifo").to_path_buf()
}

pub(crate) fn create_fifo<P: AsRef<Path>>(fifo_path: P) {
    let _ = std::fs::remove_file(&fifo_path);
    let fifo_name = CString::new(
        fifo_path
            .as_ref()
            .to_str()
            .expect("Couldn't convert FIFO path to str"),
    )
    .expect("Couldn't convert str path to C String");
    unsafe {
        libc::mkfifo(fifo_name.as_ptr(), 0o644);
    }
}

pub struct FifoWriterHandle {
    kek: RandomizedNonceKey,
    fifo_path: PathBuf,
    handle: OnceCell<File>,
}

impl FifoWriterHandle {
    fn new<P: AsRef<Path>>(path: P) -> (Self, String) {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mut key_vec = [0u8; 32];
        rng.fill(&mut key_vec)
            .expect("Couldn't create key material for kek");
        let alg_id = get_sskdf_hmac_algorithm(aws_lc_rs::kdf::SskdfHmacAlgorithmId::Sha256)
            .ok_or(Unspecified)
            .unwrap();

        let mut end_derived_key = [0u8; 32];

        let mut salt = [0u8; 32];
        rng.fill(&mut salt).expect("Couldn't create salt for kek");
        let info = path.as_ref().to_str().unwrap().as_bytes();

        sskdf_hmac(alg_id, &key_vec, info, &salt, &mut end_derived_key)
            .expect("Couldn't derive kek");

        let usable_key = RandomizedNonceKey::new(&AES_256_GCM, &end_derived_key)
            .expect("Couldn't generate AES key from derived material");

        let derived_hex = hex::encode(&end_derived_key);
        (
            Self {
                kek: usable_key,
                fifo_path: path.as_ref().to_path_buf(),
                handle: OnceCell::new(),
            },
            derived_hex,
        )
    }

    fn enable_fifo(&mut self) {
        let fifo_file = File::options()
            .write(true)
            .append(true)
            .open(&self.fifo_path)
            .expect("Couldn't open FIFO file");

        self.handle
            .set(fifo_file)
            .expect("Couldn't set fifo handler");
    }

    pub fn write_session_key(
        &mut self,
        key_material: &[u8],
        client_id: &ClientId,
    ) -> Result<(), ()> {
        //Encrypt session key
        let mut cipher = key_material.to_vec();
        println!("FIFO_WRITE: Derived key as hex is {}", hex::encode(&cipher));
        let nonce = self
            .kek
            .seal_in_place_append_tag(Aad::empty(), &mut cipher)
            .map_err(|_| ())?;
        //Put the cipher in hex form so easier to decode on the other end
        let cipher_hex = hex::encode(&cipher);
        //Same for nonce
        let nonce_hex = hex::encode(nonce.as_ref());
        //Also pass the client id
        write!(
            self.handle.get_mut().expect("FIFO was not enabled yet"),
            "{},{},{}\n",
            nonce_hex,
            cipher_hex,
            client_id
        )
        .expect("Couldn't write to FIFO");
        println!("We wrote line \"{},{},{}\n\"",nonce_hex, cipher_hex, client_id);
        Ok(())
    }
}
