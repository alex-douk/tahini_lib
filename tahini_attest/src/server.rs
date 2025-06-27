use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    usize,
};

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use lazy_static::lazy_static;

use crate::types::ClientId;
use clap::Parser;
use std::thread;

lazy_static! {
    pub static ref CLIENT_MAP: Arc<RwLock<HashMap<ClientId, RandomizedNonceKey>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

#[ctor::ctor]
pub unsafe fn client_map_state_constructor() {
    let args = SidecarCliArgs::parse();
    let fifo_read = File::options()
        .read(true)
        .open(&args.fifo_path)
        .expect("Couldn't open FIFO as read");
    thread::spawn(move || {
        let kek_hex = args.kek_hex;
        let fifo_path = args.fifo_path;
        let read_handler = FifoReadHandle::new(fifo_path, kek_hex);
        loop {
            //read_session_key is blocking on actually reading a key
            let (client_id, session_key) = read_handler.read_session_key();
            //We only acquire write lock if we have a key to write
            CLIENT_MAP
                .write()
                .expect("Couldn't get a write lock on the client map")
                .insert(client_id, session_key);
        }
    });
}

#[derive(clap::Parser)]
struct SidecarCliArgs {
    #[arg(long = "fifo_path")]
    fifo_path: PathBuf,
    #[arg(long = "kek_hex")]
    kek_hex: String,
}

struct FifoReadHandle {
    kek: RandomizedNonceKey,
    handle: File,
}

impl FifoReadHandle {
    fn new<P: AsRef<Path>>(fifo_path: P, hex_kek: String) -> Self {
        let fifo_read = File::options()
            .read(true)
            .open(fifo_path.as_ref())
            .expect("Couldn't open FIFO as read");
        let kek_bytes = hex::decode(hex_kek).expect("Malformed kek received from command line");
        Self {
            kek: RandomizedNonceKey::new(&AES_256_GCM, &kek_bytes)
                .expect("Couldn't generate AES KEK key from material"),
            handle: fifo_read,
        }
    }

    fn read_session_key(&self) -> (ClientId, RandomizedNonceKey) {
        let mut reader = BufReader::new(&self.handle);
        let mut buf = String::new();
        loop {
            match reader.read_line(&mut buf) {
                Ok(n) => {
                    if n > 0 {
                        std::io::stdout().flush();
                        let splitted_line: Vec<_> = buf.split(",").collect();
                        if splitted_line.len() != 3 {
                            panic!("Line received from FIFO is malformed")
                        }
                        let (nonce_hex, cipher_hex, client_id) =
                            (splitted_line[0], splitted_line[1], splitted_line[2]);
                        //Decode to slice handles string mismatch, so we can ensure the nonce is
                        //welformed and full after decoding
                        let mut nonce: [u8; 12] = [0u8; 12];
                        hex::decode_to_slice(nonce_hex, &mut nonce).expect("Malformed nonce");

                        let nonce = Nonce::assume_unique_for_key(nonce);
                        let mut cipher_vec = hex::decode(cipher_hex).expect("Cipher hex malformed");
                        let key_material = self
                            .kek
                            .open_in_place(nonce, Aad::empty(), &mut cipher_vec)
                            .expect("Couldn't decrypt cipher");


                        let key = RandomizedNonceKey::new(&AES_256_GCM, &key_material)
                            .expect("Couldn't generate session key from derived key material");

                        let client_id = ClientId::from(
                            usize::from_str_radix(client_id.trim_end_matches("\n"), 10)
                                .expect("Client ID malformed"),
                        );
                        buf.clear();

                        return (client_id, key);
                    }
                }
                Err(_) => panic!("Couldn't read from the FIFO"),
            }
        }
    }
}

pub fn get_key_for_client(client_id: &ClientId) -> RandomizedNonceKey {
    let mut engine_lock = CLIENT_MAP
        .write()
        .expect("Couldn't get a read lock on the client map");
    let val = engine_lock
        .remove_entry(client_id)
        .expect("Client_id not found in the map");
    val.1
}
