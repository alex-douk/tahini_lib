use crate::TahiniCertificate;
use aws_lc_rs::signature::Ed25519KeyPair;
use std::io;
use std::path::Path;

use super::{BinHash, PolicyHash};

fn read_file(path: &std::path::Path) -> io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

pub fn get_signing_key(path: &Path) -> Ed25519KeyPair {
    let der_bytes = read_file(path).expect("Couldn't read private key certificate file");
    let kpair = Ed25519KeyPair::from_pkcs8(&der_bytes);
    kpair.expect("Couldn't parse certificate file ")
}

// pub fn verify_pkey(path: &Path) -> UnparsedPublicKey<Vec<u8>> {
//     let pkey_bytes = read_file(path).unwrap();
//     let key_material = &pkey_bytes[pkey_bytes.len()-32..];
//     let pkey = UnparsedPublicKey::new(&signature::ED25519, key_material.to_vec());
//     pkey
// }

pub fn gen_certificate(service_name: String, data: (PolicyHash, BinHash), key: &Ed25519KeyPair) -> TahiniCertificate {
    let policy_u8 = hex::decode(&data.0.0).expect("policy hash is not hexadecimal");
    let binary_u8 = hex::decode(&data.1.0).expect("policy hash is not hexadecimal");
    let mut signing_data = policy_u8.clone();
    signing_data.extend(binary_u8);
    let sig = key.sign(signing_data.as_slice());
    TahiniCertificate {
        service_name,
        policy_hash: data.0,
        binary_hash: data.1,
        signature: crate::Signature(hex::encode(sig.as_ref())),
    }
}

// pub fn verify_certificate(path: &Path, pkey: &UnparsedPublicKey<Vec<u8>>) -> bool {
//     let certificate_file =
//         File::open(path).expect("Couldn't find certificate file at provided path");
//     let certificate: TahiniCertificate =
//         serde_json::from_reader(certificate_file).expect("Couldn't parse certificate data");
//     println!("Verifying signature for {:?}", path);
//
//     let policy_u8 = hex::decode(&certificate.policy_hash.0).expect("policy hash is not hexadecimal");
//     let binary_u8 = hex::decode(&certificate.binary_hash.0).expect("binary hash is not hexadecimal");
//     let signature = hex::decode(&certificate.signature.0).expect("signature is not hexadecimal");
//     
//     let mut signing_data = policy_u8.clone();
//     signing_data.extend(binary_u8);
//     pkey.verify(&signing_data, &signature).expect("Couldn't verify signature");
//     true
// }
