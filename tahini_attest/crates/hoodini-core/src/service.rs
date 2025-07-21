use crate::types::ServiceName;
use aws_lc_rs::{
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, agree_ephemeral},
    error::Unspecified,
    kdf::{get_sskdf_hmac_algorithm, sskdf_hmac},
};

#[tarpc::service]
pub trait AttestationService {
    //FIXME: Add sidecar keyshare + client_id to the attestation report
    async fn attest_binary(service_name: ServiceName, nonce: u128, key_share: Vec<u8>) -> crate::types::DynamicAttestationReport;
}

pub fn compute_local_share() -> (EphemeralPrivateKey, PublicKey) {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let skey = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
    let pkey = skey.compute_public_key().unwrap();
    (skey, pkey)
}

//TODO: Add service name to key derivation
pub fn derive_key_from_shares(local_skey: EphemeralPrivateKey, remote_share: Vec<u8>) -> Vec<u8> {
    let pkey_peer = UnparsedPublicKey::new(&agreement::X25519, remote_share);
    let a = [0u8; 32];
    let info = "Sidecar_session".as_bytes();
    let mut end_derived_key = [0u8; 32];
    let alg_id = get_sskdf_hmac_algorithm(aws_lc_rs::kdf::SskdfHmacAlgorithmId::Sha256)
        .ok_or(Unspecified)
        .unwrap();
    let usable_kdf =
        |key_material: &[u8]| sskdf_hmac(alg_id, key_material, &info, &a, &mut end_derived_key);

    let _ = agree_ephemeral(
        local_skey,
        &pkey_peer,
        aws_lc_rs::error::Unspecified,
        usable_kdf,
    )
    .expect("Key exchange failed");
    end_derived_key.to_vec()

    // let aes_key = RandomizedNonceKey::new(&AES_128_GCM, &end_derived_key).unwrap();
    // aes_key
}
