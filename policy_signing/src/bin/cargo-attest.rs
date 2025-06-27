#![feature(rustc_private)]

use env_logger::Target;
use std::fs::{create_dir, File, OpenOptions};
use log::trace;

fn main() {
    env_logger::builder()
        .target(Target::Pipe(Box::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open("attest.log")
                .unwrap(),
        )))
        .init();
    match create_dir("./policy_hashes"){
        Ok(_) => trace!("Creating new policy hashes from scratch"),
        Err(_) => trace!("Updating existing policy hashes")
    };
    let _ = File::create("./policy_hashes/hash_index");
    //

    rustc_plugin::cli_main(trusted_attest::AttestPlugin);
}
