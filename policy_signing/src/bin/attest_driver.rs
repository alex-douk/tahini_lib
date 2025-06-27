#![feature(rustc_private)]
use env_logger::Target;
use std::fs::OpenOptions;

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
    rustc_plugin::driver_main(trusted_attest::AttestPlugin);
}
