#Install the policy checker compiler plugin
install_attest:
  cd {{justfile_dir()}}/policy_signing/ && cargo install --locked --path .
  cd {{justfile_dir()}}

alias gen_att_keys := generate_attestation_keys
generate_attestation_keys:
  mkdir -p {{justfile_dir()}}/keys/certif_keys/
  openssl genpkey -algorithm ed25519 -outform DER -out {{justfile_dir()}}/keys/certif_keys/certificate_skey.der
  openssl pkey -in {{justfile_dir()}}/keys/certif_keys/certificate_skey.der -pubout -outform DER -out {{justfile_dir()}}/keys/certif_keys/certificate_verifier.der

alias gen_run_keys:= generate_runtime_keys
generate_runtime_keys:
  mkdir -p {{justfile_dir()}}/keys/runtime_keys/
  openssl genpkey -algorithm ed25519 -outform DER -out ./keys/runtime_keys/sidecar_skey.der
  openssl pkey -in ./keys/runtime_keys/sidecar_skey.der -pubout -outform DER -out ./keys/runtime_keys/runtime_client_pkey.der

alias gk:= generate_all_keys
alias gen_keys:=generate_all_keys
generate_all_keys:
  just generate_attestation_keys
  just generate_runtime_keys

#Migrate created keys to new folder
migrate_keys NEW_KEY_FOLDER:
  cp -r {{justfile_dir()}}/keys {{NEW_KEY_FOLDER}}

export_public_keys NEW_KEY_FOLDER:
  mkdir -p {{NEW_KEY_FOLDER}}/certif_key
  cp {{justfile_dir()}}/keys/certif_keys/certificate_verifier.der {{NEW_KEY_FOLDER}}/certif_key/
  mkdir -p {{NEW_KEY_FOLDER}}/runtime_key
  cp {{justfile_dir()}}/keys/runtime_keys/runtime_client_pkey.der {{NEW_KEY_FOLDER}}/runtime_key/


#Invoke compiler plugin to generate policy analysis
compile_policies PROJECT_FOLDER:
  cd {{PROJECT_FOLDER}} && RUST_LOG=trace cargo +nightly-2024-12-15 attest
  cd {{justfile_dir()}}


#Generate certificates bound to binaries
gen_certificates PROJECT_FOLDER KEY_FOLDER="../keys":
  mkdir -p {{justfile_dir()}}/certificates/
  cd certificate_generation && cargo run --release -- -p ../{{PROJECT_FOLDER}} -k {{KEY_FOLDER}}/certif_keys/certificate_skey.der
  cp -r {{PROJECT_FOLDER}}/certificates/* {{justfile_dir()}}/certificates/{{file_name(PROJECT_FOLDER)}}/
  cd {{justfile_dir()}}


#Invoke the entire static toolchain
build_toolchain PROJECT_FOLDER KEY_FOLDER="../keys":
  just install_attest
  echo "Installed compiler plugin"
  just compile_policies {{PROJECT_FOLDER}}
  echo "Analyzed policies"
  just gen_certificates {{PROJECT_FOLDER}} {{KEY_FOLDER}}
  echo "Generated certificates"


gen_sidecar_configs PROJECT_FOLDER:
  cd ./config_parser && cargo run --release -- -m ../{{PROJECT_FOLDER}}/project_metadata.toml -c {{justfile_dir()}}/certificates/{{file_stem(PROJECT_FOLDER)}}/ -k {{justfile_dir()}}/keys/runtime_keys/sidecar_skey.der -C {{justfile_dir()}}/sidecar/certificate_config.toml
  cp ./config_parser/certificate_config.toml ./config_parser/sidecar_config.toml ./sidecar


build: 
  cd ./policy_signing/ && cargo build --release
  cd ./config_parser// && cargo build --release
  cd ./certificate_generation/ && cargo build --release
  cd ./sidecar/ && cargo build --release


update PROJECT_FOLDER:
  @just gen_certificates {{PROJECT_FOLDER}}
  @just gen_sidecar_configs {{PROJECT_FOLDER}}
  @just run


do_all PROJECT_FOLDER USED_KEY_FOLDER:
  @just build
  @just build_toolchain {{PROJECT_FOLDER}}
  @just update {{PROJECT_FOLDER}}
  @just run

run:
  cd {{justfile_dir()}}/sidecar/ && cargo run --release


clean:
  cd ./policy_signing/ && rm -r target/
  cd ./config_parser/ && rm -r target/ certificate_config.toml sidecar_config.toml
  cd ./certificate_generation/ && rm -r target/
  # cd ./tahini_attest/ && rm -r target/
  cd ./sidecar/ && rm -r target/ certificate_config.toml sidecar_config.toml
  rm -r ./certificates
  rm -r ./keys
