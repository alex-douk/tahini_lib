#Install the policy checker compiler plugin
install_attest:
  cd ./policy_signing && cargo install --locked --path .

alias gen_att_keys := generate_attestation_keys
generate_attestation_keys:
  openssl genpkey -algorithm ed25519 -outform DER -out ./keys/certif_keys/certificate_skey.der
  openssl pkey -in ./keys/certif_keys/certificate_skey.der -pubout -outform DER -out ./keys/certif_keys/certificate_verifier.der

alias gen_run_keys:= generate_runtime_keys
generate_runtime_keys:
  openssl genpkey -algorithm ed25519 -outform DER -out ./keys/runtime_keys/sidecar_skey.der
  openssl pkey -in ./keys/runtime_keys/sidecar_skey.der -pubout -outform DER -out ./keys/runtime_keys/runtime_client_pkey.der

alias gk:= generate_all_keys
generate_all_keys:
  just generate_attestation_keys
  just generate_runtime_keys

#Migrate created keys to new folder
migrate_keys NEW_KEY_FOLDER:
  cp -r ./keys {{NEW_KEY_FOLDER}}


