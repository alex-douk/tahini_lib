# Tahini library

Tahini is a framework for verifiable, ergonomic, and practical privacy compliance for distributed applications.

Based on [Sesame](https://github.com/brownsys/Sesame), a framework for privacy compliance.

# Usage

This repository contains all utilities related to generating certificates and running the runtime attestation machine (aka Sidecar).

## Running a project
For a project with root `<PROJECT_ROOT>`,
you need to do:
```just
#Generate both certificate and runtime key pairs
just generate_all_keys 

#Export the public keys so they are accessible by the client
just export_public_keys <USED_KEY_FOLDER> 

# Before running the final step, ensure the project has been setup and generated a project_metadata.toml

#Attest to policies in a project, gen certificates, launch binaries, open pipes
#Warning: End-to-end certificate creation can take some time
just do_all <PROJECT_ROOT> 
```

# Repository contents

This repository currently contains all data structures that enable the two-stage attestation of Tahini services.

## Attestation data structures 
Used by Sesame (currently, WIP) for each Tahini client and server.

## Sidecar
Trusted process launching Tahini processes and enabler of runtime attestation protocol.

## Certificate creation
Build toolchain that turns source code into static guarantees embedded in a signed certificate.

