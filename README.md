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

This repository contains all system components of Tahini:


## Tahini RPC framework
Contains both the core network logic, application-safe interfaces, and the associated derive macros.
Is currently entwined with the attestation protocol, and the encryption.


## ScopeLight attestation
Libraries for the `ScopeLight` attestation protocol.
Contains core types, client-side interfaces, server-side interfaces, and sidecar interfaces.

Note the server-side interface should NOT be imported anywhere unless you want to be attested to by the sidecar.


## Sidecar
The runtime trusted launcher that is responsible for starting Tahini-attested services.
Currently starts services via means of the `std::process::Command` and passes security-critical information via means of command-line arguments.

## Certificate creation
Tahini and ScopeLight depend upon certificates that are generated during compilation.
Currently the certificates embed a tree of all dependencies that use Sesame policies, and a hash for each associated policy implementation.
TODO: Critical regions hashes over source code.
Scrutinizer config file.


# Missing from the repository

## Dylints
Dylints for SesameType implementation + no extensions + well-formedness of Tahini codegen.

## End-to-end trusted compilation toolchain.
Requires to atomically compile, run scrutinizer, check dylints, and generate certificates.
