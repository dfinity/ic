## Purpose
This README file documents how to (re-)generate DFINITY DEV environment root CA and key files, as
well as where to apply these files and when to apply these files to make use of them.

## How to (re-)generate new root CA and signing key
`cd dev-certs`
`sh root_cert_gen.sh`

## How to apply root CA and signing key to VMs
### VM as HTTPS client
Copy `minica.pem` to `/usr/local/share/ca-certificates/` folder of Linux VM, and run: 
`sudo update-ca-certificates` command. This adds the newly-generated root certificate 
to the `ca-certificates.crt` bundle file sitting under `/etc/ssl/certs` folder, where
processes running on the VM will be able to treat `/etc/ssl/certs` directory as trusted CAs.

IC-OS reads `dev-certs/` to update its `/etc/ssl/certs/ca-certificates.crt`
bundle in: `/ic-os/guestos/context/Dockerfile`

### VM as HTTPS server
In the folder where you have `minica.pem` and `minica-key.pem`, generate service 
certificate from the root certificate:

`docker run -it -v "$(pwd)"/:/etc/nginx/certs ryantk/minica --domains {you_domain_name}`

Initiate your service with SSL using the newly generated certificate. Your service should
start with new certificate for its representation, allowing the HTTPS client with same CA
injected (as described above) to validate.

As a detailed example, check: `/rs/tests/src/canister_http/universal_vm_activation.sh`

Note: 
The `Universal VM` currently uses the above mentioned root certificate during activation,
as can be noticed here: `/rs/tests/src/driver/universal_vm.rs`, `single_activate_script_config_dir()`
function. 
