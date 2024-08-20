# Certificate Issuance

This directory contains all the necessary code to host custom domains on the
boundary nodes. This includes allowing users to register their domain with the
boundary node, obtaining the corresponding certificates, and serving traffic
for these domains.

In the following, we first provide a [high-level overview of the design](#design-overview). Then, we
explain the [structure of this directory](#directory-organization) and the different components required to host custom domains on the boundary nodes. Finally, we explain all the [steps](#running-the-certificate-issuance-service) necessary to set up and run the custom domains service on the boundary nodes.

## Design Overview

We can split the custom domains design into two parts: [first](#registering-custom-domains), the part that
is required to allow users to register their domains, obtain the certificates,
and distribute them among all boundary nodes; and [second](#serving-traffic), the part that is
required to allow the boundary nodes to serve traffic for all the registered
custom domains.

The design relies both on services running on the boundary nodes, as well as on a
canister running on the Internet Computer. The services on the boundary nodes
handle the registration requests and process them, while the canister coordinates
the work among the boundary nodes and distributes all the required information.

### Registering Custom Domains

At a high-level, a user configures the DNS record of their domains to route all traffic
to the boundary nodes. Then, they notify the boundary nodes to start the registration process.
The boundary nodes perform a few checks to ensure everything has been properly
set up by the user and will then request a certificate.

The `certificate-issuer` service runs on all boundary nodes. It has a public
endpoint that allows users to register a custom domain, check the status
of the registration request, update an existing registration and remove a
registration. Whenever the service receives a new request, it first
checks that the DNS entries of the domain have been properly configured:

1. The traffic is redirected to the boundary nodes using a `CNAME` to the boundary nodes' application domain (e.g., ic0.app).
2. The ID of the canister to which the domain should be mapped is specified in a `TXT` record at the `_canister-id`-subdomain of the custom domain.
3. The DNS-01 ACME-challenge is redirected to the delegation domain used by the boundary nodes using a `CNAME` for the `_acme-challenge`-subdomain of the custom domain.

In addition, the boundary node also checks that the owner of the domain actually
controls the canister by checking for the existence of a file containing the custom domain
under `/.well-known/ic-domains` inside the canister.

If any of the checks fail, the boundary node will reject the request with an
appropriate error (e.g., "missing dns cname").

If all the checks pass, the boundary node will submit the registration request
to the `certificate-orchestrator`, which is a canister running on the Internet Computer.
This canister keeps track of all the registration requests and their status, and
coordinates the work among the `certificate-issuers` running on the boundary
nodes. 

The `certificate-orchestrator` also applies a rate-limit on new registrations to 
prevent an attacker from exhausting the rate-limit with the ACME provider.
The rate-limit is applied per apex domain (e.g., the apex domain of `example.com` and
`www.example.com` is for both domains `example.com`). The rate-limit is currently
set to 5 registration requests per hour and apex domain.

The `certificate-issuers` periodically check if there are tasks available on the
boundary nodes and process them in order to obtain the certificates. Each
registration request is processed in three phases: the _order_, the _ready_, and the _certificate_ phase.

In the _order_ phase, the `certificate-issuer` creates an order with Let's Encrypt,
our certificate authority and ACME provider. We rely on the [`DNS-01` challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
in combination with [domain delegation](https://www.eff.org/deeplinks/2018/02/technical-deep-dive-securing-automation-acme-dns-challenge-validation).
Let's encrypt provides the `certificate-issuer` with a token that needs to be set
in a `TXT` record in the delegation domain. We use Cloudflare as DNS provider for
the delegation domain. Once the `certificate-issuer` is done, it informs the
`certificate-orchestrator`, which schedules a task for the next phase, the _ready_ phase.

In the _ready_ phase, the `certificate-issuer` first checks that the `TXT` record
has been set and propagated. It then informs Let's Encrypt that the challenge is
ready and can be checked. It then informs the `certificate-orchestrator`, which
schedules a task for the next phase.

In the _certificate_ phase, the `certificate-issuer` finalizes the order and
obtains the certificate from Let's Encrypt. It removes the `TXT` record used for
the challenge and uploads the certificate and corresponding private key to the
`certificate-orchestrator`. Before it uploads the data, it encrypts it using a
symmetric key, which is shared among all the boundary nodes.

### Serving Traffic

In order for the boundary nodes to serve the custom domains, the domains need to
be added to the `nginx` configuration and `nginx` needs to have access to the
certificates and corresponding keys.

The `certificate-issuer` running on the boundary nodes periodically retrieves
all certificates and keys from the `certificate-orchestrator`, and keeps a local
copy.

The `certificate-syncer` is a service running on the boundary nodes, which obtains
the certificates and keys from the `certificate-issuer`, and updates the `nginx`
configuration to include all registered custom domains.

## Directory Organization

This directory contains all the code related to custom domains with the exception
of the [`nginx` configuration](../../../ic-os/components/boundary-guestos/etc/nginx/):

- [`certificate_issuer`](certificate_issuer/) contains the boundary node service, which handles all registration requests, processes registration tasks and interfaces with the `certificate-orchestrator`.
- [`certificate_syncer`](certificate_syncer/) contains the boundary node service, which ensures that `nginx` has access to all certificates and keys, and is configured to serve the custom domains.
- [`certificate_orchestrator`](certificate_orchestrator/) contains the orchestration canister, which runs on the Internet Computer and coordinates the work among the boundary nodes.
- [`certificate_orchestrator_interface`](certificate_orchestrator_interface/) contains the interface used between the `certificate-issuer` and the `certificate-orchestrator`.
- [`create_acme_account`](create_acme_account/) contains helper code to setup an account with Let's Encrypt.

## Running the Certificate Issuance Service

In the following, we go through all the steps necessary to provide custom domains
on a boundary node. First, we explain all the preparatory steps that need to be
done once. Then, we explain all the steps necessary to deploy the `certificate-orchestrator`
canister on the Internet Computer. Finally, we explain the steps necessary to
run the `certificate-issuer` and `certificate-syncer` on the boundary nodes.

### Preparation

#### **Create an account with Let's Encrypt**

Run `create_acme_account` to create an account with Let's Encrypt.

```sh
cd ic/rs/boundary_node/certificate_issuance/create_acme_account/
cargo run -- --contact <your email address>
```

After running it, you should obtain an output similar to this:

```sh
{
  "id": "https://acme-v02.api.letsencrypt.org/acme/acct/<LETSENCRYPT_ACCOUNT_ID>",
  "key_pkcs8": "<LETSENCRYPT_ACCOUNT_KEY>",
  "urls": {
    "newNonce": "https://acme-v02.api.letsencrypt.org/acme/new-nonce",
    "newAccount": "https://acme-v02.api.letsencrypt.org/acme/new-acct",
    "newOrder": "https://acme-v02.api.letsencrypt.org/acme/new-order"
  }
}
```

Take a note of your account ID and account key, as it is needed to run the `certificate_issuer`.

#### **Generate a Symmetric Key to Encrypt Certificates and Keys**

```sh
cd ic/rs/boundary_node/certificate_issuance/certificate_issuer/
cargo run --bin generate-key -- --key-path <PATH>
```

Keep the generated key in a secure place.

#### **Cloudflare managed Delegation Domain for DNS-01 Challenge**

To use the [DNS-01 challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) for Let's Encrypt,
you need a dedicated delegation domain, which is managed through Cloudflare.

The `certificate-issuer` needs a Cloudflare API key for that delegation domain.
We recommend limiting the access of the API key to the delegation domain only
(i.e., manage only that zone).

#### **Generate Identities for Boundary Nodes to Access the Orchestration Canister**

Access to the `certificate-orchestrator` is granted based on allowlisted identities.
To this end, you need to create at least one identity, which is shared among all
boundary nodes or create one identity per boundary node.

An identity consists of the private key, which has to be provided to the `certificate-issuer`,
and a principal, which needs to be allowlisted on the `certificate-orchestrator` canister.

To create the identities you can use [`dfx`](https://internetcomputer.org/docs/current/references/cli-reference/):

```sh
dfx identity new --disable-encryption <BN_IDENTITY_NAME>
```

To export the private key, you can use the following command and store the output
in a `.pem` file:

```sh
dfx identity export <BN_IDENTITY_NAME>
-----BEGIN EC PRIVATE KEY-----
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END EC PRIVATE KEY-----
```

To obtain the principal linked to the private key, you can use the following commands
and take note of the output.

```sh
dfx identity use <BN_IDENTITY_NAME>
dfx identity get-principal
aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-aaa
```

### Deploy Orchestration Canister

The `certificate-orchestrator` canister
coordinates the work on the boundary nodes and distributes the certificates. To
offer the custom domain service, you first need to deploy such a canister to the
Internet Computer.

#### **Root Identity and Wallet**

Before deploying the canister, ensure you have an identity with an associated wallet
that can act as a controller for the canister.

If you need to create one, follow the steps outlined [here](https://internetcomputer.org/docs/current/developer-docs/quickstart/network-quickstart).

From now on, we refer to the identity as `ROOT_IDENTITY` and to the corresponding principal
as `ROOT_PRINCIPAL`.

#### **Deploy the `certificate_orchestrator` Canister**

The orchestration canister requires two arguments at deployment:

- `rootPrincipals`: a list of identities that will get root access to the canister. This allows those identities to edit permissions on the canister. You can use the identity used to deploy the canister or a separate one. We do not recommend using an identity, which is used for the boundary nodes.
- `idSeed`: a natural number, used in ID generation to make it harder to predict and enumerate IDs.

```sh
cd ic/rs/boundary_node/certificate_issuance/certificate_orchestrator/
dfx deploy \
    --identity <ROOT_IDENTITY> \
    --network ic \
    --argument "(
        record {
            rootPrincipals = vec {
                principal \"<ROOT_PRINCIPAL>\";
            };
            idSeed = <ID_SEED>;
        }
    )" \
    certificate_orchestrator
```

_Important:_ Make sure to use a random, large enough value for the `ID_SEED`. The
value is an unsigned 128bit integer. You can use the following command, to generate
such a value:

```sh
od -N 16 -t uL -An /dev/urandom | tr -d " "
```

Take note of the canister ID of the deployed `certificate-orchestrator`. In
the following, we refer to it as `CANISTER_ID`.

#### **Allowlisting of the Boundary Node Identities**

Once the canister is deployed, you can allowlist the identities used by the
boundary nodes such that they can interact with the canister, obtain tasks,
and upload certificates and keys.

In this step, you need the principals of the boundary node identities that you
generated in the [previous step](#generate-identities-for-boundary-nodes-to-access-the-orchestration-canister).

To allowlist an identity, you can add its principal to the canister:

```sh
cd ic/rs/boundary_node/certificate_issuance/certificate_orchestrator/
dfx canister call --network ic --identity <ROOT_IDENTITY> --candid interface.did <CANISTER_ID> addAllowedPrincipal "(principal \"<BN_PRINCIPAL>\")"
```

To remove an identity from the allowlist, use:

```sh
cd ic/rs/boundary_node/certificate_issuance/certificate_orchestrator/
dfx canister call --network ic --identity <ROOT_IDENTITY> --candid interface.did <CANISTER_ID> rmAllowedPrincipal "(principal \"<BN_PRINCIPAL>\")"
```

And to list all principals, which are currently on the allowlist, use:

```sh
cd ic/rs/boundary_node/certificate_issuance/certificate_orchestrator/
dfx canister call --network ic --identity <ROOT_IDENTITY> --candid interface.did <CANISTER_ID> listAllowedPrincipals "()"
```

### Prepare BN Services

In order to run the `certificate-issuer` and `certificate-syncer` on a
boundary node, you need to provide it with the proper configuration through the
virtual USB-stick.

The virtual USB-stick can be built using the [`build-deployment.sh` script](../../../ic-os/boundary-guestos/scripts/build-deployment.sh).
It has three arguments related to custom domains:

* `cert-issuer-creds`: a configuration file. Its contents are explained below;
* `cert-issuer-identity`: the identity file belonging to an allowlisted identity (see the [previous step](#generate-identities-for-boundary-nodes-to-access-the-orchestration-canister));
* `cert-issuer-enc-key`: the symmetric encryption key generated in a [previous step](#generate-symmetric-key-certificate-issuerbin-to-encrypt-certificates-and-keys).

The `cert-issuer-creds` file needs to have the following content:
```
certificate_orchestrator_uri=<BN_APPLICATION_DOMAIN>
certificate_orchestrator_canister_id=<CANISTER_ID>
certificate_issuer_delegation_domain=<DELEGATION_DOMAIN>
certificate_issuer_application_domain=<BN_APPLICATION_DOMAIN>
certificate_issuer_acme_id=<LETSENCRYPT_ACCOUNT_ID>
certificate_issuer_acme_key=<LETSENCRYPT_ACCOUNT_KEY>
certificate_issuer_cloudflare_api_key=<CLOUDFLARE_API_KEY>
```

When you deploy a boundary node with these configurations, the two services
automatically start.

The `certificate-issuer` relies on the following services and setup scripts:
* [setup-certificate-issuer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/setup-certificate-issuer.service)
* [setup-certificate-issuer.sh](../../../ic-os/components/boundary-guestos/opt/ic/bin/setup-certificate-issuer.sh)
* [certificate-issuer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/certificate-issuer.service)

The `certificate-syncer` relies on the following services and setup scripts:
* [setup-certificate-syncer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/setup-certificate-syncer.service)
* [setup-certificate-syncer.sh](../../../ic-os/components/boundary-guestos/opt/ic/bin/setup-certificate-syncer.sh)
* [certificate-syncer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/certificate-syncer.service)

In addition, the `certificate-syncer` needs a [configuration template](/ic-os/components/boundary-guestos/etc/certificate-syncer/domain.tmpl) to dynamically include all
custom domains in the `nginx` configuration. It is part of the boundary node
root filesystem and is maintained along with this codebase.
