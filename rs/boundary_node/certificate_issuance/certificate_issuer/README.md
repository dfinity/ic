# Certificate Issuer

This service runs on the boundary nodes. It handles domain registration requests
from users, processes them and interacts with the `certificate_orchestrator` canister.

The `certificate_issuer` provides two public endpoints, which can be used to
submit registration requests and query the status of these requests:

* `/registrations` (POST): submit a registration requests;
* `/registrations/<id>` (GET): check the status of a submitted request.
* `/registrations/<id>` (PUT): update the canister behind the domain.
* `/registrations/<id>` (DELETE): delete registration (domain-to-canister mapping, certificate and keys).

In addition, it provides a private endpoint for the `certificate_syncer` to obtain
the certificates:

* `/certificates`: obtain all registered domains and their corresponding certificates.

Finally, it provides a metrics endpoint for Prometheus:

* `/metrics`: get metrics for Prometheus.

The `certificate_issuer` expects a delegation domain, which is managed through
Cloudflare and is used for the [DNS-01 challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge). It uses Let's Encrypt as
certificate authority.

## Usage

The following three files are used to setup and start the service on the boundary node:

* [setup-certificate-issuer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/setup-certificate-issuer.service)
* [setup-certificate-issuer.sh](../../../ic-os/components/boundary-guestos/opt/ic/bin/setup-certificate-issuer.sh)
* [certificate-issuer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/certificate-issuer.service)

The `/registration` endpoint needs to be publicly accessible. To this end, the
`nginx` configuration needs to expose and endpoint, which is routed to the certificate issuer.

## Changelog

### 0.1.1

* Use `ic-agent` to perform the check for the `.well-known/ic-domains` file
  instead of making a http request to the canister.
