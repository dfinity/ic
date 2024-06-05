# Certificate Syncer

This service runs on the boundary nodes to ensure that `nginx` can serve custom domains
by adding the domains to its configuration and making certificates and corresponding keys
available.

The `certificate-syncer` obtains the custom domains, their certificates and keys
from the `certificate-issuer` service, which is also running on the boundary nodes.

## Usage

The following three files are used to setup and start the service on the boundary node:

* [setup-certificate-syncer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/setup-certificate-syncer.service)
* [setup-certificate-syncer.sh](../../../ic-os/components/boundary-guestos/opt/ic/bin/setup-certificate-syncer.sh)
* [certificate-syncer.service](../../../ic-os/components/boundary-guestos/etc/systemd/system/certificate-syncer.service)
