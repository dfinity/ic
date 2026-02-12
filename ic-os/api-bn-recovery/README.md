# API Boundary Node Recovery

The NNS is accessed through API boundary nodes, which are themselves managed by the NNS -- a circular dependency. If an outage renders the API boundary nodes unusable, we need a way to spin up at least one non-NNS-managed API boundary node so that we and the community can access the NNS and vote on recovery proposals.

This directory contains a Docker setup that packages `ic-boundary` and `ic-registry-replicator` into a single container that can be deployed independently of the production boundary node infrastructure.

## Quick Start

```bash
./build.sh

# Run (HTTP only, for testing)
docker run -d --name api-bn --network host api-boundary-node:latest

# Test (allow ~3 min for registry sync and replica discovery)
dfx canister --network http://localhost:8080 call ryjl3-tyaaa-aaaaa-aaaba-cai name --query
```

## HTTPS with Let's Encrypt

To make the boundary node publicly accessible with automatic TLS:

1. Point a DNS record (e.g., `bn.example.com`) to your server's public IP.
2. Ensure port 443 is open on the server's firewall.
3. Run with `TLS_HOSTNAME` set:

```bash
docker run -d --rm --name api-bn \
  --network host \
  -e TLS_HOSTNAME=bn.example.com \
  -v acme-data:/data/acme \
  api-boundary-node:latest
```

The `-v acme-data:/data/acme` volume persists the Let's Encrypt account and certificates across container restarts so they don't need to be re-issued each time.

Test via:

```bash
dfx canister --network https://bn.example.com call ryjl3-tyaaa-aaaaa-aaaba-cai name --query
```

## Recovery Playbook

1. Deploy the container on a server with IPv6 access to IC replicas (see Prerequisites).
2. Enable HTTPS (see above).
3. Update the HTTP gateways to point to this boundary node, so that the community can reach the NNS through it.
4. Verify NNS access:
   ```bash
   dfx canister --network https://ic0.app call ryjl3-tyaaa-aaaaa-aaaba-cai name --query
   ```
5. Submit and vote on NNS proposals that restore the production API boundary nodes.
6. Once production API boundary nodes are restored, revert the HTTP gateway changes and take down the recovery boundary node:

## Prerequisites

- The host machine must have **IPv6 connectivity** to IC replica nodes.
  Replica firewalls only accept connections from allowlisted IPv6 prefixes.
  These include:
  - Prefixes of nodes that have joined the network.
  - A set of hardcoded DFINITY data center prefixes
    (see `ic-os/components/networking/nftables/hostos/nftables.template`, the `dfinity_dcs` set).

  In practice, this means the server running this container must be in one of
  those DFINITY data centers, (or on a network whose prefix has been added to
  the registry firewall rules).
