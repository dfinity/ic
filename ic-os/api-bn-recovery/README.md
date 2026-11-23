# API Boundary Node Recovery

The NNS is accessed through API boundary nodes, which are themselves managed by the NNS 
-- a circular dependency. If an outage renders the API boundary nodes unusable, we need a 
way to spin up at least one API boundary node that is not NNS-managed such that the community 
can access the NNS and vote on the proposals that should recover the access through the API boundary nodes.

This directory contains a Docker setup that packages `ic-boundary` and `ic-registry-replicator` 
into a single container that can be deployed independently of the production boundary node infrastructure.

Follow the API Boundary Node Disaster Recovery Runbook doc to complete a production recovery.

## Prerequisites

In order to reach mainnet, the server running this container must have an IPv6 address in 
the set of allowlisted prefixes in the registry firewall rules.

## Usage

Build the Docker image:

```bash
./build.sh
```

To run in HTTP-only mode (for local testing):

```bash
docker run -d --name api-bn --network host api-boundary-node:latest
```

To run with HTTPS via Let's Encrypt (for production / public access):

1. Point a DNS record (e.g., `recovery.boundary.dfinity.network`) to your server's public IP.
2. Ensure port 443 is open on the server's firewall.
3. Run with `TLS_HOSTNAME` set:

```bash
docker run -d --rm --name api-bn \
  --network host \
  -e TLS_HOSTNAME=recovery.boundary.dfinity.network \
  -v acme-data:/data/acme \
  api-boundary-node:latest
```

Test (allow ~3 min for registry sync and replica discovery). From a checkout of this repository,
query `name` on the ICP ledger through the boundary node. The tool verifies the reply's node
signatures against the IC mainnet root key compiled into it, and checks that the boundary node's
`/api/v2/status` serves that same key, so it only works against mainnet:

```bash
# HTTP
bazel run //rs/boundary_node/smoke_test:ic-boundary-smoke-test -- --url http://localhost:8080

# HTTPS
bazel run //rs/boundary_node/smoke_test:ic-boundary-smoke-test -- --url https://recovery.boundary.dfinity.network
```
