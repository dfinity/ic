# API Boundary Node Recovery

The NNS is accessed through API boundary nodes, which are themselves managed by the NNS 
-- a circular dependency. If an outage renders the API boundary nodes unusable, we need a 
way to spin up at least one non-NNS-managed API boundary node so that the NNS can be 
accessed to vote on recovery proposals.

This directory contains a Docker setup that packages `ic-boundary` and `ic-registry-replicator` into a single container that can be deployed independently of the production boundary node infrastructure.

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

Test (allow ~3 min for registry sync and replica discovery):

```bash
# HTTP
dfx canister --network http://localhost:8080 call ryjl3-tyaaa-aaaaa-aaaba-cai name --query

# HTTPS
dfx canister --network https://bn.example.com call ryjl3-tyaaa-aaaaa-aaaba-cai name --query
```

## Recovery Playbook

1. Deploy the container on a server with IPv6 access to IC replicas (see Prerequisites).
2. Enable HTTPS (see above).
3. Configure the HTTP gateways: Update the IC_URL to point to this boundary node and disable IC_USE_DISCOVERY, so that the community can reach the NNS through it.
4. Verify NNS access:
   ```bash
   dfx canister --network https://ic0.app call ryjl3-tyaaa-aaaaa-aaaba-cai name --query
   ```
5. Submit and vote on NNS proposals that restore the production API boundary nodes.
6. Once production API boundary nodes are restored, revert the HTTP gateway changes and take down the recovery boundary node:
