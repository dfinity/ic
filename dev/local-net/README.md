# ic-local-net

A self-contained way to run a real **4-node Internet Computer subnet** locally
on Apple Silicon (and Linux), purpose-built for hacking on the IC's
**network and consensus layers**.

Replicas are the unmodified `ic-replica` binary from this repo, built for
`x86_64-linux` and run in Docker containers via Rosetta 2. Each node is its
own container with its own IPv6 address and its own state; the four together
run real BFT consensus over a real QUIC P2P transport.

## Quick start

Prerequisites: OrbStack (or Docker Desktop) with Rosetta enabled; dfx
(optional, only for deploying canisters); and a VPN connection to DFINITY's
internal network (for the bazel-remote cache — without it the first build
is much slower).

```sh
cd dev/local-net          # from the IC repo root
./build.sh                # ~5-10 min first time, cached after
./prep.sh                 # generate registry, crypto, configs    (<5s)
docker compose up -d      # start the 4 replicas                  (~10s)
./verify.sh               # smoke test
```

After this, `dfx ping http://localhost:8080` works and the network is
deploy-ready. See [DEPLOY.md](./DEPLOY.md) for the dfx setup.

## What you get

| | |
|---|---|
| **Topology** | 1 subnet, 4 nodes, ULA IPv6 bridge `fd00:1::/64` |
| **Node addresses** | `fd00:1::10` through `fd00:1::13` |
| **Ports per node** | 4100 (P2P), 8080 (HTTP API), 9090 (metrics) |
| **Host-published** | `localhost:8080` (API) and `:9090` (metrics) → node-0 only |
| **Consensus** | real BFT, ~10 blocks/sec at idle |
| **State** | per-node named Docker volumes; survives container restarts |
| **Resource use** | ~2 GiB RAM, modest CPU when idle |

What this network **is**:
- A real 4-node IC subnet, wire-compatible with mainnet for the public spec.
- Suitable for testing changes to `rs/p2p/`, `rs/consensus/`, `rs/state_manager/`,
  ingress handling, transport, etc.

What it **isn't** (yet):
- NNS-enabled. Registry / Governance / Ledger canisters are not installed.
  Anything requiring them (`dfx wallet`, `dfx ledger`, `ic-admin get-topology`)
  will report `Canister rwlgt-... not found`.
- Multi-subnet. Single subnet, single canister-ID range.
- A faithful production deployment shape. There is no HostOS / SetupOS /
  orchestrator layer; replicas are plain Linux processes.

## The scripts

| Script | Purpose | Typical time |
|---|---|---|
| `build.sh` | Cold build of all binaries via the official `ic-build` image | 5–10 min first, ~1 min incr |
| `prep.sh` | Run `ic-prep`, generate per-node `ic.json5`, lay out `bootstrap/` | <5s |
| `verify.sh` | Smoke-test the running network (status + dfx ping + per-node health) | <5s |
| `iter.sh [services] [--tail]` | bazel build → restart → wait healthy. **Fast dev loop.** | 20s warm |
| `reset.sh` | Down `-v`, regen prep, fresh up. Use for genesis from height 0. | ~15s |
| `logs.sh [pattern]` | `docker compose logs -f` with optional grep filter | streaming |
| `clean.sh [--all]` | Tear down compose + builder; `--all` also wipes `bootstrap/`, `out/`, `cache/` | <5s |

## Dev loop

The expected workflow once you're set up:

```sh
$ vim rs/consensus/...                  # edit
$ ./iter.sh --tail                      # rebuild + restart + tail logs
==> bazel build  (//rs/replica:replica)
    (bazel: 22s)
==> docker compose restart  (all 4 replicas)
==> waiting for replicas to be healthy
    4/4 replicas healthy
    (total iter: 35s)
==> docker compose logs -f --tail=10
...
```

`iter.sh` keeps a persistent `ic-builder` container running with the bazel
JVM warm, and the freshly-built binaries are picked up by the replicas via a
bind mount over `/usr/local/bin/`. Subsequent iterations after a small edit
typically run in 20–40s.

For a specific subset of nodes:

```sh
$ ./iter.sh replica-0                   # restart only node-0 (test rolling upgrade)
```

For a different bazel target:

```sh
$ TARGETS="//rs/canister_sandbox:canister_sandbox" ./iter.sh
```

## Architecture

```
                       Host (macOS / Apple Silicon)
   ┌──────────────────────────────────────────────────────────────┐
   │                                                              │
   │  ./out/  ./bootstrap/  ./cache/    OrbStack VM (linux/amd64) │
   │     │       │             │       ┌─────────────────────┐    │
   │     │       │             │       │  ic-builder (sleep) │    │
   │     │       │             └───────│  warm bazel server  │    │
   │     │       │                     └─────────────────────┘    │
   │     │       │                                                │
   │     │       │  ┌──── docker network ic-local (fd00:1::/64) ──┐│
   │     │       │  │                                             ││
   │     ▼       ▼  ▼                                             ││
   │  ┌─────────────────┐  ┌─────────────────┐                    ││
   │  │ ic-replica-0    │  │ ic-replica-1    │                    ││
   │  │ fd00:1::10      │◀─┤ fd00:1::11      │                    ││
   │  │ port 8080 ──┐   │  │                 │                    ││
   │  └─────────────│───┘  └─────────────────┘                    ││
   │                │                                             ││
   │  ┌─────────────────┐  ┌─────────────────┐                    ││
   │  │ ic-replica-2    │◀─┤ ic-replica-3    │                    ││
   │  │ fd00:1::12      │  │ fd00:1::13      │                    ││
   │  └─────────────────┘  └─────────────────┘                    ││
   │  ◀── BFT consensus over QUIC transport ────▶                 ││
   │                                              ┌──────────────┐││
   │  host:8080 ◀────────────────────────────────▶│ API (node-0) │││
   │  host:9090 ◀────────────────────────────────▶│ metrics      │││
   │                                              └──────────────┘││
   │                                                              ││
   └──────────────────────────────────────────────────────────────┘│
                                                                   │
   dfx ──── http://localhost:8080  ──────────────────────────────▶
```

Each replica container mounts:

- `./out/` → `/usr/local/bin/` (read-only, the binaries; this is what `iter.sh` swaps)
- `./bootstrap/ic_registry_local_store/` → `/etc/ic/registry/` (read-only, the registry blob)
- `./bootstrap/node-N/crypto/` → `/etc/ic/crypto/` (writable; replica rotates NI-DKG keys)
- `./bootstrap/node-N/ic.json5` → `/etc/ic/ic.json5` (read-only, replica config)
- `state-N` Docker volume → `/var/lib/ic/` (writable, consensus pool + state + backups)

## Troubleshooting

**`docker compose up` immediately exits / restarts**
Check `docker compose logs replica-0`. The replica is strict about its
config: missing fields in `ic.json5` produce `Failed to parse config from
file ... missing field 'X'`. If you've edited `prep.sh`, regenerate with
`./reset.sh`.

**`Error: cannot use a wallet before dfx start` when deploying**
Pass `--no-wallet` to `dfx canister create`. See DEPLOY.md.

**`Canister rwlgt-iiaaa-aaaaa-aaaaa-cai not found` from `ic-admin`**
That's the NNS Registry canister, which isn't installed. Use commands that
don't require the NNS Registry — e.g. operate on the local-store directly,
or install the NNS canisters (out of scope for now).

**Bazel build fails with `RegistryUnreachable` or `No route to host`**
The bazel-remote cache and downloader live on DFINITY's internal network.
Connect to the VPN, or fall back to `bazel build --config=local` (slow first
build).

**Replica panics with `Read-only file system` on crypto**
The crypto mount must be read-write — the replica rotates forward-secure
NI-DKG keys at runtime. If you modified `compose.yml`, check that the
`/etc/ic/crypto` mount does **not** have the `:ro` suffix.

**iter.sh is slow on first run**
The first iter spins up the persistent builder and starts a fresh bazel
server, which takes ~3-4 min. Subsequent iters reuse both and run in ~20s.

## Background

For the design rationale (why x86_64 Linux replicas in Rosetta containers
rather than GuestOS VMs, aarch64-linux builds, or other variants), see the
chat thread that produced this setup. Short version: this is the fastest
edit-rebuild-observe loop available for IC consensus/P2P work, while still
running real protocol code on a real multi-node BFT network.
