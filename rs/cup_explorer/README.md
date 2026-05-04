# CUP Explorer & Verifier

A command-line tool for exploring and verifying Catch-Up Packages (CUPs) of the Internet Computer Protocol (ICP).

## Overview

This tool provides utilities for interacting with Catch-Up Packages (CUPs) on subnets of the Internet Computer. CUPs are special artifacts that are created and signed by a subnet in periodic intervals (i.e. once every 500 blocks). Each CUP (via its state hash) corresponds to a specific state checkpoint of the subnet. 

The tool supports two main functionalities:

- **Exploring** the latest CUP of a subnet,
- **Verifying** the integrity and signature of a locally stored CUP, and determining whether the subnet was halted on the given CUP.

In particular, this tool can be used to verify whether a given Catch-Up Package represents the most recent state of a subnet that was intentionally halted via a governance proposal (e.g., during a key resharing maintenance). This is done by checking that the CUP references a registry version that explicitly instructs the subnet to halt at the next CUP height. If the verification succeeds, it provides the necessary parameters that should be included in a recovery proposal to safely restart the subnet, without making changes to the subnet state. Specifically, these parameters are:
1. The `TIME` at which the CUP was created
2. The block `HEIGHT` of the CUP
3. The `STATE HASH` of the corresponding state checkpoint

A subsequent recovery proposal to restart the subnet should contain a `TIME` and `HEIGHT` that are *greater* than in the given latest CUP. The proposed `STATE HASH` should be *equal*, meaning that the subnet will be restarted on the same state that it was halted on.

## Usage

By default, the tool uses `https://ic0.app` and the mainnet public key as the NNS registry entrypoint. This can be overridden using the `--nns-url` and `--nns-pem` options:

```bash
bazel run rs/cup_explorer:cup_explorer_bin -- --nns-url http://[<NNS_NODE_IP>]:8080 --nns-pem /path/to/nns_public_key.pem <subcommand> ...
```

Run the binary with one of the available subcommands:

### Explore

Fetch and optionally persist the most recent CUPs of all nodes on a given subnet (requires IC network access).

```bash
bazel run rs/cup_explorer:cup_explorer_bin -- explore --subnet-id <SUBNET_ID> [--download-path <PATH>]
```

- `--subnet-id`: The target subnet to inspect (required).
- `--download-path`: If specified, saves the latest CUP to the given path.

### Verify CUP of halted subnet

Verify a CUP file's integrity and threshold signature, and check if the subnet was halted at that height.

```bash
bazel run rs/cup_explorer:cup_explorer_bin -- verify-cup-of-halted-subnet --cup-path <CUP_FILE>
```

- `--cup-path`: Path to a local CUP protobuf file (required).

The tool will:
- Decode and validate the CUP contents.
- Verify the combined threshold signature against the subnet public key in registry.
- Confirm the subnet was configured to halt at the CUP’s height.
- Check if the subnet was recovered with the correct parameters.

## Example Output

Executed command:
```bash
bazel run rs/cup_explorer:cup_explorer_bin -- verify --cup-path /path/to/cup.pb
```
- `/path/to/cup.pb`: A Catch-Up Package file that was published during a subnet maintenance

Output:
```
[..]
Reading CUP file at "/path/to/cup.pb"
CUP integrity verified!

Checking CUP signature for subnet fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae...
Getting registry value of key catch_up_package_contents_fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae at version 50690...
CUP signature verification successful!

Latest subnet state according to CUP:
                TIME: 1748271343192946614, (2025-05-26 14:55:43.192946614 UTC)
              HEIGHT: 143603500
                HASH: c214b0175f2348a28a0bb9b63b46d9502cec8071974a370559edbb7ab481b569
    REGISTRY VERSION: 50690

Verifying that the subnet was halted on this CUP...
Getting registry value of key subnet_record_fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae at version 50690...

Confirmed that subnet fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae was halted on this CUP as of 2025-05-26 14:55:43.192946614 UTC.
This means that the CUP represents the latest state of the subnet while the subnet remains halted.
The subnet may ONLY be restarted via a recovery proposal using the same state hash as listed above.

Searching for a recovery proposal...
The subnet has not been recovered yet.
A recovery proposal should specify a time and height that is greater than the time and height of the CUP above.
Additionally, the proposed state hash should be equal to the one in the provided CUP, to ensure there were no modifications to the state.
```
