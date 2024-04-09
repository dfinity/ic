Before a release of the PocketIC server, copy the contents below into the CHANGELOG.md in the [PocketIC server repo](https://github.com/dfinity/pocketic/blob/main/CHANGELOG.md)!
=================================================================================================================================================================================
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## Unreleased

### Added
- New endpoints `/instances/<instance_id>/auto_progress` and `/instances/<instance_id>/stop_progress` to make IC instances
  progress (updating time and executing rounds) automatically.
- New endpoints `/instances/<instance_id>/api/v2/...` supporting the HTTP interface of the IC as described
  by the [Interface Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec).
- New subnet specification allowing to set very high instruction limits for (asymptotic) benchmarking canister code.
- New endpoint `/read_graph/:state_label/:op_id` for polling on a long-running operation. The state_label and op_id are returned by `ApiResponse::Started{state_label, op_id}`. 
- New CLI option `--port-file` to specify a file to which the PocketIC server port should be written.
- New endpoints `/http_gateway` and `/http_gateway/:id/stop` to start and stop an HTTP gateway.
- DTS is enabled on a subnet based on a new field `dts_flag` in `SubnetSpec`.

### Fixed

- Subnet IDs are derived from the subnets' public keys by default.
- The time of every subnet advances by 1ns before every round execution to make sure the subnet time is strictly increasing in every round.


## 3.0.1 - 2024-02-14

### Fixed
- Traps in tECDSA calls due to malformed tECDSA public key.
- Server rejects jsons containing unimplemented variants of `SubnetStateConfig`.
- The `inspect_message` method no longer panics when call is rejected.

## 3.0.0 - 2024-02-06

### Added
- New endpoint `/api.json` that serves an OpenAPI documentation of the PocketIC server.
- Instances can be created from existing NNS state.

### Changed
- Breaking: The create_instance endpoint accepts an ExtendedSubnetConfigSet, which allows more options. 

### Fixed
- Canister inspect message errors when executing ingress messages are returned as canister execution results rather than request errors.
- Subnets agree on which subnet id is the NNS subnet id. Fixes the problem where a canister installation via CMC directly would fail. 


## 2.0.1 - 2023-11-23

### Fixed
- Fixed a bug where `get_subnet()` would return results for non-existent canisters, causing `canister_exists()` to return `true` for non-existent canisters in client libraries
- Fixed a bug related to `PocketIc`s internal time being set to the current time, which lead to non-deterministic behavior


### Changed
- Cycles consumption is now more appropriately scaled according to the size of the subnet



## 2.0.0 - 2023-11-21

### Added
- Support for multiple subnets
- Support for cross-subnet canister calls
- Improved support to start the PocketIC server from the command line:
    - Ability to start the server without any flags
    - Use `-p or --port` to specify a port where the server should listen
    - Use `--ttl` to specify for how long the server should be running before it shuts down
    - `--pid` flag is no longer required and discouraged to use from the command line
- Improved logging support:
    - Use the `POCKET_IC_LOG_DIR` environment varible to specify where to store logs
    - Use the environment variable `POCKET_IC_LOG_DIR_LEVELS=trace` to specify the log level of the logs that are written to the log file
- `read/pub_key` endpoint to retrieve the public key of a subnet
- `read/get_subnet` endpoint to retrieve the subnet id of a canister

### Changed
- POST `instances/` endpoint requires a subnet config 
- POST `instances/` endpoint returns a toplogy of the instance
- `/read/query` and `/update/execute_ingress_message` require an `effective_principal` field

### Removed
- Checkpointing
- `read/canister_exists` endpoint (superseded by `read/get_subnet`)
- `read/root_key` endpoint (superseded by `read/pub_key`)



## 1.0.0 - 2023-10-12

### Added
- Blocking REST-API: Encode IC-call in endpoint, not in body



## 0.1.0 - 2023-08-31

### Added
- Blocking API to make IC-calls to a PocketIC server
