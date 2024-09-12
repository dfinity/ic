Before a release of the PocketIC server, copy the contents below into the CHANGELOG.md in the [PocketIC server repo](https://github.com/dfinity/pocketic/blob/main/CHANGELOG.md)!
=================================================================================================================================================================================
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## Unreleased

### Added
- New CLI option `--ip_addr` to specify the IP address at which the PocketIC server should listen (defaults to `127.0.0.1`).
- New argument `ip_addr` of the endpoint `/http_gateway` to specify the IP address at which the HTTP gateway should listen (defaults to `127.0.0.1`).
- New GET endpoint `/http_gateway` listing all HTTP gateways and their details.
- Support for query statistics in the management canister.
- The argument of the endpoint `/instances/<instance_id>/auto_progress` becomes a struct with an optional field `artificial_delay_ms` specifying the minimum delay between consecutive rounds in auto progress mode.
- Support for verified application subnets: the record types `SubnetConfigSet` and `ExtendedSubnetConfigSet` contain a new field `verified_application` specifying verified application subnets;
  the enumeration type `SubnetKind` has a new variant `VerifiedApplication`.
- New endpoint `/instances/<instance_id>/api/v2/subnet/...` supporting the IC HTTP subnet read state requests.
- New endpoint `/api/v2/subnet` of the PocketIC HTTP gateway supporting the IC HTTP subnet read state requests.
- The argument of the endpoint `/instances/` takes an additional optional field `log_level` specifying the replica log level of the PocketIC instance.
- ECDSA support (IC mainnet-like): there are three ECDSA keys with names `dfx_test_key1`, `test_key_1`, and `key_1` on the II and fiduciary subnet.
- tSchnorr support (IC mainnet-like): there are three Schnorr keys with names `dfx_test_key1`, `test_key_1`, and `key_1` and algorithm BIP340 as well as three Schnorr keys with names `dfx_test_key1`, `test_key_1`, and `key_1` and algorithm Ed25519 on the II and fiduciary subnet. The messages to sign with tSchnorr must be of length 32 bytes.
- New endpoint `/_/dashboard` of the PocketIC HTTP gateway returning the dashboard of the underlying PocketIC instance or replica.
- The argument of the endpoint `/instances/<instance_id>/mock_canister_http_response` takes an additional field `additional_responses` to mock additional responses for a pending canister HTTP outcall;
  if non-empty, the total number of responses (one plus the number of additional responses) must be equal to the size of the subnet on which the canister making the HTTP outcall is deployed.

### Changed
- The argument `listen_at` of the endpoint `/http_gateway` has been renamed to `port`.
- The endpoint `/instances/<instance_id>/auto_progress` returns an error if the corresponding PocketIC instance is already in auto progress mode.

### Removed
- The option `--ready-file`: the PocketIC server is ready to accept HTTP connections once the port file (specified via `--pid` or `--port-file`) contains a line terminated by a newline character.



## 5.0.0 - 2024-07-22

### Added
- A new subnet is created on an existing PocketIC instance if a new canister is created with a specified mainnet canister ID that does not belong to any existing subnet's canister range.
- The argument of the endpoint `/http_gateway` takes an additional optional field `domains` specifying the domains at which the HTTP gateway is listening (default to `localhost`).
- The argument of the endpoint `/http_gateway` takes an additional optional field `https_config` specifying the TLS certificate and key. If provided, then an HTTPS gateway is started using that TLS certificate.
- A new endpoint `/instances/<instance_id>/read/topology` to retrieve the topology of the PocketIC instance. The topology contains a list of node IDs instead of subnet size which can be derived from the number of node IDs.
- New CLI option `--ready-file` to specify a file which is created by the PocketIC server once it is ready to accept HTTP connections.
- A new endpoint `/instances/<instance_id>/_/dashboard` serving a PocketIC dashboard.
- ECDSA support (IC mainnet-like): there are three ECDSA keys with names `dfx_test_key1`, `test_key_1`, and `key_1` on the II subnet.
- The argument of the endpoint `/instances/` to create a new PocketIC instance becomes a struct with three fields:
  the original argument of that endpoint is the field `subnet_config_set`, the new optional field `state_dir`
  specifies a directory in which the state of the PocketIC instance can be preserved across the PocketIC instance lifetime
  (that directory should be empty when specified as `state_dir` for the very first time), and the new optional field `nonmainnet_features`
  specifies if non-mainnet features (e.g., best-effort responses) should be enabled for the PocketIC instance.
  The topology contains a new field `subnet_seed` which is equal to the directory name of the directory in the `state_dir`
  storing the state of the corresponding subnet.
  The state directory (if specified) also contains a file `registry.proto` containing the current snapshot of the registry.
- Support for canister HTTP outcalls: endpoint `/instances/<instance_id>/get_canister_http` to retrieve pending canister HTTP outcalls
  and endpoint `/instances/<instance_id>/mock_canister_http_response` to mock a response for a pending canister HTTP outcall,
  the server produces responses for pending canister HTTP outcalls automatically in the auto-progress mode (started by calling the endpoint `/instances/<instance_id>/auto_progress`).
- New endpoint `/instance/<instance_id>/api/v3/canister/<effective_canister_id>/call` supporting a synchronous HTTP interface of the IC for update calls.
  Note that this endpoint might non-deterministically return a response with status code 202 and empty body (in this case, the status of the call
  must be polled at the endpoint `/instance/<instance_id>/api/v3/canister/<effective_canister_id>/read_state`).
  
### Fixed
- Executing a query call on a new PocketIC instance crashed the PocketIC server.



## 4.0.0 - 2024-04-30

### Added
- New endpoints `/instances/<instance_id>/auto_progress` and `/instances/<instance_id>/stop_progress` to make IC instances
  progress (updating time and executing rounds) automatically.
- New endpoints `/instances/<instance_id>/api/v2/...` supporting the HTTP interface of the IC as described
  by the [Interface Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec).
- Breaking: New subnet specification allowing to set very high instruction limits for (asymptotic) benchmarking canister code.
- New endpoint `/read_graph/:state_label/:op_id` for polling on a long-running operation. The `state_label` and `op_id` are returned by `ApiResponse::Started{state_label, op_id}`.
- New CLI option `--port-file` to specify a file to which the PocketIC server port should be written.
- New endpoints `/http_gateway` and `/http_gateway/:id/stop` to start and stop an HTTP gateway.
- Breaking: DTS is enabled on a subnet based on a new field `dts_flag` in `SubnetSpec`.
- New endpoints `submit_ingress_message` (submit an ingress message without executing it) and `await_ingress_message` (execute rounds on the PocketIc instance until the message is executed).

### Fixed

- Potentially breaking: Subnet IDs are derived from the subnets' public keys by default.
- Potentially breaking: The time of every subnet advances by 1ns before every round execution to make sure the subnet time is strictly increasing in every round.



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
