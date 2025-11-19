# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- The function `PocketIcBuilder::with_initial_time` to specify the initial timestamp of the newly created PocketIC instance.
- The parameter `ttl` to `StartServerParams` to specify the TTL of the PocketIC server.
- The constant `LATEST_SERVER_VERSION` to facilitate downloading the PocketIC server.
- The function `PocketIcBuilder::with_dogecoind_addrs` to specify a list of addresses at which a `dogecoind` process is listening
  for Dogecoin support in PocketIC.

### Changed
- Deprecated `PocketIcBuilder::with_initial_timestamp`, use `PocketIcBuilder::with_initial_time` instead.
- The function `start_server` only downloads the PocketIC server binary
  if no path to the PocketIC server binary is provided explicitly.

### Removed
- The constant `EXPECTED_SERVER_VERSION`: semantic version is now used instead of a fixed expected PocketIC server version.



## 10.0.0 - 2025-09-12

### Added
- The function `start_server` and its input type `StartServerParams` to manually start a PocketIC server.
- The function `PocketIc::upgrade_eop_canister` to upgrade a Motoko EOP canister.
- The function `PocketIcBuilder::with_icp_features` to specify that selected ICP features (supported by PocketIC) should be enabled.
- The function `PocketIcBuilder::with_initial_timestamp` to specify the initial timestamp of the newly created PocketIC instance.
- The function `PocketIcBuilder::with_auto_progress` to specify that the new instance should make progress automatically,
  i.e., PocketIC should periodically update the time of the instance to the real time and execute rounds on the subnets.
- The function `PocketIcBuilder::with_http_gateway` to specify that an HTTP gateway should be created for the newly created instance.

### Removed
- The field `node_ids` from `SubnetConfig`. Node ids can always be retrieved from the registry.
- The deprecated function `PocketIc::make_deterministic`.

### Changed
- Renamed `PocketIcBuilder::with_nonmainnet_features` to `PocketIcBuilder::with_icp_config` and changed the argument type
  from a simple Boolean to a record with separate settings for the individual configuration options.



## 9.0.2 - 2025-06-06

(Only PocketIC server version bump to v9.0.3.)



## 9.0.1 - 2025-05-27

(Only PocketIC server version bump to v9.0.2.)



## 9.0.0 - 2025-04-30

### Changed
- Bumped `ic-management-canister-types` to v0.3.0.



## 8.0.0 - 2025-04-23

### Added
- The function `PocketIc::auto_progress_enabled` to determine whether the automatic progress was enabled for the PocketIC instance.
- The struct `PocketIcState` encapsulating the state of a PocketIC instance persisted in a temporary directory (`PocketIcState::new`)
  or in a directory on disk (`PocketIcState::new_from_path`).
  A temporary directory is managed by `PocketIcState` (i.e., it is deleted automatically when `PocketIcState` is dropped)
  unless consumed into a `PathBuf` using `PocketIcState::into_path`.
  The directory on disk used in `PocketIcState::new_from_path` is persisted after `PocketIcState` is dropped.
- The function `PocketIcBuilder::with_read_only_state` to specify a state from which the PocketIC instance is initialized.
  The provided state is not modified (i.e., it is read-only).
- The function `PocketIcBuilder::with_state` to specify a state from which the PocketIC instance is initialized
  and in which changes to the PocketIC instance are persisted.
  This state must be empty if `PocketIcBuilder::with_read_only_state` is used.
- The function `PocketIc::drop_and_take_state` to drop a PocketIC instance and get its final state if the instance was created
  using `PocketIcBuilder::with_state` or `PocketIcBuilder::with_state_dir`.
- The type `Time` used by the functions `PocketIc::get_time`, `PocketIc::set_time`, and `PocketIc::set_certified_time`.

### Removed
- The module `management_canister` used to contain interface types of the IC management canister. Those types have since been published on crates.io as `ic-management-canister-types`, so PocketIC can depend on that and remove the redundant types.
- The subnet ID from the functions `SubnetSpec::with_state_dir`, `PocketIcBuilder::with_nns_state`, and `PocketIcBuilder::with_subnet_state`;
  the subnet ID from the type `SubnetStateConfig`; and the functions `SubnetSpec::get_subnet_id` and `SubnetStateConfig::get_subnet_id`.

### Changed
- The functions `PocketIcBuilder::with_nns_subnet`, `PocketIcBuilder::with_sns_subnet`, `PocketIcBuilder::with_ii_subnet`, `PocketIcBuilder::with_fiduciary_subnet`, and `PocketIcBuilder::with_bitcoin_subnet` do not add a new empty subnet if a subnet of the corresponding kind has already been specified (e.g., with state loaded from a given state directory).
- The function `PocketIc::make_live_with_params` takes an optional IP address to which the HTTP gateway should bind.



## 7.0.0 - 2025-02-26

### Added
- The function `PocketIcBuilder::with_bitcoind_addrs` to specify multiple addresses and ports at which `bitcoind` processes are listening.
- The function `PocketIc::new_from_existing_instance` to create a PocketIC handle to an existing instance on a running server.
- The function `PocketIc::get_server_url` returning the URL of the PocketIC server on which the PocketIC instance is running.
- The functions `PocketIc::update_call_with_effective_principal` and `PocketIc::query_call_with_effective_principal` for making generic query calls (including management canister query calls).
- The function `PocketIc::ingress_status` to fetch the status of an update call submitted through an ingress message.
- The function `PocketIc::ingress_status_as` to fetch the status of an update call submitted through an ingress message.
  If the status of the update call is known, but the update call was submitted by a different caller, then an error is returned.
- The function `PocketIc::await_call_no_ticks` to await the status of an update call (submitted through an ingress message) becoming known without triggering round execution
  (round execution must be triggered separarely, e.g., on a "live" instance or by separate PocketIC library calls).
- The function `PocketIc::set_certified_time` to set the current certified time on all subnets of the PocketIC instance.
- The function `PocketIc::tick_with_configs` extending the function `PocketIc::tick` with an argument optionally containing the blockmaker and failed blockmakers
  for every subnet used by the endpoint `node_metrics_history` of the management canister.
- The function `PocketIcBuilder::with_server_binary` to provide the path to the PocketIC server binary used instead of the environment variable `POCKET_IC_BIN`.

### Changed
- The response types `pocket_ic::WasmResult`, `pocket_ic::UserError`, and `pocket_ic::CallError` are replaced by a single reject response type `pocket_ic::RejectResponse`.
- The PocketIC server binary is downloaded to a subdirectory of the temporary directory if neither the function `PocketIcBuilder::with_server_binary`
  nor the environment variable `POCKET_IC_BIN` provide the path to the PocketIC server binary.
- The current working directory is ignored when looking for the PocketIC server binary.

## 6.0.0 - 2024-11-13

### Added
- The function `PocketIc::get_subnet_metrics` to retrieve metrics of a given subnet.
- The function `PocketIcBuilder::with_bitcoind_addr` to specify the address and port at which a `bitcoind` process is listening.
- The function `PocketIcBuilder::new_with_config` to specify a custom `ExtendedSubnetConfigSet`.
- The function `PocketIcBuilder::with_subnet_state` to load subnet state from a state directory for an arbitrary subnet kind and subnet id.
- The function `get_default_effective_canister_id` to retrieve a default effective canister id for canister creation on a PocketIC instance.
- The function `PocketIc::get_controllers` to get the controllers of a canister.
- Functions `PocketIc::take_canister_snapshot`, `PocketIc::load_canister_snapshot`, `PocketIc::list_canister_snapshots`, and `PocketIc::delete_canister_snapshot` to manage canister snapshots.
- Functions `PocketIc::upload_chunk`, `PocketIc::stored_chunks`, and `PocketIc::clear_chunk_store` to manage the WASM chunk store of a canister.
- The function `PocketIc::install_chunked_canister` to install a canister from WASM chunks in the WASM chunk store of a canister.
- The function `PocketIc::fetch_canister_logs` to fetch canister logs via a query call to the management canister.
- The function `Topology::get_subnet` to get a subnet to which a canister belongs independently of whether the canister exists.

### Removed
- Functions `PocketIc::from_config`, `PocketIc::from_config_and_max_request_time`, and `PocketIc::from_config_and_server_url`.
  Use the `PocketIcBuilder` instead.
- The enumeration `DtsFlag` and its associated builder patterns: DTS is always enabled in PocketIC.
- The reexport `pocket_ic::CanisterSettings`: use `pocket_ic::management_canister::CanisterSettings` instead.

### Changed
- The type `Topology` becomes a struct with two fields: `subnet_configs` contains an association of subnet ids to their configurations
  and `default_effective_canister_id` contains a default effective canister id for canister creation.
- Management canister types are defined in a new `management_canister` module to avoid a dependency on `ic-cdk`.
- Environment variable `POCKET_IC_MUTE_SERVER` now only mutes output when set to non-empty string (previously any value muted server).


## 5.0.0 - 2024-09-12

### Added
- Support for verified application subnets: the library function `PocketIcBuilder::with_verified_application_subnet` adds a verified application subnet to the PocketIC instance;
  the library function `PocketIc::get_verified_app_subnets` lists all verified application subnets of the PocketIC instance.
- The function `PocketIcBuilder::with_log_level` to specify the replica log level of the PocketIC instance.



## 4.0.0 - 2024-07-22

### Added
- Module `nonblocking` with asynchronous PocketIc library. The asynchronous function `drop` must be called
  (e.g., `pic.drop().await`) to drop the PocketIc instance. It must be called manually
  as Rust doesn't support asynchronous drop.
- The library functions `PocketIc::install_canister`, `PocketIc::upgrade_canister`, and `PocketIc::reinstall_canister`
  support installing canisters with a large WASM as a sequence of chunks (transparently, i.e.,
  the user does not need to take any extra action).
- The maximum duration (timeout) of a PocketIC operation is configurable using `PocketIcBuilder::with_max_request_time_ms`
  and can be deactivated by specifying it as `None` (the default is a timeout of 5 minutes).
- The library function `PocketIc::create_canister_with_id` works for all IC mainnet canister IDs that do not belong to the NNS or II subnet.
- The library function `PocketIc::uninstall_canister` to uninstall code of an existing canister.
- The library function `PocketIc::update_canister_settings` to update settings (e.g., compute allocation) of an existing canister.
- The library function `PocketIc::make_live_with_params` creates an HTTP gateway for this PocketIC instance listening on an optionally specified port (defaults to choosing
  an arbitrary unassigned port) and optionally specified domains (default to `localhost`) and using an optionally specified TLS certificate (if provided,
  an HTTPS gateway is created) and configures the PocketIC instance to make progress automatically, i.e., periodically update the time of the PocketIC instance to the real time
  and execute rounds on the subnets.
- The function `PocketIcBuilder::with_server_url` to specify the URL of the PocketIC server (if not used, then the URL of an already running PocketIC server
  is derived or a new PocketIC server is started).
- The function `PocketIcBuilder::with_state_dir` to specify a directory in which the state of the PocketIC instance can be preserved across the PocketIC instance lifetime
  (that directory should be empty when specified as `state_dir` for the very first time).
- The function `PocketIcBuilder::with_nonmainnet_features` to specify that non-mainnet features (e.g., best-effort responses) should be enabled for the PocketIC instance.
- Support for canister HTTP outcalls: a function `PocketIc::get_canister_http` to retrieve pending canister HTTP outcalls
  and a function `PocketIc::mock_canister_http_response` to mock a response for a pending canister HTTP outcall.

### Removed
- Public field `instance_id` in the synchronous PocketIc library, use the function `instance_id` instead

### Changed
- Deprecated `make_deterministic`, use `stop_live` instead
- The topology contains a list of node IDs instead of subnet size which can be derived from the number of node IDs.



## 3.1.0 - 2024-05-02

### Added
- Added `with_benchmarking_system_subnet` builder option to enable benchmarking with high message size limits.



## 3.0.0 - 2024-04-30

### Added
- New functions `auto_progress` and `stop_progress` to make IC instances
  progress (updating time and executing rounds) automatically.
- New subnet specification allowing to set very high instruction limits for (asymptotic) benchmarking canister code.
- New field `dts_flag` in `SubnetSpec` controlling if DTS is enabled (enabled by default on all non-benchmarking subnets).
- New functions `make_live` and `make_deterministic` configuring a PocketIc instance to automatically make progress (updating time and executing rounds)
  and creating an HTTP gateway for that instance listening at a dedicated port (and reverting that configuration, respectively).
- New functions `submit_call`, `submit_call_with_effective_principal` (submit an ingress message without executing it) and `await_call` (execute rounds on the PocketIc instance until the message is executed).

### Changed
- `get` and `post` helpers which are used by all server-facing functions now poll on results, because 1) instances can be busy with other computations and 2) the `post`ed computations may take longer than the specified timeout or the `reqwest` client's own timeout. With this change, very long-running computations can be handled by the library. 



## 2.2.0 - 2024-02-14

### Added
- a new `canister_status` function to request a canister's status

### Fixed
- `reqwest` dependency does not use the default features



## 2.1.0 - 2024-02-06

### Added
- Convenience functions `update_candid` and `update_candid_as`.
- New `set_controllers` method to set canister's controllers.
- Added PocketIC builder function `with_nns_state` to provide an NNS state directory. 

### Changed
- Use ExtendedSubnetConfigSet to be compatible with PocketIC server 3.0.0



## 2.0.1 - 2023-11-23

### Added
- Support for PocketIC server version 2.0.1


### Changed
- When the PocketIC binary is not found, the error now points to the PocketIC repo instead of the download link



## 2.0.0 - 2023-11-21

### Added
- Support for multiple subnets
- Support for cross-subnet canister calls
- Ability to mute the server's stdout/stderr streams by setting the `POCKET_IC_MUTE_SERVER` environment variable
- New struct `PocketIcBuilder` to create a PocketIC instance with a subnet configuration
- New constructor `PocketIc::from_config(config: SubnetConfigSet)` to create a PocketIC instance with a specified subnet topology
- New `get_subnet()` method to get the subnet of a canister
- New `create_canister_with_id()` method to create a canister with a specified ID
- New `create_canister_on_subnet()` method to create a canister on a specified subnet
- New `topology()` method returning a map of subnet IDs to subnet configurations
- New struct `SubnetConfig` returned by `topology()` to describe a subnet
- New struct `SubnetConfigSet` describing the desired subnet topology on initialization
- New enum `SubnetKind` to specify different kinds ob subnets

### Changed
- `create_canister()` method now takes no arguments, the anonymous prinicpal is used. To use a custom sender, use `create_canister_with_settings()`

### Removed
- `create_checkpoint()` method



## 1.0.0 - 2023-10-12

### Added
- Blocking REST-API: Encode IC-call in endpoint, not in body.
