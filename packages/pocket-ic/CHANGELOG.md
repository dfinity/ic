# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased



## 5.0.0 - 2024-09-12

### Added
- Support for verified application subnets: the library function `PocketIcBuilder::with_verified_application_subnet` adds a verified application subnet to the PocketIC instance;
  the library function `PocketIc::get_verified_app_subnets` lists all verified application subnets of the PocketIC instance.
- The function `PocketIcBuilder::with_log_level` to specify the replica log level of the PocketIC instance.
- The function `PocketIcBuilder::with_config` to specify a custom `ExtendedSubnetConfigSet`.
  This function `PocketIcBuilder::with_config` can only be used if no config was (partially) provided so far.

### Removed
- Functions `PocketIc::from_config`, `PocketIc::from_config_and_max_request_time`, and `PocketIc::from_config_and_server_url`.
  Use the `PocketIcBuilder` instead.



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
