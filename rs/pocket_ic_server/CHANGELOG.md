Before a release of the PocketIC server, copy the contents below into the CHANGELOG.md in the [PocketIC server repo](https://github.com/dfinity/pocketic/blob/main/CHANGELOG.md)!
=================================================================================================================================================================================
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## Unreleased

### Added
- New endpoint `/api.json` that serves an OpenAPI documentation of the PocketIC server



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
