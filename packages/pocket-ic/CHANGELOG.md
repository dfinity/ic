# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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
