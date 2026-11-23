# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `icrc21::lib::validate_consent_message_arg_size` and `icrc21::lib::decode_consent_message_arg`, for checking and decoding the `arg` of an ICRC-21 consent message request.

### Changed
- In ICRC-21 consent messages, the memo is shown as text only if it cannot alter how the rest of the message is displayed, and as hex otherwise, labeled `Memo (hex)`. In `GenericDisplayMessage` consent messages, that means printable ASCII without backticks. In `FieldsDisplayMessage` consent messages, it means valid UTF-8 without control characters, line or paragraph separators, or bidirectional formatting characters. Before, any valid UTF-8 memo was shown as text, so a memo containing backticks or line breaks could add Markdown to a `GenericDisplayMessage` consent message. Memos that are not valid UTF-8 were already shown as hex, but without the `(hex)` label.
- `build_icrc21_consent_info` decodes the `arg` of the consent message request with a Candid skipping quota of 10,000, the same quota the `ic_cdk` endpoint macros apply to the endpoints being described.

### Fixed
- ICRC-21 consent messages for `icrc2_approve` show the approval expiration correctly for UTC offsets beyond ±9:06. An offset outside the range supported by the `time` crate is reported as an invalid UTC offset.

## 0.2.0

### Changed
- The implementation of the `Storable` trait for `Account` and the dependency on the `ic-stable-structures` crate are now disabled by default. Enable the `storable` feature flag to opt in.

## 0.1.13

### Added

- Add MetadataKey type.
- Add ICRC-107 fee collector transaction type and schema.

## 0.1.12

### Added

- `try_from_subaccount_to_principal` that returns an error rather than panicking if the subaccount is not a valid Principal.
- Add optional fee to `Mint` and `Burn` icrc3 operations.

## 0.1.11

### Changed
- Fix the generic ICRC-21 message to conform to https://github.com/dfinity/wg-identity-authentication/tree/main/topics/ICRC-21/examples, add FieldsDisplay and remove LineDisplay.

## 0.1.10

### Changed

- Remove unneeded dependency on `ic-cdk`.

## 0.1.9

### Added

- `icrc103` types.

## 0.1.8

### Added

- Add default encoding and decoding of a Principal in a Subaccount.

## 0.1.7

### Added

- Rustdoc.

## 0.1.6

### Added

- `icrc3` and `icrc21` types.

## 0.1.5

- Use candid 0.10

## 0.1.4

- Types derive `serde::Serialize`.

## 0.1.3

- Add `icrc3` module.

## 0.1.2

- Change ICRC-1 Account to use the standard ICRC-1 Textual Representation.

## 0.1.1

## 0.1.0

### Added

- `icrc1` and `icrc2` types.
- The `Value` type and the algorithm to compute its hash.

### Changed

- Updated candid library to the latest version.
