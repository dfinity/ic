# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [2.0.0] - 2025-11-13

### Changed

- Breaking: The API has been significantly revised.
    - `spawn` has been replaced with `spawn_protected` and `spawn_migratory`. Protected tasks are cancelled when the method ends.
    - Contexts are now 'tracking', meaning that they know when canister methods start and end. Calls to `ic0.call_*` must be accompanied by `extend_current_method_context`; `in_callback_executor_context_for` takes this value.
    - Cancellation is no longer done per-task with the waker, but per-method with the function `cancel_all_tasks_attached_to_current_method`.

## [1.0.2] - 2025-08-18

### Changed

- Moved the panic handler logic into the executor.

### Fixed

- Removed a panic from the case where a callback context closure doesn't do anything. The only way this usually occurs is if you upgrade a canister without stopping it first. A message has been added warning you not to do this.

## [1.0.1] - 2025-06-30

### Changed

- Added a check against spawning tasks during trap recovery.
- Added a check against invoking wakers outside an executor context.

### Fixed

- Removed a panic when a dangling waker is invoked.

## [1.0.0] - 2025-05-13

This release is a copy-paste of the executor from ic-cdk 0.18.1.

## [0.1.0] - 2025-05-13

This release is a copy-paste of the executor from ic-cdk 0.17.1.
