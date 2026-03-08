# TLA+ Instrumentation

The `rs/tla_instrumentation/` directory provides a Rust framework for linking IC canister code to TLA+ formal models, enabling runtime verification that code transitions match TLA+ specifications.

## Requirements

### Requirement: TLA+ Value Representation

The `tla_value` module (`tla_instrumentation/src/tla_value.rs`) defines a Rust representation of TLA+ values.

#### Scenario: TLA+ value types
- **WHEN** TLA+ values are constructed in Rust
- **THEN** the `TlaValue` enum supports: `Set`, `Record`, `Function`, `Seq`, `Literal`, `Constant`, `Bool`, `Int`, and `Variant`
- **AND** all variants implement `Clone`, `Hash`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`
- **AND** all variants are serializable via Candid

#### Scenario: Value size computation
- **WHEN** `value.size()` is called
- **THEN** it returns an approximation of the value size in terms of atoms
- **AND** compound types recursively sum the sizes of their elements

#### Scenario: Value diff computation
- **WHEN** `value.diff(other)` is called
- **THEN** it returns `None` if the values are equal
- **AND** for `Record` types, it returns a `RecordDiff` with only the differing fields
- **AND** for `Function` types, it returns a `FunctionDiff` with differing key-value pairs
- **AND** for other types, it returns `Diff::Other(Some(self), Some(other))`
- **AND** nested records and functions produce hierarchical diffs (e.g., `field.subfield`)

#### Scenario: ToTla trait conversion
- **WHEN** Rust types implement `ToTla`
- **THEN** they can be converted to `TlaValue` using `.to_tla_value()`
- **AND** standard types like `bool`, integers, `String`, `BTreeMap`, `BTreeSet`, `Vec`, `Principal`, `Nat`, and `Int` are supported

### Requirement: TLA+ State Management

The `tla_state` module manages variable assignments, labels, and state transitions.

#### Scenario: Variable assignment
- **WHEN** `VarAssignment::new()` is created
- **THEN** it represents an empty mapping of variable names to TLA+ values
- **AND** variables can be added via `push(name, value)` or `add(name, value)`

#### Scenario: Variable assignment merge
- **WHEN** two `VarAssignment`s are merged via `merge()`
- **THEN** the result contains variables from both assignments
- **AND** the operation panics if the two assignments have overlapping variable names

#### Scenario: Global state tracking
- **WHEN** `GlobalState` is used during instrumentation
- **THEN** it wraps a `VarAssignment` representing the global canister state
- **AND** it supports `extend()` for incremental state accumulation

#### Scenario: Local state with labels
- **WHEN** `LocalState` is constructed
- **THEN** it pairs a `VarAssignment` of local variables with a `Label` indicating the program counter
- **AND** labels can be merged from a stack of nested function calls

### Requirement: Instrumentation State Machine

The core instrumentation library tracks state transitions during canister message handling.

#### Scenario: Initialize instrumentation for message handler
- **WHEN** `InstrumentationState::new(update, global, snapshotter, location)` is called
- **THEN** a new `MessageHandlerState` is created with the initial label from the `Update`
- **AND** default start locals are applied
- **AND** the global state is captured at the handler entry point

#### Scenario: Log local variables
- **WHEN** `tla_log_locals!(var1: expr1, var2: expr2)` is invoked
- **THEN** the specified local variables and their values are recorded in the instrumentation state
- **AND** if instrumentation is not initialized, a warning is printed instead of panicking

#### Scenario: Log global variables
- **WHEN** `tla_log_globals!((var1: expr1, var2: expr2))` is invoked
- **THEN** the specified global variables are recorded in the instrumentation state

#### Scenario: Log inter-canister request
- **WHEN** `tla_log_request!(label, destination, method, message)` is invoked
- **THEN** a state pair is recorded capturing the transition from current state to a new state
- **AND** the request buffer records the destination, method, and arguments
- **AND** the label is pushed onto the location stack
- **AND** the state pair is added to the accumulated trace

#### Scenario: Log inter-canister response
- **WHEN** `tla_log_response!(from, message)` is invoked
- **THEN** a new start state is recorded with the response information
- **AND** the global and local state are reset for the continuation

#### Scenario: Log method return
- **WHEN** `log_method_return(state, global, location)` is called
- **THEN** it finalizes the state pair from the last start state to the end state
- **AND** the end label is taken from the `Update`'s `end_label`
- **AND** the resolved state pair is returned

#### Scenario: Function call tracking
- **WHEN** `log_fn_call` and `log_fn_return` are called
- **THEN** a placeholder is pushed/popped on the location stack
- **AND** this supports nested function instrumentation with merged labels

### Requirement: Update Description

The `Update` struct describes a TLA+ process (PlusCal procedure).

#### Scenario: Define an update
- **WHEN** an `Update` is constructed
- **THEN** it specifies: start and end labels, default start/end locals, process ID, canister name
- **AND** a `post_process` function for cleaning up traces and extracting constants

#### Scenario: Update trace collection
- **WHEN** a message handler completes
- **THEN** an `UpdateTrace` is produced containing: model name, state pairs, and constants
- **AND** traces are stored in either `TLA_TRACES_LKEY` (thread-local) or `TLA_TRACES_MUTEX` (global)

### Requirement: TLA+ Proc Macro (tla_update_method)

The `tla_instrumentation_proc_macros` crate provides the `#[tla_update_method]` attribute.

#### Scenario: Annotate a canister method
- **WHEN** `#[tla_update_method(update_expr, snapshotter_expr)]` is applied to a function
- **THEN** the function is wrapped with instrumentation code
- **AND** `InstrumentationState` is initialized before the function body
- **AND** the trace is collected and stored after the function completes
- **AND** both sync and async functions are supported (via `force_async_fn` keyword argument)

#### Scenario: Async trait support
- **WHEN** `force_async_fn = true` is specified
- **THEN** the macro handles `async_trait`-desugared functions that return `Pin<Box<dyn Future<...>>>`

### Requirement: Apalache Model Checker Integration

The `checker` module verifies state transitions against TLA+ models using the Apalache model checker.

#### Scenario: Check state transition
- **WHEN** a state pair is checked against a TLA+ model
- **THEN** an init predicate is generated from the pre-state
- **AND** a next predicate constrains the transition to the post-state
- **AND** Apalache is invoked to verify the transition is valid

#### Scenario: Apalache check failure
- **WHEN** Apalache reports a check failure
- **THEN** `ApalacheError::CheckFailed` is returned with the exit code and stderr
- **AND** exit code 12 indicates a likely mismatch between code and model
- **AND** `TlaCheckError` includes the model path, the state pair, and constants for debugging

#### Scenario: Apalache setup error
- **WHEN** Apalache cannot be invoked or the model file is not found
- **THEN** `ApalacheError::SetupError` is returned with a descriptive message
