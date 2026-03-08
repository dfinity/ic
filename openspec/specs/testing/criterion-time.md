# Criterion Time Utilities

The `ic-criterion-time` crate (`rs/criterion_time/`) provides a custom Criterion.rs measurement implementation that uses process CPU time instead of wall-clock time for more accurate benchmarking.

## Requirements

### Requirement: Process Time Measurement

The `ProcessTime` enum provides CPU-time-based measurements using the `getrusage` system call.

#### Scenario: User time measurement
- **WHEN** `ProcessTime::UserTime` is used as a Criterion measurement
- **THEN** only the user-mode CPU time of the process is measured
- **AND** system time (kernel time) is excluded

#### Scenario: User and system time measurement
- **WHEN** `ProcessTime::UserAndSystemTime` is used (the default)
- **THEN** both user-mode and system-mode CPU time are measured
- **AND** the sum of `ru_utime` and `ru_stime` from `getrusage(RUSAGE_SELF)` is used

#### Scenario: Default measurement mode
- **WHEN** `ProcessTime::default()` is used
- **THEN** `UserAndSystemTime` is selected as the default

### Requirement: Criterion Measurement Trait Implementation

`ProcessTime` implements Criterion's `Measurement` trait.

#### Scenario: Start measurement
- **WHEN** `measurement.start()` is called
- **THEN** the current process CPU time (as `Duration`) is captured via `getrusage`

#### Scenario: End measurement
- **WHEN** `measurement.end(intermediate)` is called
- **THEN** the elapsed process CPU time is computed by subtracting the intermediate from the current time

#### Scenario: Value arithmetic
- **WHEN** `measurement.add(v1, v2)` is called
- **THEN** the two `Duration` values are summed

#### Scenario: Zero value
- **WHEN** `measurement.zero()` is called
- **THEN** `Duration::from_secs(0)` is returned

#### Scenario: Float conversion
- **WHEN** `measurement.to_f64(val)` is called
- **THEN** the duration is converted to nanoseconds as `f64`

#### Scenario: Formatter
- **WHEN** `measurement.formatter()` is called
- **THEN** the `WallTime` formatter from Criterion is reused for display

### Requirement: Resource Usage System Call

The crate wraps the `getrusage` libc call for portability.

#### Scenario: Successful resource usage query
- **WHEN** `resource_usage()` is called
- **THEN** `libc::getrusage(RUSAGE_SELF, ...)` is invoked
- **AND** the `rusage` struct is returned with timing information

#### Scenario: System call failure
- **WHEN** `getrusage` returns a non-zero value
- **THEN** the function panics with the system error from `std::io::Error::last_os_error()`

#### Scenario: Timeval to Duration conversion
- **WHEN** `timeval_to_duration(tv)` is called
- **THEN** `tv_sec` is converted to seconds and `tv_usec` to microseconds
- **AND** they are summed into a single `Duration`
