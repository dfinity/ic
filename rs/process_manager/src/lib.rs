//! The raison-d'être of the [ProcessManager] is starting, stopping processes
//! and observing process events, such as output printed on stdout and stderr by
//! a running process.
//!
//! [ProcessManager] exposes methods to start/kill processes and process events
//! that can be received via a `Stream` (by calling `start_stream()`).

pub mod process_manager;
