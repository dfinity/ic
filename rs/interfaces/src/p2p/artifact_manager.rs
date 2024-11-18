/// Event loops/actors that implement a graceful shutdown on destruction implement this trait.
/// This is useful when the the event loop/actor has multiple handles and a separate object
/// that does the shutdown is required.
pub trait JoinGuard {}
