/// Source of the current time.
///
/// Abstracting the system API away lets code that timestamps its actions be exercised without a
/// canister environment.
pub trait TimeProvider: Clone + 'static {
    /// Returns the current time, in nanoseconds since the Unix epoch (1970-01-01).
    fn time(&self) -> u64;
}

/// The [`TimeProvider`] used in production, backed by the Internet Computer system API.
pub const IC_TIME_PROVIDER: IcTimeProvider = IcTimeProvider;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IcTimeProvider;

impl TimeProvider for IcTimeProvider {
    fn time(&self) -> u64 {
        ic_cdk::api::time()
    }
}
