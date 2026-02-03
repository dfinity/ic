/// One kibibyte (1024 bytes).
///
/// ```
/// use ic_execution_environment::units::KIB;
/// assert_eq!(KIB, 1024);
/// ```
pub const KIB: u64 = 1024;

/// One mebibyte (1024 kibibytes).
///
/// ```
/// use ic_execution_environment::units::{MIB, KIB};
/// assert_eq!(MIB, 1024 * KIB);
/// ```
pub const MIB: u64 = 1024 * KIB;

/// One gibibyte (1024 mebibytes).
///
/// ```
/// use ic_execution_environment::units::{GIB, MIB};
/// assert_eq!(GIB, 1024 * MIB);
/// ```
pub const GIB: u64 = 1024 * MIB;

/// One tebibyte (1024 gibibytes).
///
/// ```
/// use ic_execution_environment::units::{TIB, GIB};
/// assert_eq!(TIB, 1024 * GIB);
/// ```
pub const TIB: u64 = 1024 * GIB;
