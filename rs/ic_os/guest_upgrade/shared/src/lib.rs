pub mod api;
pub mod attestation;

/// The port on which the upgrade service listens.
pub const DEFAULT_SERVER_PORT: u16 = 19522;

// Path to a block device where the encrypted store is located
pub const STORE_DEVICE: &str = "/dev/disk/by-partuuid/231213c6-ec9e-11f0-b45f-b7bbea44aaf0";
