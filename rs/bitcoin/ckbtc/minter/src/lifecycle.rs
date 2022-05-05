///! Module dealing with the lifecycle methods of the ckBTC Minter.
pub mod init;
pub use init::init;

pub mod upgrade;
pub use upgrade::{post_upgrade, pre_upgrade};
