//! Tools for creating and manipulating disk partitions (ext4, FAT, GPT) used
//! during IC-OS image construction.

pub mod ext;
pub mod fat;
mod gpt;
mod partition;

pub use partition::Partition;
