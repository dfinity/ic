pub mod fs;
pub mod mmap;
pub mod utility_command;

use lazy_static::lazy_static;

lazy_static! {
    /// Size of an OS memory page in bytes.
    pub static ref PAGE_SIZE: usize = {
        use nix::unistd::{sysconf, SysconfVar};
        sysconf(SysconfVar::PAGE_SIZE)
            .expect("sysconf PAGE_SIZE succeeds")
            .expect("PAGE_SIZE is not none") as usize
    };

    pub static ref IS_WSL: bool = wsl::is_wsl();
}
