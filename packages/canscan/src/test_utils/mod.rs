use std::env;
use std::path::PathBuf;

pub fn get_runfile_path(path: &str) -> PathBuf {
    [
        env::var("RUNFILES_DIR").unwrap().as_str(),
        "_main/packages/canscan/",
        path,
    ]
    .iter()
    .collect()
}
