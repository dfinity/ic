use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use which;

pub fn mcopy() -> Result<PathBuf, std::io::Error> {
    match which::which("mcopy") {
        // $PATH may not be defined in Bazel runs at all.
        Err(_e) => match which::which("/usr/bin/mcopy") {
            Err(_e) => Err(Error::from(ErrorKind::Unsupported)),
            Ok(p) => Ok(p),
        },
        Ok(p) => Ok(p),
    }
}
pub fn faketime() -> Result<PathBuf, std::io::Error> {
    match which::which("faketime") {
        // $PATH may not be defined in Bazel runs at all.
        Err(_e) => match which::which("/usr/bin/faketime") {
            Err(_e) => Err(Error::from(ErrorKind::Unsupported)),
            Ok(p) => Ok(p),
        },
        Ok(p) => Ok(p),
    }
}

pub fn debugfs() -> Result<PathBuf, std::io::Error> {
    match which::which("debugfs") {
        // Often in superuser folder which may not be in $PATH
        // or $PATH may not be defined in Bazel runs at all.
        Err(_e) => match which::which("/usr/sbin/debugfs") {
            Err(_e) => Err(Error::from(ErrorKind::Unsupported)),
            Ok(p) => Ok(p),
        },
        Ok(p) => Ok(p),
    }
}
