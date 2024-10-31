use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use which;

pub fn fdisk() -> Result<PathBuf, Error> {
    match which::which("fdisk") {
        // Often in superuser folder which may not be in $PATH.
        Err(_e) => match which::which("/usr/sbin/fdisk") {
            Err(_e) => Err(Error::from(ErrorKind::Unsupported)),
            Ok(p) => Ok(p),
        },
        Ok(p) => Ok(p),
    }
}

pub fn mcopy() -> Result<PathBuf, std::io::Error> {
    match which::which("mcopy") {
        Err(_e) => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
        Ok(p) => Ok(p),
    }
}
pub fn faketime() -> Result<PathBuf, std::io::Error> {
    match which::which("faketime") {
        Err(_e) => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
        Ok(p) => Ok(p),
    }
}

pub fn debugfs() -> Result<PathBuf, std::io::Error> {
    match which::which("debugfs") {
        // Often in superuser folder which may not be in $PATH.
        Err(_e) => match which::which("/usr/sbin/debugfs") {
            Err(_e) => Err(Error::from(ErrorKind::Unsupported)),
            Ok(p) => Ok(p),
        },
        Ok(p) => Ok(p),
    }
}
