use crate::error::get_user_home::GetUserHomeError;
use crate::error::get_user_home::GetUserHomeError::NoHomeInEnvironment;
use std::ffi::OsString;

pub fn get_user_home() -> Result<OsString, GetUserHomeError> {
    std::env::var_os("HOME").ok_or(NoHomeInEnvironment())
}
