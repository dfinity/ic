use lazy_static::lazy_static;

use tla_instrumentation::Update;

use super::empty_update;

lazy_static! {
    pub static ref UPDATE_BALANCE_DESC: Update = empty_update("Update_Balance");
}

