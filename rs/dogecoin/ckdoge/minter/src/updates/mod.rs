#[cfg(test)]
mod tests;

pub mod get_doge_address;
pub mod icrc21;

pub use get_doge_address::{
    account_to_p2pkh_address, account_to_p2pkh_address_from_state, get_doge_address,
};
