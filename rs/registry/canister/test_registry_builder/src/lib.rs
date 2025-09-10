use ic_types::{PrincipalId, SubnetId};

pub mod builder;

mod copied_utils;
mod model;

#[cfg(test)]
mod tests;

fn operator(num: u64) -> PrincipalId {
    PrincipalId::new_user_test_id(num)
}

fn provider(num: u64) -> PrincipalId {
    PrincipalId::new_user_test_id(9999 - num)
}

fn subnet(num: u64) -> SubnetId {
    SubnetId::new(PrincipalId::new_subnet_test_id(num))
}
