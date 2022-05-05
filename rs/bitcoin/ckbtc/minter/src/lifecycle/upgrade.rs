use ic_ckbtc_minter::runtime::Runtime;
use ic_ckbtc_minter::types::UpgradeArgs;

pub fn pre_upgrade(_runtime: &mut dyn Runtime) {
    ic_cdk::println!("Executing pre upgrade");
}

pub fn post_upgrade(_args: UpgradeArgs, _runtime: &mut dyn Runtime) {
    ic_cdk::println!("Executing post upgrade");
}
