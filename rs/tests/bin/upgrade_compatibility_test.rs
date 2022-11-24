use anyhow::Result;

use ic_tests::driver::new::group::SystemTestGroup;
use ic_tests::orchestrator::downgrade_with_ecdsa::{config, downgrade_app_subnet};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config)
        .add_test(systest!(downgrade_app_subnet))
        .execute_from_args()?;

    Ok(())
}

// vec![
//     pot_with_setup(
//         "downgrade_app_subnet_with_ecdsa",
//         orchestrator::downgrade_with_ecdsa::config,
//         par(vec![sys_t(
//             "downgrade_app_subnet_with_ecdsa",
//             orchestrator::downgrade_with_ecdsa::downgrade_app_subnet,
//         )]),
//     ),
//     pot_with_setup(
//         "upgrade_downgrade_app_subnet",
//         orchestrator::upgrade_downgrade::config,
//         par(vec![sys_t(
//             "upgrade_downgrade_app_subnet",
//             orchestrator::upgrade_downgrade::upgrade_downgrade_app_subnet,
//         )]),
//     ),
//     pot_with_setup(
//         "upgrade_downgrade_nns_subnet",
//         orchestrator::upgrade_downgrade::config,
//         par(vec![sys_t(
//             "upgrade_downgrade_nns_subnet",
//             orchestrator::upgrade_downgrade::upgrade_downgrade_nns_subnet,
//         )]),
//     ),
// ],
// )
// .with_alert(ENG_ORCHESTRATOR_CHANNEL),
