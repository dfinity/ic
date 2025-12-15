use crate::driver::{
    constants::{GROUP_SETUP_DIR, GROUP_TTL, KEEPALIVE_INTERVAL},
    context::GroupContext,
    farm::Farm,
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::HasFarmUrl,
    test_setup::GroupSetup,
};
use slog::{debug, info};

pub(crate) fn keepalive_task(group_ctx: GroupContext) -> () {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> keepalive");
    loop {
        let group_ctx: GroupContext = group_ctx.clone();
        let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
        if setup_dir.exists() {
            let env = TestEnv::new_without_duplicating_logger(setup_dir, logger.clone());
            match GroupSetup::try_read_attribute(&env) {
                Ok(group_setup) => {
                    let farm_url = env.get_farm_url().unwrap();
                    let farm = Farm::new(farm_url.clone(), env.logger());
                    let group_name = group_setup.infra_group_name;
                    if let Err(e) = farm.set_group_ttl(&group_name, GROUP_TTL) {
                        panic!(
                            "{}",
                            format!(
                                "Failed to keep group {group_name} alive via endpoint {farm_url:?}: {e:?}"
                            )
                        )
                    };
                    debug!(
                        logger,
                        "Group {} TTL set to +{:?} from now (Farm endpoint: {:?})",
                        group_name,
                        GROUP_TTL,
                        farm_url
                    );
                }
                _ => {
                    info!(logger, "Farm group not created yet.");
                }
            }
        } else {
            info!(logger, "Setup directory not created yet.");
        }
        std::thread::sleep(KEEPALIVE_INTERVAL);
    }
}
