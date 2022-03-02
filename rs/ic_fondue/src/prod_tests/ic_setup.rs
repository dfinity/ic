use super::bootstrap::{init_ic, setup_and_start_vms};
use super::driver_setup::DriverContext;
use super::resource::{allocate_resources, get_resource_request};
use super::test_setup::create_ic_handle;
use crate::ic_instance::InternetComputer;
use crate::ic_manager::IcHandle;
use anyhow::Result;

impl InternetComputer {
    pub fn setup_and_start(
        &self,
        ctx: &DriverContext,
        temp_dir: &tempfile::TempDir,
        group_name: &str,
    ) -> Result<IcHandle> {
        let res_request = get_resource_request(ctx, self, group_name);
        let res_group = allocate_resources(ctx, &res_request)?;
        let (init_ic, mal_beh, node_vms) = init_ic(ctx, temp_dir.path(), self, &res_group);
        setup_and_start_vms(ctx, &init_ic, &node_vms)?;
        Ok(create_ic_handle(ctx, &init_ic, &node_vms, &mal_beh))
    }
}
