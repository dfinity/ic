#[rustfmt::skip]

use anyhow::Result;
use ic_query_stats_test::{aggregation::query_stats_above_threshold, query_stats_config};
use ic_system_test_driver::{driver::group::SystemTestGroup, systest};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(query_stats_config)
        .add_test(systest!(query_stats_above_threshold))
        .execute_from_args()?;
    Ok(())
}
