use std::net::IpAddr;

use config_writer_common::filters::TargetGroupFilter;
use service_discovery::TargetGroup;

#[derive(Debug)]
pub struct OldMachinesFilter {}

impl TargetGroupFilter for OldMachinesFilter {
    fn filter(&self, target_group: TargetGroup) -> bool {
        target_group
            .targets
            .iter()
            // Maps addresses to true if they are new
            .map(|sockaddr| !matches!(sockaddr.ip(), IpAddr::V6(a) if a.segments()[4] == 0x5000))
            .all(|is_new| is_new)
    }
}
