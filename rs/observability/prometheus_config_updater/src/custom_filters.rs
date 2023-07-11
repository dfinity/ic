use std::net::{IpAddr, SocketAddr};

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
            .map(|sockaddr: &SocketAddr| {
                sockaddr.port() != 9100
                    || !matches!(sockaddr.ip(), IpAddr::V6(a) if a.segments()[4] == 0x5000)
            })
            .all(|is_new| is_new)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddrV6, str::FromStr};

    use ic_types::{NodeId, PrincipalId, SubnetId};
    use service_discovery::TargetGroup;

    use crate::custom_filters::OldMachinesFilter;
    use config_writer_common::filters::TargetGroupFilter;

    fn create_dummy_target_group(ipv6: &str) -> TargetGroup {
        let mut targets = BTreeSet::new();
        targets.insert(std::net::SocketAddr::V6(
            SocketAddrV6::from_str(ipv6).unwrap(),
        ));
        TargetGroup {
            node_id: NodeId::from(PrincipalId::new_anonymous()),
            ic_name: "mercury".into(),
            targets,
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        }
    }

    #[test]
    fn old_machine_filter_test() {
        let filter = OldMachinesFilter {};

        let new_orchestrator_tg =
            create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091");
        assert!(TargetGroupFilter::filter(&filter, new_orchestrator_tg));

        let old_orchestrator_tg =
            create_dummy_target_group("[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091");
        assert!(TargetGroupFilter::filter(&filter, old_orchestrator_tg));

        let old_host_tg = create_dummy_target_group("[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9100");
        assert!(!TargetGroupFilter::filter(&filter, old_host_tg));

        let new_host_tg = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9100");
        assert!(TargetGroupFilter::filter(&filter, new_host_tg));
    }
}
