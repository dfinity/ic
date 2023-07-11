use regex::Regex;
use service_discovery::TargetGroup;
use std::fmt::Debug;

pub trait TargetGroupFilter: Send + Sync + Debug {
    fn filter(&self, target_groups: TargetGroup) -> bool;
}

#[derive(Debug)]
pub struct NodeIDRegexFilter {
    regex: Regex,
}

impl NodeIDRegexFilter {
    pub fn new(regex: Regex) -> Self {
        Self { regex }
    }
}

impl TargetGroupFilter for NodeIDRegexFilter {
    fn filter(&self, target_group: TargetGroup) -> bool {
        self.regex.is_match(&target_group.node_id.to_string())
    }
}

#[derive(Debug)]
pub struct TargetGroupFilterList {
    filters: Vec<Box<dyn TargetGroupFilter>>,
}

impl TargetGroupFilterList {
    pub fn new(filters: Vec<Box<dyn TargetGroupFilter>>) -> Self {
        Self { filters }
    }
}

impl TargetGroupFilter for TargetGroupFilterList {
    fn filter(&self, target_group: TargetGroup) -> bool {
        // If the group is empty, consider that as having no filter, thus always accept the element
        if self.filters.is_empty() {
            true
        } else {
            self.filters
                .iter()
                .map(|f| f.filter(target_group.clone()))
                .all(|status| status)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddrV6, str::FromStr};

    use ic_types::{NodeId, PrincipalId, SubnetId};
    use regex::Regex;
    use service_discovery::TargetGroup;

    use crate::filters::TargetGroupFilter;

    use super::{NodeIDRegexFilter, TargetGroupFilterList};

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
    fn node_id_regex_filter_test() {
        let filter = NodeIDRegexFilter::new(Regex::new("^i").unwrap());

        let accepted_tg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "iylgr-zpxwq-kqgmf-4srtx-o4eey-d6bln-smmq6-we7px-ibdea-nondy-eae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        };
        assert!(filter.filter(accepted_tg));

        let rejected_tg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        };
        assert!(!filter.filter(rejected_tg));
    }

    #[test]
    fn filter_list_test() {
        let filter_vec: Vec<Box<dyn TargetGroupFilter>> =
            vec![Box::new(NodeIDRegexFilter::new(Regex::new("^i").unwrap()))];
        let filterlist = TargetGroupFilterList::new(filter_vec);

        let accepted_tg = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "iylgr-zpxwq-kqgmf-4srtx-o4eey-d6bln-smmq6-we7px-ibdea-nondy-eae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        };
        assert!(filterlist.filter(accepted_tg));

        let rejected_tg_1 = TargetGroup {
            node_id: NodeId::from(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
            ic_name: "mercury".into(),
            targets: BTreeSet::new(),
            subnet_id: Some(SubnetId::from(PrincipalId::new_anonymous())),
            dc_id: "test".to_string(),
            operator_id: PrincipalId::new_anonymous(),
            node_provider_id: PrincipalId::new_anonymous(),
        };
        assert!(!filterlist.filter(rejected_tg_1));

        let old_tg = create_dummy_target_group("[2a02:800:2:2003:5000:f6ff:fec4:4c86]:9091");
        assert!(!filterlist.filter(old_tg));
    }

    #[test]
    fn filter_list_test_empty() {
        let filterlist = TargetGroupFilterList::new(vec![]);
        let tg = create_dummy_target_group("[2a02:800:2:2003:6801:f6ff:fec4:4c86]:9091");
        assert!(filterlist.filter(tg));
    }
}
