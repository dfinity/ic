use crate::{contracts::DataContract, filters::TargetGroupFilter};
use ic_types::PrincipalId;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct NodeIDRegexFilter {
    regex: Regex,
    bn_principal_placeholder: PrincipalId,
}

impl NodeIDRegexFilter {
    pub fn new(regex: Regex) -> Self {
        Self {
            regex,
            bn_principal_placeholder: PrincipalId::new_anonymous(),
        }
    }
    pub fn get_regex(self) -> Regex {
        self.regex
    }
}

impl TargetGroupFilter for NodeIDRegexFilter {
    fn filter(&self, target_group: &dyn DataContract) -> bool {
        if target_group.get_id() == self.bn_principal_placeholder.to_string() {
            return self.regex.is_match(&target_group.get_name().to_string());
        }

        self.regex.is_match(&target_group.get_id())
    }
}
