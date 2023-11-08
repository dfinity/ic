use crate::{contracts::TargetDto, filters::TargetGroupFilter};
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
    fn filter(&self, target_group: &TargetDto) -> bool {
        if target_group.node_id == self.bn_principal_placeholder.into() {
            return self.regex.is_match(&target_group.name.to_string());
        }

        self.regex.is_match(&target_group.node_id.to_string())
    }
}
