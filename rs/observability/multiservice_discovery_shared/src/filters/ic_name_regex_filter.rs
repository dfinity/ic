use crate::{contracts::DataContract, filters::TargetGroupFilter};
use regex::Regex;

#[derive(Debug, Clone)]
pub struct IcNameRegexFilter {
    regex: Regex,
}

impl IcNameRegexFilter {
    pub fn new(regex: Regex) -> Self {
        Self { regex }
    }
    pub fn get_regex(self) -> Regex {
        self.regex
    }
}

impl TargetGroupFilter for IcNameRegexFilter {
    fn filter(&self, target_group: &dyn DataContract) -> bool {
        self.regex.is_match(&target_group.get_name())
    }
}
