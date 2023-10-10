use std::fmt::Debug;

use crate::contracts::TargetDto;

pub mod ic_name_regex_filter;
pub mod node_regex_id_filter;

pub trait TargetGroupFilter: Send + Sync + Debug {
    fn filter(&self, target_groups: &TargetDto) -> bool;
}

#[derive(Debug)]
pub struct TargetGroupFilterList {
    filters: Vec<Box<dyn TargetGroupFilter>>,
}

impl TargetGroupFilterList {
    pub fn new(filters: Vec<Box<dyn TargetGroupFilter>>) -> Self {
        Self { filters }
    }

    pub fn add(&mut self, filter: Box<dyn TargetGroupFilter>) {
        self.filters.push(filter);
    }
}

impl TargetGroupFilter for TargetGroupFilterList {
    fn filter(&self, target_group: &TargetDto) -> bool {
        // If the group is empty, consider that as having no filter, thus always accept the element
        if self.filters.is_empty() {
            true
        } else {
            self.filters
                .iter()
                .map(|f| f.filter(target_group))
                .all(|status| status)
        }
    }
}
