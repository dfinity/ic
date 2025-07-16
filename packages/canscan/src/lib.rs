use parse_display::{Display, FromStr};
use std::collections::BTreeSet;
use derive_more::From;

#[derive(Clone, Eq, Debug, Ord, PartialEq, PartialOrd, Display, FromStr)]
pub enum CanisterEndpoint {
    #[display("update:{0}")]
    Update(String),
    #[display("query:{0}")]
    Query(String),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, From)]
pub struct CanisterEndpoints(BTreeSet<CanisterEndpoint>);

impl CanisterEndpoints {
    pub fn new() -> Self {
        Self(BTreeSet::new())
    }

    pub fn difference<'a>(
        &'a self,
        other: &'a CanisterEndpoints,
    ) -> BTreeSet<&'a CanisterEndpoint> {
        self.0.difference(&other.0).collect()
    }
}

impl FromIterator<CanisterEndpoint> for CanisterEndpoints {
    fn from_iter<I: IntoIterator<Item = CanisterEndpoint>>(iter: I) -> Self {
        Self(iter.into_iter().collect::<BTreeSet<CanisterEndpoint>>())
    }
}
