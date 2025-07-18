use parse_display::{Display, FromStr};
use std::collections::BTreeSet;

#[derive(Clone, Eq, Debug, Ord, PartialEq, PartialOrd, Display, FromStr)]
pub enum CanisterEndpoint {
    #[display("update:{0}")]
    Update(String),
    #[display("query:{0}")]
    Query(String),
}

pub type CanisterEndpoints = BTreeSet<CanisterEndpoint>;
