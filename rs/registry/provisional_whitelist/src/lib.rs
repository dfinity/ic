use ic_base_types::PrincipalId;
use ic_protobuf::{
    proxy::ProxyDecodeError, registry::provisional_whitelist::v1 as pb, types::v1 as pb_types,
};
use std::{collections::BTreeSet, convert::TryFrom};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProvisionalWhitelist {
    /// The only PrincipalIds that are allowed to use the provisional API are
    /// the ones listed here.
    Set(BTreeSet<PrincipalId>),
    /// All PrincipalIds are allowed to use the provisional API.  This option
    /// exists to facilitate local development and testing.
    All,
}

impl ProvisionalWhitelist {
    pub fn contains(&self, id: &PrincipalId) -> bool {
        match self {
            Self::All => true,
            Self::Set(set) => set.contains(id),
        }
    }

    /// Returns a new empty whitelist
    pub fn new_empty() -> Self {
        Self::Set(BTreeSet::new())
    }
}

impl From<ProvisionalWhitelist> for pb::ProvisionalWhitelist {
    fn from(src: ProvisionalWhitelist) -> Self {
        match src {
            ProvisionalWhitelist::Set(set) => Self {
                list_type: pb::provisional_whitelist::ListType::Set as i32,
                set: set.into_iter().map(pb_types::PrincipalId::from).collect(),
            },
            ProvisionalWhitelist::All => Self {
                list_type: pb::provisional_whitelist::ListType::All as i32,
                set: vec![],
            },
        }
    }
}

impl TryFrom<pb::ProvisionalWhitelist> for ProvisionalWhitelist {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::ProvisionalWhitelist) -> Result<Self, Self::Error> {
        if src.list_type == pb::provisional_whitelist::ListType::All as i32 {
            Ok(Self::All)
        } else if src.list_type == pb::provisional_whitelist::ListType::Set as i32 {
            Ok(Self::Set(
                src.set
                    .into_iter()
                    .map(|id| PrincipalId::try_from(id).unwrap())
                    .collect(),
            ))
        } else {
            Err(ProxyDecodeError::ValueOutOfRange {
                typ: "ProvisionalWhitelist::ListType",
                err: format!(
                    "{} is not one of the expected variants of ListType.",
                    src.list_type
                ),
            })
        }
    }
}
