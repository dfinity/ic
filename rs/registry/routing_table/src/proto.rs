use super::{CanisterIdRange, CanisterIdRanges, CanisterMigrations, RoutingTable};
use ic_base_types::{subnet_id_into_protobuf, subnet_id_try_from_protobuf, CanisterId};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    registry::routing_table::v1 as pb,
    types::v1 as pb_types,
};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
};

impl From<CanisterIdRange> for pb::CanisterIdRange {
    fn from(src: CanisterIdRange) -> Self {
        Self {
            start_canister_id: Some(pb_types::CanisterId::from(src.start)),
            end_canister_id: Some(pb_types::CanisterId::from(src.end)),
        }
    }
}

impl TryFrom<pb::CanisterIdRange> for CanisterIdRange {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::CanisterIdRange) -> Result<Self, Self::Error> {
        Ok(Self {
            start: CanisterId::try_from(src.start_canister_id.ok_or(
                ProxyDecodeError::MissingField("CanisterIdRange::start_canister_id"),
            )?)?,
            end: CanisterId::try_from(src.end_canister_id.ok_or(
                ProxyDecodeError::MissingField("CanisterIdRange::end_canister_id"),
            )?)?,
        })
    }
}

impl From<CanisterIdRanges> for pb::CanisterIdRanges {
    fn from(src: CanisterIdRanges) -> Self {
        let ranges = src.0.into_iter().map(pb::CanisterIdRange::from).collect();
        Self { ranges }
    }
}

impl TryFrom<pb::CanisterIdRanges> for CanisterIdRanges {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::CanisterIdRanges) -> Result<Self, Self::Error> {
        let ranges = src
            .ranges
            .into_iter()
            .map(CanisterIdRange::try_from)
            .collect::<Result<Vec<CanisterIdRange>, Self::Error>>()?;
        Ok(ranges.try_into()?)
    }
}

impl From<RoutingTable> for pb::RoutingTable {
    fn from(src: RoutingTable) -> Self {
        Self::from(&src)
    }
}

impl From<&RoutingTable> for pb::RoutingTable {
    fn from(src: &RoutingTable) -> Self {
        let entries = src
            .0
            .iter()
            .map(|(range, subnet_id)| pb::routing_table::Entry {
                range: Some(pb::CanisterIdRange::from(*range)),
                subnet_id: Some(subnet_id_into_protobuf(*subnet_id)),
            })
            .collect();
        Self { entries }
    }
}

impl TryFrom<pb::RoutingTable> for RoutingTable {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::RoutingTable) -> Result<Self, Self::Error> {
        let mut map = BTreeMap::new();
        for entry in src.entries {
            let range = try_from_option_field(entry.range, "RoutingTable::Entry::range")?;
            let subnet_id =
                try_from_option_field(entry.subnet_id, "RoutingTable::Entry::subnet_id")?;
            let subnet_id = subnet_id_try_from_protobuf(subnet_id)?;
            if let Some(prev_subnet_id) = map.insert(range, subnet_id) {
                return Err(ProxyDecodeError::DuplicateEntry {
                    key: format!("{:?}", range),
                    v1: prev_subnet_id.to_string(),
                    v2: subnet_id.to_string(),
                });
            }
        }
        Ok(map.try_into()?)
    }
}

impl From<CanisterMigrations> for pb::CanisterMigrations {
    fn from(src: CanisterMigrations) -> Self {
        Self::from(&src)
    }
}

impl From<&CanisterMigrations> for pb::CanisterMigrations {
    fn from(src: &CanisterMigrations) -> Self {
        let entries = src
            .0
            .iter()
            .map(|(range, subnet_ids)| pb::canister_migrations::Entry {
                range: Some(pb::CanisterIdRange::from(*range)),
                subnet_ids: subnet_ids
                    .iter()
                    .map(|subnet_id| subnet_id_into_protobuf(*subnet_id))
                    .collect(),
            })
            .collect();
        Self { entries }
    }
}

impl TryFrom<pb::CanisterMigrations> for CanisterMigrations {
    type Error = ProxyDecodeError;

    fn try_from(src: pb::CanisterMigrations) -> Result<Self, Self::Error> {
        let mut map = BTreeMap::new();
        for entry in src.entries {
            let range = try_from_option_field(entry.range, "CanisterMigrations::Entry::range")?;
            let mut subnet_ids = Vec::new();
            for subnet_id in entry.subnet_ids {
                subnet_ids.push(subnet_id_try_from_protobuf(subnet_id)?);
            }
            if let Some(prev_subnet_ids) = map.insert(range, subnet_ids.clone()) {
                return Err(ProxyDecodeError::DuplicateEntry {
                    key: format!("{:?}", range),
                    v1: format!("{:?}", prev_subnet_ids),
                    v2: format!("{:?}", subnet_ids),
                });
            }
        }
        Ok(map.try_into()?)
    }
}
