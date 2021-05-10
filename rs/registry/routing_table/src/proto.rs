use super::{CanisterIdRange, CanisterIdRanges, RoutingTable};
use ic_base_types::{subnet_id_into_protobuf, subnet_id_try_from_protobuf, CanisterId};
use ic_protobuf::{
    proxy::{try_from_option_field, ProxyDecodeError},
    registry::routing_table::v1 as pb,
    types::v1 as pb_types,
};
use std::{collections::BTreeMap, convert::TryFrom};

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
            start: CanisterId::try_from(src.start_canister_id.unwrap())?,
            end: CanisterId::try_from(src.end_canister_id.unwrap())?,
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
        Ok(Self(ranges))
    }
}

impl From<RoutingTable> for pb::RoutingTable {
    fn from(src: RoutingTable) -> Self {
        let entries = src
            .0
            .into_iter()
            .map(|(range, subnet_id)| pb::routing_table::Entry {
                range: Some(pb::CanisterIdRange::from(range)),
                subnet_id: Some(subnet_id_into_protobuf(subnet_id)),
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
            let subnet_id = subnet_id_try_from_protobuf(entry.subnet_id.unwrap())?;
            if let Some(prev_subnet_id) = map.insert(range, subnet_id) {
                return Err(ProxyDecodeError::DuplicateEntry {
                    key: format!("{:?}", range),
                    v1: prev_subnet_id.to_string(),
                    v2: subnet_id.to_string(),
                });
            }
        }
        Ok(Self(map))
    }
}
