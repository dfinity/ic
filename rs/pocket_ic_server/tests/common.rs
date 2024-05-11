use candid::Principal;
use ic_registry_routing_table::CanisterIdRange;
use ic_types::PrincipalId;
use pocket_ic::common::rest::CanisterIdRange as RawCanisterIdRange;

pub fn raw_canister_id_range_into(r: &RawCanisterIdRange) -> CanisterIdRange {
    CanisterIdRange {
        start: PrincipalId(Principal::from_slice(&r.start.canister_id))
            .try_into()
            .unwrap(),
        end: PrincipalId(Principal::from_slice(&r.end.canister_id))
            .try_into()
            .unwrap(),
    }
}
