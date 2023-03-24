mod targets {
    use crate::messages::{Blob, Delegation};
    use crate::time::GENESIS;
    use crate::Time;
    use assert_matches::assert_matches;
    use ic_base_types::CanisterId;

    const CURRENT_TIME: Time = GENESIS;

    #[test]
    fn should_error_when_canister_id_invalid() {
        let invalid_canister_id = Blob([1_u8; 30].to_vec());
        let delegation = Delegation {
            pubkey: Blob(vec![]),
            expiration: CURRENT_TIME,
            targets: Some(vec![
                to_blob(CanisterId::from(1)),
                invalid_canister_id,
                to_blob(CanisterId::from(3)),
            ]),
        };

        let targets = delegation.targets();

        assert_matches!(targets, Err(msg) if msg.contains("longer than 29 bytes"))
    }

    #[test]
    fn should_eliminate_duplicated_canister_ids() {
        let canister_id_1 = CanisterId::from(1);
        let canister_id_2 = CanisterId::from(2);
        let canister_id_3 = CanisterId::from(3);
        let delegation = Delegation {
            pubkey: Blob(vec![]),
            expiration: CURRENT_TIME,
            targets: Some(vec![
                to_blob(canister_id_3),
                to_blob(canister_id_3),
                to_blob(canister_id_1),
                to_blob(canister_id_2),
                to_blob(canister_id_2),
                to_blob(canister_id_3),
                to_blob(canister_id_1),
            ]),
        };

        let targets = delegation.targets().expect("invalid targets");

        assert_matches!(targets, Some(computed_targets)
            if computed_targets.len() == 3 &&
            computed_targets.contains(&canister_id_1) &&
            computed_targets.contains(&canister_id_2) &&
            computed_targets.contains(&canister_id_3))
    }

    fn to_blob(id: CanisterId) -> Blob {
        Blob(id.get().to_vec())
    }
}
