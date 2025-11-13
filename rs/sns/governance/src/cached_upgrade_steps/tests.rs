use super::*;

#[test]
fn cache_upgrade_steps_proto_conversions() {
    let pb = CachedUpgradeStepsPb {
        upgrade_steps: Some(Versions {
            versions: vec![Version {
                root_wasm_hash: vec![0, 0, 0],
                governance_wasm_hash: vec![1, 1, 1],
                ledger_wasm_hash: vec![2, 2, 2],
                swap_wasm_hash: vec![3, 3, 3],
                archive_wasm_hash: vec![4, 4, 4],
                index_wasm_hash: vec![5, 5, 5],
            }],
        }),
        requested_timestamp_seconds: Some(111),
        response_timestamp_seconds: Some(222),
    };

    // Scenario A: Round trip conversions work for a valid structure.
    {
        let cached_upgrade_steps = CachedUpgradeSteps::try_from(&pb).unwrap();
        assert_eq!(CachedUpgradeStepsPb::from(cached_upgrade_steps), pb);
    }

    // Scenario B: Conversion fails for a structure with missing `upgrade_steps` fields.
    {
        let mut pb = pb.clone();
        pb.upgrade_steps = None;
        let err = CachedUpgradeSteps::try_from(&pb).unwrap_err();
        assert_eq!(err, "CachedUpgradeSteps.upgrade_steps must be specified.");
    }

    // Scenario C: Conversion fails if there are no versions.
    {
        let mut pb = pb.clone();
        pb.upgrade_steps = Some(Versions { versions: vec![] });
        let err = CachedUpgradeSteps::try_from(&pb).unwrap_err();
        assert_eq!(err, "CachedUpgradeSteps.upgrade_steps must not be empty.");
    }

    // Scenario D: Conversion fails if there are duplicate versions.
    {
        let mut pb = pb.clone();
        let mut versions = pb.upgrade_steps.clone().unwrap().versions;
        versions.extend(versions.clone());
        pb.upgrade_steps = Some(Versions { versions });
        let err = CachedUpgradeSteps::try_from(&pb).unwrap_err();
        assert_eq!(
            err,
            "CachedUpgradeSteps.upgrade_steps must not contain duplicates: SnsVersion { \
                root:000000, governance:010101, swap:030303, \
                index:050505, ledger:020202, archive:040404 \
             } occurres more than once.",
        );
    }
}

#[test]
fn cache_upgrade_steps_sns_w_response_conversions() {
    let requested_timestamp_seconds = 111;
    let response_timestamp_seconds = 222;
    let sns_w_response = ListUpgradeStepsResponse {
        steps: vec![ListUpgradeStep {
            version: Some(
                Version {
                    root_wasm_hash: vec![0, 0, 0],
                    governance_wasm_hash: vec![1, 1, 1],
                    ledger_wasm_hash: vec![2, 2, 2],
                    swap_wasm_hash: vec![3, 3, 3],
                    archive_wasm_hash: vec![4, 4, 4],
                    index_wasm_hash: vec![5, 5, 5],
                }
                .into(),
            ),
        }],
    };
    let expected_pb = CachedUpgradeStepsPb {
        upgrade_steps: Some(Versions {
            versions: vec![Version {
                root_wasm_hash: vec![0, 0, 0],
                governance_wasm_hash: vec![1, 1, 1],
                ledger_wasm_hash: vec![2, 2, 2],
                swap_wasm_hash: vec![3, 3, 3],
                archive_wasm_hash: vec![4, 4, 4],
                index_wasm_hash: vec![5, 5, 5],
            }],
        }),
        requested_timestamp_seconds: Some(111),
        response_timestamp_seconds: Some(222),
    };

    // Scenario A: Round trip conversions work for a valid structure.
    {
        let cached_upgrade_steps = CachedUpgradeSteps::try_from_sns_w_response(
            sns_w_response.clone(),
            requested_timestamp_seconds,
            response_timestamp_seconds,
        )
        .unwrap();

        assert_eq!(
            CachedUpgradeStepsPb::from(cached_upgrade_steps),
            expected_pb
        );
    }

    // Scenario B: Conversion fails for a structure with missing `version` fields.
    {
        let mut sns_w_response = sns_w_response.clone();
        sns_w_response.steps.push(ListUpgradeStep { version: None });

        let err = CachedUpgradeSteps::try_from_sns_w_response(
            sns_w_response,
            requested_timestamp_seconds,
            response_timestamp_seconds,
        )
        .unwrap_err();

        assert!(err.contains("SnsW.list_upgrade_steps response had invalid fields"));
    }

    // Scenario C: Conversion fails if there are no versions.
    {
        let err = CachedUpgradeSteps::try_from_sns_w_response(
            ListUpgradeStepsResponse { steps: vec![] },
            requested_timestamp_seconds,
            response_timestamp_seconds,
        )
        .unwrap_err();

        assert_eq!(err, "ListUpgradeStepsResponse.steps must not be empty.");
    }

    // Scenario D: Conversion fails if there are duplicate versions.
    {
        let mut sns_w_response = sns_w_response.clone();
        sns_w_response.steps.push(sns_w_response.steps[0].clone());

        let err = CachedUpgradeSteps::try_from_sns_w_response(
            sns_w_response,
            requested_timestamp_seconds,
            response_timestamp_seconds,
        )
        .unwrap_err();

        assert_eq!(
            err,
            "ListUpgradeStepsResponse.steps must not contain duplicates: SnsVersion { \
                root:000000, governance:010101, swap:030303, \
                index:050505, ledger:020202, archive:040404 \
             } occurres more than once.",
        );
    }
}

#[test]
fn cached_upgrade_steps_without_pending_upgrades() {
    let v = Version {
        root_wasm_hash: vec![0, 0, 0],
        governance_wasm_hash: vec![1, 1, 1],
        ledger_wasm_hash: vec![2, 2, 2],
        swap_wasm_hash: vec![3, 3, 3],
        archive_wasm_hash: vec![4, 4, 4],
        index_wasm_hash: vec![5, 5, 5],
    };

    // A: It validates.
    let cached_upgrade_steps = CachedUpgradeSteps::without_pending_upgrades(v.clone(), 111);
    assert_eq!(
        CachedUpgradeSteps::try_from(&CachedUpgradeStepsPb::from(cached_upgrade_steps.clone()))
            .unwrap(),
        cached_upgrade_steps
    );

    // B. It's methods work as expected.
    assert_eq!(cached_upgrade_steps.last(), &v);
    assert!(cached_upgrade_steps.contains(&v));
    assert!(cached_upgrade_steps.is_current(&v));
    assert_eq!(cached_upgrade_steps.current(), &v);
    assert_eq!(cached_upgrade_steps.next(), None);
    assert!(!cached_upgrade_steps.has_pending_upgrades());
    assert_eq!(
        cached_upgrade_steps.clone().take_from(&v),
        Ok(cached_upgrade_steps.clone())
    );
    assert_eq!(
        cached_upgrade_steps.approximate_time_of_validity_timestamp_seconds(),
        111
    );
    assert_eq!(
        cached_upgrade_steps.validate_new_target_version(&v),
        Err("new_target_version must differ from the current version.".to_string())
    );
    assert_eq!(
        cached_upgrade_steps.into_iter().collect::<Vec<_>>(),
        vec![v]
    );
}

#[test]
fn cached_upgrade_steps_with_pending_upgrades() {
    let v0 = Version {
        root_wasm_hash: vec![0, 0, 0],
        governance_wasm_hash: vec![0, 0, 0],
        ledger_wasm_hash: vec![0, 0, 0],
        swap_wasm_hash: vec![0, 0, 0],
        archive_wasm_hash: vec![0, 0, 0],
        index_wasm_hash: vec![0, 0, 0],
    };

    let v1 = {
        let mut v = v0.clone();
        v.root_wasm_hash = vec![1, 1, 1];
        v
    };

    let v2 = {
        let mut v = v0.clone();
        v.root_wasm_hash = vec![2, 2, 2];
        v
    };

    let v3 = {
        let mut v = v0.clone();
        v.root_wasm_hash = vec![3, 3, 3];
        v
    };

    let cached_upgrade_steps = CachedUpgradeSteps {
        current_version: v0.clone(),
        subsequent_versions: vec![v1.clone(), v2.clone()],
        response_timestamp_seconds: 0,
        requested_timestamp_seconds: 0,
    };

    // .last
    assert_eq!(cached_upgrade_steps.last(), &v2);

    // .contains
    assert!(cached_upgrade_steps.contains(&v0));
    assert!(cached_upgrade_steps.contains(&v1));
    assert!(cached_upgrade_steps.contains(&v2));
    assert!(!cached_upgrade_steps.contains(&v3));

    // .current, .is_current
    assert_eq!(cached_upgrade_steps.current(), &v0);
    assert!(cached_upgrade_steps.is_current(&v0));
    assert!(!cached_upgrade_steps.is_current(&v1));
    assert!(!cached_upgrade_steps.is_current(&v2));
    assert!(!cached_upgrade_steps.is_current(&v3));

    // .next, .has_pending_upgrades
    assert_eq!(cached_upgrade_steps.next(), Some(&v1));
    assert!(cached_upgrade_steps.has_pending_upgrades());

    // .contains_in_order
    let expected_err = Err(format!("{cached_upgrade_steps:?} does not contain {v3:?}"));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v0, &v0), Ok(true));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v0, &v1), Ok(true));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v0, &v2), Ok(true));
    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v0, &v3),
        expected_err
    );

    assert_eq!(cached_upgrade_steps.contains_in_order(&v1, &v0), Ok(false));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v1, &v1), Ok(true));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v1, &v2), Ok(true));
    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v1, &v3),
        expected_err
    );

    assert_eq!(cached_upgrade_steps.contains_in_order(&v2, &v0), Ok(false));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v2, &v1), Ok(false));
    assert_eq!(cached_upgrade_steps.contains_in_order(&v2, &v2), Ok(true));
    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v2, &v3),
        expected_err
    );

    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v3, &v0),
        expected_err
    );
    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v3, &v1),
        expected_err
    );
    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v3, &v2),
        expected_err
    );
    assert_eq!(
        cached_upgrade_steps.contains_in_order(&v3, &v3),
        expected_err
    );

    // .validate_new_target_version
    assert_eq!(
        cached_upgrade_steps.validate_new_target_version(&v0),
        Err("new_target_version must differ from the current version.".to_string())
    );
    assert_eq!(
        cached_upgrade_steps.validate_new_target_version(&v1),
        Ok(())
    );
    assert_eq!(
        cached_upgrade_steps.validate_new_target_version(&v2),
        Ok(())
    );
    assert_eq!(
        cached_upgrade_steps.validate_new_target_version(&v3),
        Err("new_target_version must be among the upgrade steps.".to_string())
    );

    // .take_from
    assert_eq!(
        cached_upgrade_steps.clone().take_from(&v0),
        Ok(cached_upgrade_steps.clone())
    );
    assert_eq!(
        cached_upgrade_steps.clone().take_from(&v1),
        Ok(CachedUpgradeSteps {
            current_version: v1.clone(),
            subsequent_versions: vec![v2.clone()],
            response_timestamp_seconds: 0,
            requested_timestamp_seconds: 0,
        })
    );
    assert_eq!(
        cached_upgrade_steps.clone().take_from(&v2),
        Ok(CachedUpgradeSteps {
            current_version: v2.clone(),
            subsequent_versions: vec![],
            response_timestamp_seconds: 0,
            requested_timestamp_seconds: 0,
        })
    );
    assert_eq!(
        cached_upgrade_steps.clone().take_from(&v3),
        Err(format!(
            "Cannot take_from {v3} that is not one of the cached upgrade steps."
        ))
    );

    // .into_iter
    assert_eq!(
        cached_upgrade_steps.into_iter().collect::<Vec<_>>(),
        vec![v0, v1, v2]
    );
}
