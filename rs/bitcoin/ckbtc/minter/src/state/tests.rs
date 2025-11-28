mod processable_utxos_for_account {
    use crate::state::invariants::CheckInvariantsImpl;
    use crate::state::{CkBtcMinterState, ProcessableUtxos, SuspendedReason};
    use crate::test_fixtures::{
        DAY, NOW, ignored_utxo, init_args, ledger_account, quarantined_utxo, utxo,
    };
    use crate::updates::update_balance::SuspendedUtxo;
    use candid::Principal;
    use ic_btc_interface::{OutPoint, Utxo};
    use icrc_ledger_types::icrc1::account::Account;
    use maplit::btreeset;
    use proptest::proptest;
    use std::time::Duration;

    #[test]
    fn should_be_all_new_utxos_when_state_empty() {
        let state = CkBtcMinterState::from(init_args());
        let all_utxos = btreeset! {utxo()};
        let result =
            state.processable_utxos_for_account(all_utxos.clone(), &ledger_account(), &NOW);
        assert_eq!(
            result,
            (
                ProcessableUtxos {
                    new_utxos: all_utxos.clone(),
                    ..Default::default()
                },
                vec![]
            )
        );
    }

    proptest! {
        #[test]
        fn should_not_reevaluate_suspended_utxo_yet(before_now_ns in 1..=3600_u64, after_now_ns in 0..=u64::MAX) {
            let mut state = CkBtcMinterState::from(init_args());
            let before_now = Duration::from_nanos(before_now_ns);
            let after_now = Duration::from_nanos(after_now_ns);
            let account = ledger_account();
            let ignored_utxo = ignored_utxo();
            state.suspend_utxo(
                ignored_utxo.clone(),
                account,
                SuspendedReason::ValueTooSmall,
                NOW.checked_sub(DAY).unwrap(),
            );
            let new_utxo = utxo();
            let (processable_utxos, suspended_utxos) = state.processable_utxos_for_account(
                btreeset! {new_utxo.clone(), ignored_utxo.clone()},
                &account,
                &NOW.checked_sub(before_now).unwrap(),
            );

            assert_eq!(
                processable_utxos,
                ProcessableUtxos {
                    new_utxos: btreeset! {new_utxo.clone()},
                    ..Default::default()
                },
            );
            assert_eq!(
                suspended_utxos,
                vec![SuspendedUtxo {
                    utxo: ignored_utxo.clone(),
                    reason: SuspendedReason::ValueTooSmall,
                    earliest_retry: NOW.as_nanos_since_unix_epoch(),
                }]
            );

            let (processable_utxos, suspended_utxos) = state.processable_utxos_for_account(
                btreeset! {new_utxo.clone(), ignored_utxo.clone()},
                &account,
                &NOW.saturating_add(after_now),
            );
            assert_eq!(
                processable_utxos,
                ProcessableUtxos {
                    new_utxos: btreeset! {new_utxo},
                    previously_ignored_utxos: btreeset! {ignored_utxo},
                    ..Default::default()
                },
            );
            assert_eq!(suspended_utxos, vec![]);
        }
    }

    #[test]
    fn should_retrieve_correct_utxos() {
        let account = ledger_account();
        let other_account = Account {
            owner: Principal::from_slice(&[43_u8; 20]),
            subaccount: None,
        };
        assert_ne!(account, other_account);
        let mut state = CkBtcMinterState::from(init_args());
        state.suspend_utxo(
            ignored_utxo(),
            account,
            SuspendedReason::ValueTooSmall,
            NOW.checked_sub(2 * DAY).unwrap(),
        );
        state.suspend_utxo(
            Utxo {
                outpoint: OutPoint {
                    txid: "2e0bf7c2d9db13143cbb317ad4726ee2d39a83275b275be83c989ea956202410"
                        .parse()
                        .unwrap(),
                    vout: 504,
                },
                ..ignored_utxo()
            },
            other_account,
            SuspendedReason::ValueTooSmall,
            NOW.checked_sub(2 * DAY).unwrap(),
        );
        assert_eq!(state.suspended_utxos.num_utxos(), 2);

        state.suspend_utxo(
            quarantined_utxo(),
            account,
            SuspendedReason::Quarantined,
            NOW.checked_sub(DAY).unwrap(),
        );
        state.suspend_utxo(
            Utxo {
                outpoint: OutPoint {
                    txid: "017ad4dc53443f81c35996e553ff0c913d3873b98cbbdea12f5418b13877cd65"
                        .parse()
                        .unwrap(),
                    vout: 1,
                },
                ..quarantined_utxo()
            },
            other_account,
            SuspendedReason::Quarantined,
            NOW.checked_sub(DAY).unwrap(),
        );
        assert_eq!(state.suspended_utxos.num_utxos(), 4);

        state.add_utxos::<CheckInvariantsImpl>(account, vec![utxo()]);
        state.add_utxos::<CheckInvariantsImpl>(
            other_account,
            vec![Utxo {
                outpoint: OutPoint {
                    txid: "178aad676fe6e38f082648c5e4297b53076ef5fe21a168b089a29374cfd26c42"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                ..utxo()
            }],
        );
        assert_eq!(state.utxos_state_addresses.len(), 2);

        let new_utxo = Utxo {
            outpoint: OutPoint {
                txid: "8efd27f52e81794e9f319736d43179b412de49622adc41e5a467e553da1474f8"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            ..utxo()
        };
        let result = state.processable_utxos_for_account(
            btreeset! {utxo(), new_utxo.clone(), ignored_utxo(), quarantined_utxo()},
            &account,
            &NOW,
        );

        assert_eq!(
            result,
            (
                ProcessableUtxos {
                    new_utxos: btreeset! {new_utxo},
                    previously_ignored_utxos: btreeset! {ignored_utxo()},
                    previously_quarantined_utxos: btreeset! {quarantined_utxo()},
                },
                vec![]
            )
        );
    }
}

mod suspended_utxos {
    use crate::state::{SuspendedReason, SuspendedUtxos};
    use crate::test_fixtures::{DAY, NOW, ledger_account, utxo};
    use maplit::btreemap;
    use std::collections::BTreeMap;

    #[test]
    fn should_be_nop_when_already_suspended_for_same_reason() {
        for reason in all_suspended_reasons() {
            let mut suspended_utxos = SuspendedUtxos::default();

            assert!(suspended_utxos.insert(ledger_account(), utxo(), reason, NOW.checked_sub(DAY)));
            assert_eq!(suspended_utxos.num_utxos(), 1);
            assert_eq!(
                suspended_utxos.last_time_checked_cache,
                btreemap! {utxo() => NOW.checked_sub(DAY).unwrap()}
            );

            assert!(!suspended_utxos.insert(ledger_account(), utxo(), reason, Some(NOW)));
            assert_eq!(suspended_utxos.num_utxos(), 1);
            assert_eq!(
                suspended_utxos.last_time_checked_cache,
                btreemap! {utxo() => NOW}
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn should_add_account_information_to_utxo() {
        for first_reason in all_suspended_reasons() {
            for second_reason in all_suspended_reasons() {
                let mut suspended_utxos = SuspendedUtxos::default();
                let utxo = utxo();

                suspended_utxos.insert_without_account(utxo.clone(), first_reason);
                assert_eq!(suspended_utxos.num_utxos(), 1);
                assert_eq!(suspended_utxos.last_time_checked_cache, BTreeMap::default());

                assert!(suspended_utxos.insert(
                    ledger_account(),
                    utxo.clone(),
                    second_reason,
                    Some(NOW)
                ));
                assert_eq!(suspended_utxos.num_utxos(), 1);
                assert_eq!(
                    suspended_utxos.last_time_checked_cache,
                    btreemap! {utxo => NOW}
                );
            }
        }
    }

    #[test]
    fn should_register_change_of_suspended_reason() {
        for reason in all_suspended_reasons() {
            let mut suspended_utxos = SuspendedUtxos::default();
            let utxo = utxo();
            assert!(suspended_utxos.insert(
                ledger_account(),
                utxo.clone(),
                reason,
                NOW.checked_sub(DAY)
            ));
            assert_eq!(suspended_utxos.num_utxos(), 1);

            let other_reason = match reason {
                SuspendedReason::ValueTooSmall => SuspendedReason::Quarantined,
                SuspendedReason::Quarantined => SuspendedReason::ValueTooSmall,
            };
            assert!(suspended_utxos.insert(
                ledger_account(),
                utxo.clone(),
                other_reason,
                Some(NOW)
            ));
            assert_eq!(suspended_utxos.num_utxos(), 1);
            assert_eq!(
                suspended_utxos.last_time_checked_cache,
                btreemap! {utxo => NOW}
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn should_remove_utxo() {
        for reason in all_suspended_reasons() {
            let mut suspended_utxos = SuspendedUtxos::default();
            let utxo = utxo();

            suspended_utxos.insert_without_account(utxo.clone(), reason);
            assert_eq!(suspended_utxos.num_utxos(), 1);
            suspended_utxos.remove_without_account(&utxo);
            assert_eq!(suspended_utxos.num_utxos(), 0);
            assert_eq!(suspended_utxos.last_time_checked_cache, BTreeMap::default());

            suspended_utxos.insert_without_account(utxo.clone(), reason);
            assert_eq!(suspended_utxos.num_utxos(), 1);
            suspended_utxos.remove(&ledger_account(), &utxo);
            assert_eq!(suspended_utxos.num_utxos(), 0);
            assert_eq!(suspended_utxos.last_time_checked_cache, BTreeMap::default());

            suspended_utxos.insert(ledger_account(), utxo.clone(), reason, Some(NOW));
            assert_eq!(suspended_utxos.num_utxos(), 1);
            suspended_utxos.remove_without_account(&utxo);
            assert_eq!(suspended_utxos.num_utxos(), 0);
            assert_eq!(suspended_utxos.last_time_checked_cache, BTreeMap::default());

            suspended_utxos.insert(ledger_account(), utxo.clone(), reason, Some(NOW));
            assert_eq!(suspended_utxos.num_utxos(), 1);
            suspended_utxos.remove(&ledger_account(), &utxo);
            assert_eq!(suspended_utxos.num_utxos(), 0);
            assert_eq!(suspended_utxos.last_time_checked_cache, BTreeMap::default());
        }
    }

    fn all_suspended_reasons() -> Vec<SuspendedReason> {
        vec![SuspendedReason::Quarantined, SuspendedReason::ValueTooSmall]
    }
}

mod withdrawal_reimbursement {
    use crate::reimbursement::{
        InvalidTransactionError, ReimburseWithdrawalTask, WithdrawalReimbursementReason,
    };
    use crate::state::{
        CkBtcMinterState, InFlightStatus, RetrieveBtcStatus, RetrieveBtcStatusV2,
        SubmittedBtcTransaction,
    };
    use crate::test_fixtures::{expect_panic_with_message, init_args, ledger_account};
    use assert_matches::assert_matches;
    use icrc_ledger_types::icrc1::account::Account;
    use std::collections::BTreeMap;

    #[test]
    fn should_fail_to_schedule_reimbursement_when_transaction_pending() {
        let mut state = CkBtcMinterState::from(init_args());
        let ledger_burn_index = 1;
        let amount_to_reimburse = 1_000;
        let ledger_account = ledger_account();
        state.push_in_flight_request(1, InFlightStatus::Signing);

        expect_panic_with_message(
            || {
                state.schedule_withdrawal_reimbursement(
                    ledger_burn_index,
                    reimburse_withdrawal_task(ledger_account, amount_to_reimburse),
                )
            },
            "BUG: Cannot reimburse",
        );

        let dummy_tx = SubmittedBtcTransaction {
            requests: vec![].into(),
            txid: "688f1309fe62ae66ea71959ef6d747bb63ec7c5ab3d8b1e25d8233616c3ec71a"
                .parse()
                .unwrap(),
            used_utxos: vec![],
            submitted_at: 0,
            change_output: None,
            fee_per_vbyte: None,
            withdrawal_fee: None,
        };
        state.push_submitted_transaction(dummy_tx.clone());

        expect_panic_with_message(
            || {
                state.schedule_withdrawal_reimbursement(
                    ledger_burn_index,
                    reimburse_withdrawal_task(ledger_account, amount_to_reimburse),
                )
            },
            "BUG: Cannot reimburse",
        );

        let replaced_tx = SubmittedBtcTransaction {
            txid: "c9535f049c9423e974ac8daddcd0353579d779cb386fd212357e199e83f4ec5f"
                .parse()
                .unwrap(),
            ..dummy_tx.clone()
        };
        state.replace_transaction(&dummy_tx.txid, replaced_tx);

        expect_panic_with_message(
            || {
                state.schedule_withdrawal_reimbursement(
                    ledger_burn_index,
                    reimburse_withdrawal_task(ledger_account, amount_to_reimburse),
                )
            },
            "BUG: Cannot reimburse",
        );
    }

    #[test]
    fn should_quarantine_withdrawal_reimbursement() {
        let mut state = CkBtcMinterState::from(init_args());
        let ledger_burn_index = 1;
        let amount_to_reimburse = 1_000;
        let ledger_account = ledger_account();
        state.schedule_withdrawal_reimbursement(
            ledger_burn_index,
            reimburse_withdrawal_task(ledger_account, amount_to_reimburse),
        );

        assert_status_v1_unknown(&state, ledger_burn_index);
        assert_matches!(
            state.retrieve_btc_status_v2(ledger_burn_index),
            RetrieveBtcStatusV2::WillReimburse(reimbursement) if
            reimbursement.account == ledger_account &&
            reimbursement.amount == amount_to_reimburse
        );

        state.quarantine_withdrawal_reimbursement(ledger_burn_index);

        assert_eq!(state.pending_withdrawal_reimbursements, BTreeMap::default());
        assert_status_v1_unknown(&state, ledger_burn_index);
        assert_eq!(
            state.retrieve_btc_status_v2(ledger_burn_index),
            RetrieveBtcStatusV2::Unknown
        );
    }

    #[test]
    fn should_complete_withdrawal_reimbursement() {
        let mut state = CkBtcMinterState::from(init_args());
        let ledger_burn_index = 1;
        let amount_to_reimburse = 1_000;
        let ledger_account = ledger_account();
        state.schedule_withdrawal_reimbursement(
            ledger_burn_index,
            reimburse_withdrawal_task(ledger_account, amount_to_reimburse),
        );

        assert_status_v1_unknown(&state, ledger_burn_index);
        assert_matches!(
            state.retrieve_btc_status_v2(ledger_burn_index),
            RetrieveBtcStatusV2::WillReimburse(reimbursement) if
            reimbursement.account == ledger_account &&
            reimbursement.amount == amount_to_reimburse
        );

        let ledger_mint_index = 3;
        state.reimburse_withdrawal_completed(ledger_burn_index, ledger_mint_index);

        assert_eq!(state.pending_withdrawal_reimbursements, BTreeMap::default());
        assert_status_v1_unknown(&state, ledger_burn_index);
        assert_matches!(
            state.retrieve_btc_status_v2(ledger_burn_index),
            RetrieveBtcStatusV2::Reimbursed(reimbursement) if
            reimbursement.account == ledger_account &&
            reimbursement.amount == amount_to_reimburse
        );
    }

    fn assert_status_v1_unknown(state: &CkBtcMinterState, ledger_burn_index: u64) {
        assert_eq!(
            state.retrieve_btc_status(ledger_burn_index),
            RetrieveBtcStatus::Unknown
        );
    }

    fn reimburse_withdrawal_task(account: Account, amount: u64) -> ReimburseWithdrawalTask {
        ReimburseWithdrawalTask {
            account,
            amount,
            reason: WithdrawalReimbursementReason::InvalidTransaction(
                InvalidTransactionError::TooManyInputs {
                    num_inputs: 2000,
                    max_num_inputs: 1000,
                },
            ),
        }
    }
}

mod utxo_set {
    use crate::state::utxos::UtxoSet;
    use crate::test_fixtures::utxo;

    #[test]
    fn should_be_sorted_by_value() {
        let small_utxo = {
            let mut utxo = utxo();
            utxo.outpoint.vout = 42;
            utxo.value = 10;
            utxo
        };
        let medium_utxo = {
            let mut utxo = utxo();
            utxo.outpoint.vout = 2;
            utxo.value = 100;
            utxo
        };
        let large_utxo = {
            let mut utxo = utxo();
            utxo.outpoint.vout = 2_000;
            utxo.value = 1_000;
            utxo
        };

        let mut utxos = UtxoSet::default();
        assert!(utxos.insert(medium_utxo.clone()));
        assert!(utxos.insert(large_utxo.clone()));
        assert!(utxos.insert(small_utxo.clone()));

        assert_eq!(utxos.len(), 3);
        let iter: Vec<_> = utxos.iter().collect();
        assert_eq!(iter, vec![&small_utxo, &medium_utxo, &large_utxo]);
    }
}
