mod update_balance {
    use crate::state::{audit, mutate_state, UtxoCheckStatus};
    use crate::storage;
    use crate::test_fixtures::{
        ecdsa_public_key, get_uxos_response, ignored_utxo, init_args, init_state, ledger_account,
        mock::MockCanisterRuntime, quarantined_utxo, MINTER_CANISTER_ID,
    };
    use crate::updates::update_balance;
    use crate::updates::update_balance::{UpdateBalanceArgs, UtxoStatus};
    use candid::Principal;
    use ic_btc_interface::{GetUtxosResponse, Utxo};

    const KYT_PROVIDER_UUID: &str = "815f0b5f-419f-47a4-8111-ab4469e437db";
    const KYT_PROVIDER_PRINCIPAL: Principal = Principal::from_slice(&[24; 20]);

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_ignored() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let ignored_utxo = ignored_utxo();
        mutate_state(|s| audit::ignore_utxo(s, ignored_utxo.clone()));
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_caller().return_const(account.owner);
        runtime.expect_id().return_const(MINTER_CANISTER_ID);
        expect_bitcoing_get_utxos_returning(&mut runtime, vec![ignored_utxo.clone()]);
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());

        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;
        let events_after: Vec<_> = storage::events().collect();

        assert_eq!(result, Ok(vec![UtxoStatus::ValueTooSmall(ignored_utxo)]));
        assert_eq!(events_before, events_after);
    }

    #[tokio::test]
    async fn should_not_add_event_when_reevaluated_utxo_still_tainted() {
        init_state_with_ecdsa_public_key();
        let account = ledger_account();
        let quarantined_utxo = quarantined_utxo();
        register_utxo_checked(&quarantined_utxo, UtxoCheckStatus::Tainted);
        let events_before: Vec<_> = storage::events().collect();

        let mut runtime = MockCanisterRuntime::new();
        runtime.expect_caller().return_const(account.owner);
        runtime.expect_id().return_const(MINTER_CANISTER_ID);
        expect_bitcoing_get_utxos_returning(&mut runtime, vec![quarantined_utxo.clone()]);
        expect_kyt_check_utxo_returning(
            &mut runtime,
            account.owner,
            quarantined_utxo.clone(),
            UtxoCheckStatus::Tainted,
        );
        runtime.expect_time().return_const(0_u64);
        runtime.expect_global_timer_set().return_const(());

        let result = update_balance(
            UpdateBalanceArgs {
                owner: Some(account.owner),
                subaccount: account.subaccount,
            },
            &runtime,
        )
        .await;
        let events_after: Vec<_> = storage::events().collect();

        assert_eq!(result, Ok(vec![UtxoStatus::Tainted(quarantined_utxo)]));
        assert_eq!(events_before, events_after);
    }

    fn init_state_with_ecdsa_public_key() {
        init_state(init_args());
        mutate_state(|s| s.ecdsa_public_key = Some(ecdsa_public_key()))
    }

    fn register_utxo_checked(utxo: &Utxo, status: UtxoCheckStatus) {
        mutate_state(|s| {
            audit::mark_utxo_checked(
                s,
                utxo,
                KYT_PROVIDER_UUID.to_string(),
                status,
                KYT_PROVIDER_PRINCIPAL,
            );
        });
    }

    fn expect_bitcoing_get_utxos_returning(runtime: &mut MockCanisterRuntime, utxos: Vec<Utxo>) {
        runtime
            .expect_bitcoin_get_utxos()
            .times(1)
            .return_const(Ok(GetUtxosResponse {
                utxos,
                ..get_uxos_response()
            }));
    }

    fn expect_kyt_check_utxo_returning(
        runtime: &mut MockCanisterRuntime,
        caller: Principal,
        utxo: Utxo,
        status: UtxoCheckStatus,
    ) {
        runtime
            .expect_kyt_check_utxo()
            .times(1)
            .withf(move |c, u| c == &caller && u == &utxo)
            .return_const(Ok((
                KYT_PROVIDER_UUID.to_string(),
                status,
                KYT_PROVIDER_PRINCIPAL,
            )));
    }
}
