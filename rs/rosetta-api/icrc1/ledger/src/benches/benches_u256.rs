use crate::{
    benches::{
        assert_has_num_balances, emulate_archive_blocks, icrc1_transfer, max_length_principal,
        mint_tokens, upgrade, NUM_TRANSFERS,
    },
    init_state, Access, Account, LOG,
};
use assert_matches::assert_matches;
use canbench_rs::{bench, BenchResult};
use candid::Principal;
use ic_icrc1_ledger::{FeatureFlags, InitArgs, InitArgsBuilder};
use ic_ledger_canister_core::archive::ArchiveOptions;
use icrc_ledger_types::icrc1::transfer::TransferArg;

const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[0_u8, 0, 0, 0, 2, 48, 0, 156, 1, 1]);

#[bench(raw)]
fn bench_upgrade_baseline() -> BenchResult {
    init_state(cketh_ledger_init_args_with_archive());
    assert_has_num_balances(0);

    canbench_rs::bench_fn(upgrade)
}

#[bench(raw)]
fn bench_icrc1_transfers() -> BenchResult {
    init_state(cketh_ledger_init_args_with_archive());
    let start_time = ic_cdk::api::time();
    let account_with_tokens = mint_tokens(MINTER_PRINCIPAL, u128::MAX);
    assert_has_num_balances(1);

    canbench_rs::bench_fn(|| {
        {
            let _p = canbench_rs::bench_scope("before_upgrade");
            for i in 0..NUM_TRANSFERS {
                let transfer = TransferArg {
                    from_subaccount: account_with_tokens.subaccount,
                    to: Account {
                        owner: max_length_principal(i),
                        subaccount: Some([11_u8; 32]),
                    },
                    created_at_time: Some(start_time + i as u64),
                    ..cketh_transfer()
                };
                let result = icrc1_transfer(account_with_tokens.owner, transfer.clone());
                assert_matches!(result, Ok(_));
                emulate_archive_blocks::<Access>(&LOG);
            }
            assert_has_num_balances(NUM_TRANSFERS + 2);
        }
        upgrade();
    })
}

fn cketh_ledger_init_args_with_archive() -> InitArgs {
    let minter_principal = Principal::from_text("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap();
    assert_eq!(minter_principal, MINTER_PRINCIPAL);
    let nns_root_principal = Principal::from_text("r7inp-6aaaa-aaaaa-aaabq-cai").unwrap();
    InitArgsBuilder::for_tests()
        .with_minting_account(minter_principal)
        .with_fee_collector_account(Account {
            owner: minter_principal,
            subaccount: Some([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0x0f, 0xee,
            ]),
        })
        .with_decimals(18)
        .with_max_memo_length(80)
        .with_transfer_fee(2_000_000_000_000_u64)
        .with_token_symbol("ckETH")
        .with_token_name("ckETH")
        .with_feature_flags(FeatureFlags { icrc2: true })
        .with_metadata_entry("icrc1:logo", "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45NEMzNy4zMDg3IDEzMy44NjcgMTIuMTMzIDEwOC42OTEgMTAuMDYwNSA3Ny4yMDUySDE2LjM4MzdaIiBmaWxsPSJ1cmwoI3BhaW50MF9saW5lYXJfMTEwXzU4NikiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02OC43NjQ2IDE2LjM1MzRDNDAuNzYzOCAxOC40MDM2IDE4LjQwMzcgNDAuNzYzNyAxNi4zNTM1IDY4Ljc2NDZMMTAuMDMwMyA2OC43NjQ2QzEyLjEwMjcgMzcuMjc4NCAzNy4yNzg1IDEyLjEwMjYgNjguNzY0NiAxMC4wMzAyTDY4Ljc2NDYgMTYuMzUzNFoiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMjkuNjE2IDY4LjczNDNDMTI3LjU2NiA0MC43MzM0IDEwNS4yMDYgMTguMzczMyA3Ny4yMDUxIDE2LjMyMzFMNzcuMjA1MSA5Ljk5OTk4QzEwOC42OTEgMTIuMDcyNCAxMzMuODY3IDM3LjI0ODEgMTM1LjkzOSA2OC43MzQzTDEyOS42MTYgNjguNzM0M1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl8xMTBfNTg2KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03My4xOTA0IDMxVjYxLjY4MThMOTkuMTIzIDczLjI2OTZMNzMuMTkwNCAzMVoiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAzMUw0Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA2MS42ODE4VjMxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczLjE5MDQgOTMuMTUyM1YxMTRMOTkuMTQwMyA3OC4wOTg0TDczLjE5MDQgOTMuMTUyM1oiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAxMTRWOTMuMTQ4OEw0Ny4yNTQ0IDc4LjA5ODRMNzMuMTkwNCAxMTRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNNzMuMTkwNCA4OC4zMjY5TDk5LjEyMyA3My4yNjk2TDczLjE5MDQgNjEuNjg4N1Y4OC4zMjY5WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC4yIi8+CjxwYXRoIGQ9Ik00Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA4OC4zMjY5VjYxLjY4ODdMNDcuMjU0NCA3My4yNjk2WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC42Ii8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU4NiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTg2IiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==")
        .with_archive_options(ArchiveOptions {
            trigger_threshold: 2_000,
            num_blocks_to_archive: 1_0000,
            node_max_memory_size_bytes: Some(3_221_225_472),
            max_message_size_bytes: None,
            controller_id: nns_root_principal.into(),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(100_000_000_000_000),
            max_transactions_per_response: None,
        })
        .build()
}

/// ckETH ledger transaction 495542
fn cketh_transfer() -> TransferArg {
    TransferArg {
        from_subaccount: None,
        to: Account {
            owner: Principal::from_text(
                "st2wr-mlu7d-i3dep-divn5-hdwbg-az4dh-twdwl-hvaqs-ma7lb-sqdlc-3ae",
            )
            .unwrap(),
            subaccount: None,
        },
        fee: None,
        created_at_time: None,
        memo: Some(
            vec![
                0x82_u8, 0x00, 0x83, 0x54, 0x04, 0xc5, 0x63, 0x84, 0x17, 0x78, 0xc9, 0x3f, 0x41,
                0xdc, 0x1a, 0x89, 0x82, 0x1a, 0xe1, 0xc6, 0x75, 0xbb, 0xe8, 0x15, 0x58, 0x20, 0xb5,
                0xa1, 0x01, 0xfb, 0x96, 0xc5, 0xcf, 0x22, 0x4d, 0xf0, 0xd5, 0x02, 0x9b, 0x56, 0xbe,
                0x81, 0xfc, 0x65, 0xce, 0x61, 0xf8, 0x99, 0x11, 0xb7, 0x71, 0x23, 0x27, 0x8a, 0xe7,
                0xf4, 0x67, 0xb7, 0x19, 0x01, 0x2c,
            ]
            .into(),
        ),
        amount: 19_998_200_000_000_000_000_u128.into(),
    }
}
