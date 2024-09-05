use crate::benches::{
    assert_has_num_balances, emulate_archive_blocks, icrc1_transfer, max_length_principal,
    mint_tokens, upgrade, NUM_TRANSFERS,
};
use crate::{init_state, Access, LOG};
use assert_matches::assert_matches;
use canbench_rs::{bench, BenchResult};
use candid::Principal;
use ic_icrc1_ledger::{FeatureFlags, InitArgs, InitArgsBuilder};
use ic_ledger_canister_core::archive::ArchiveOptions;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

const MINTER_PRINCIPAL: Principal = Principal::from_slice(&[0_u8, 0, 0, 0, 2, 48, 0, 7, 1, 1]);

#[bench(raw)]
fn bench_upgrade_baseline() -> BenchResult {
    init_state(ckbtc_ledger_init_args_with_archive());
    assert_has_num_balances(0);

    canbench_rs::bench_fn(upgrade)
}

#[bench(raw)]
fn bench_icrc1_transfers() -> BenchResult {
    init_state(ckbtc_ledger_init_args_with_archive());
    let start_time = ic_cdk::api::time();
    let account_with_tokens = mint_tokens(MINTER_PRINCIPAL, u64::MAX);
    assert_has_num_balances(1);

    canbench_rs::bench_fn(|| {
        {
            let _p = canbench_rs::bench_scope("before_upgrade");
            for i in 0..NUM_TRANSFERS {
                let transfer = TransferArg {
                    from_subaccount: account_with_tokens.subaccount,
                    to: Account {
                        owner: max_length_principal(i),
                        subaccount: Some([12_u8; 32]),
                    },
                    created_at_time: Some(start_time + i as u64),
                    ..ckbtc_transfer()
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

fn ckbtc_ledger_init_args_with_archive() -> InitArgs {
    let minter_principal = Principal::from_text("mqygn-kiaaa-aaaar-qaadq-cai").unwrap();
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
        .with_decimals(8)
        .with_max_memo_length(80)
        .with_transfer_fee(10_u64)
        .with_token_symbol("ckBTC")
        .with_token_name("ckBTC")
        .with_feature_flags(FeatureFlags { icrc2: true })
        .with_metadata_entry("icrc1:logo", "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45MzlDMzcuMzA4NyAxMzMuODY3IDEyLjEzMyAxMDguNjkxIDEwLjA2MDUgNzcuMjA1MkgxNi4zODM3WiIgZmlsbD0idXJsKCNwYWludDBfbGluZWFyXzExMF81NzIpIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNjguNzY0NiAxNi4zNTM0QzQwLjc2MzggMTguNDAzNiAxOC40MDM3IDQwLjc2MzcgMTYuMzUzNSA2OC43NjQ2TDEwLjAzMDMgNjguNzY0NkMxMi4xMDI3IDM3LjI3ODQgMzcuMjc4NSAxMi4xMDI2IDY4Ljc2NDYgMTAuMDMwMkw2OC43NjQ2IDE2LjM1MzRaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTI5LjYxNiA2OC43MzQzQzEyNy41NjYgNDAuNzMzNSAxMDUuMjA2IDE4LjM3MzQgNzcuMjA1MSAxNi4zMjMyTDc3LjIwNTEgMTBDMTA4LjY5MSAxMi4wNzI0IDEzMy44NjcgMzcuMjQ4MiAxMzUuOTM5IDY4LjczNDNMMTI5LjYxNiA2OC43MzQzWiIgZmlsbD0idXJsKCNwYWludDFfbGluZWFyXzExMF81NzIpIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNzcuMjM1NCAxMjkuNTg2QzEwNS4yMzYgMTI3LjUzNiAxMjcuNTk2IDEwNS4xNzYgMTI5LjY0NyA3Ny4xNzQ5TDEzNS45NyA3Ny4xNzQ5QzEzMy44OTcgMTA4LjY2MSAxMDguNzIyIDEzMy44MzcgNzcuMjM1NCAxMzUuOTA5TDc3LjIzNTQgMTI5LjU4NloiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZD0iTTk5LjgyMTcgNjQuNzI0NUMxMDEuMDE0IDU2Ljc1MzggOTQuOTQ0NyA1Mi40Njg5IDg2LjY0NTUgNDkuNjEwNEw4OS4zMzc2IDM4LjgxM0w4Mi43NjQ1IDM3LjE3NUw4MC4xNDM1IDQ3LjY4NzlDNzguNDE1NSA0Ny4yNTczIDc2LjY0MDYgNDYuODUxMSA3NC44NzcxIDQ2LjQ0ODdMNzcuNTE2OCAzNS44NjY1TDcwLjk0NzQgMzQuMjI4NUw2OC4yNTM0IDQ1LjAyMjJDNjYuODIzIDQ0LjY5NjUgNjUuNDE4OSA0NC4zNzQ2IDY0LjA1NiA0NC4wMzU3TDY0LjA2MzUgNDQuMDAyTDU0Ljk5ODUgNDEuNzM4OEw1My4yNDk5IDQ4Ljc1ODZDNTMuMjQ5OSA0OC43NTg2IDU4LjEyNjkgNDkuODc2MiA1OC4wMjM5IDQ5Ljk0NTRDNjAuNjg2MSA1MC42MSA2MS4xNjcyIDUyLjM3MTUgNjEuMDg2NyA1My43NjhDNTguNjI3IDYzLjYzNDUgNTYuMTcyMSA3My40Nzg4IDUzLjcxMDQgODMuMzQ2N0M1My4zODQ3IDg0LjE1NTQgNTIuNTU5MSA4NS4zNjg0IDUwLjY5ODIgODQuOTA3OUM1MC43NjM3IDg1LjAwMzQgNDUuOTIwNCA4My43MTU1IDQ1LjkyMDQgODMuNzE1NUw0Mi42NTcyIDkxLjIzODlMNTEuMjExMSA5My4zNzFDNTIuODAyNSA5My43Njk3IDU0LjM2MTkgOTQuMTg3MiA1NS44OTcxIDk0LjU4MDNMNTMuMTc2OSAxMDUuNTAxTDU5Ljc0MjYgMTA3LjEzOUw2Mi40MzY2IDk2LjMzNDNDNjQuMjMwMSA5Ni44MjEgNjUuOTcxMiA5Ny4yNzAzIDY3LjY3NDkgOTcuNjkzNEw2NC45OTAyIDEwOC40NDhMNzEuNTYzNCAxMTAuMDg2TDc0LjI4MzYgOTkuMTg1M0M4NS40OTIyIDEwMS4zMDYgOTMuOTIwNyAxMDAuNDUxIDk3LjQ2ODQgOTAuMzE0MUMxMDAuMzI3IDgyLjE1MjQgOTcuMzI2MSA3Ny40NDQ1IDkxLjQyODggNzQuMzc0NUM5NS43MjM2IDczLjM4NDIgOTguOTU4NiA3MC41NTk0IDk5LjgyMTcgNjQuNzI0NVpNODQuODAzMiA4NS43ODIxQzgyLjc3MiA5My45NDM4IDY5LjAyODQgODkuNTMxNiA2NC41NzI3IDg4LjQyNTNMNjguMTgyMiA3My45NTdDNzIuNjM4IDc1LjA2ODkgODYuOTI2MyA3Ny4yNzA0IDg0LjgwMzIgODUuNzgyMVpNODYuODM2NCA2NC42MDY2Qzg0Ljk4MyA3Mi4wMzA3IDczLjU0NDEgNjguMjU4OCA2OS44MzM1IDY3LjMzNEw3My4xMDYgNTQuMjExN0M3Ni44MTY2IDU1LjEzNjQgODguNzY2NiA1Ni44NjIzIDg2LjgzNjQgNjQuNjA2NloiIGZpbGw9IndoaXRlIi8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU3MiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTcyIiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==")
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

/// ckBTC ledger transaction 1604556
fn ckbtc_transfer() -> TransferArg {
    TransferArg {
        from_subaccount: None,
        to: Account {
            owner: Principal::from_text(
                "rgwvx-m5lab-jv5b7-n6tc6-agk3j-fle2q-ndsbh-gh2wg-dxphx-oyk3i-vqe",
            )
            .unwrap(),
            subaccount: None,
        },
        fee: None,
        created_at_time: None,
        memo: Some(
            vec![
                0x82_u8, 0x00, 0x83, 0x58, 0x20, 0x18, 0x19, 0xcc, 0xd2, 0x28, 0xad, 0x2e, 0x83,
                0xc6, 0xc8, 0x63, 0x99, 0xa0, 0xd7, 0xd0, 0x2e, 0xe9, 0x75, 0x96, 0x95, 0x86, 0xf3,
                0x47, 0x85, 0xf6, 0xaf, 0x99, 0x00, 0x1e, 0x08, 0x8b, 0xa0, 0x02, 0x19, 0x07, 0xd0,
            ]
            .into(),
        ),
        amount: 167_708_u32.into(),
    }
}
