use crate::candid::{encode_upgrade_args, format_types, parse_constructor_args};
use crate::canister::TargetCanister;
use assert_matches::assert_matches;
use std::env;
use std::path::PathBuf;
use strum::IntoEnumIterator;

#[test]
fn should_encode_default_upgrade_args() {
    for canister in TargetCanister::iter() {
        let path = repository_root().join(canister.candid_file());
        let expected = "4449444c0000";

        let upgrade_args = encode_upgrade_args(&canister, &path, canister.default_upgrade_args());

        assert_eq!(
            hex::encode(upgrade_args.upgrade_args_bin()),
            expected,
            "failed to encode default upgrade args for: {canister:?}"
        );
    }
}

#[test]
fn should_encode_non_empty_ledger_upgrade_args() {
    let canister = TargetCanister::CkEthLedger;
    let path = repository_root().join(canister.candid_file());

    let upgrade_args = encode_upgrade_args(&canister, &path, "(variant {Upgrade})");

    assert!(hex::encode(upgrade_args.upgrade_args_bin()).starts_with("4449444c"));
}

#[test]
fn should_parse_constructor_parameters() {
    for canister in TargetCanister::iter() {
        if canister == TargetCanister::IcpArchive1
            || canister == TargetCanister::IcpArchive2
            || canister == TargetCanister::IcpArchive3
            || canister == TargetCanister::IcpArchive4
            //canister lives outside the monorepo
            || canister == TargetCanister::EvmRpc
            || canister == TargetCanister::CyclesLedger
            || canister == TargetCanister::ExchangeRateCanister
            || canister == TargetCanister::SolRpc
            || canister == TargetCanister::Bitcoin
            || canister == TargetCanister::BtcWatchdog
            || canister == TargetCanister::Dogecoin
        {
            continue;
        }

        let path = repository_root().join(canister.candid_file());

        let (_env, constructor_args) = parse_constructor_args(&path);

        assert_matches!(
            (canister, format_types(&constructor_args).as_str()),
            (
                TargetCanister::CkBtcArchive,
                "(principal, nat64, opt nat64, opt nat64)"
            ) | (TargetCanister::BtcChecker, "(CheckArg)")
                | (TargetCanister::CkBtcIndex, "(opt IndexArg)")
                | (TargetCanister::CkBtcLedger, "(LedgerArg)")
                | (TargetCanister::CkBtcMinter, "(MinterArg)")
                | (
                    TargetCanister::CkEthArchive,
                    "(principal, nat64, opt nat64, opt nat64)"
                )
                | (TargetCanister::CkEthIndex, "(opt IndexArg)")
                | (TargetCanister::CkEthLedger, "(LedgerArg)")
                | (TargetCanister::CkEthMinter, "(MinterArg)")
                | (TargetCanister::CyclesIndex, "(opt IndexArg)")
                | (TargetCanister::IcpIndex, "(InitArg)")
                | (TargetCanister::IcpLedger, "(LedgerCanisterPayload)")
                | (TargetCanister::LedgerSuiteOrchestrator, "(OrchestratorArg)")
        );
    }
}

#[test]
fn should_render_correct_didc_encode_command() {
    let canister = TargetCanister::CkEthMinter;
    let path = repository_root().join(canister.candid_file());
    let upgrade_args = encode_upgrade_args(&canister, &path, "(variant {UpgradeArg = record {} })");

    let didc_encode_cmd = upgrade_args.didc_encode_cmd();

    assert_eq!(
        didc_encode_cmd,
        "didc encode -d rs/ethereum/cketh/minter/cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {} })'"
    );
}

fn repository_root() -> PathBuf {
    match env::var("CARGO_MANIFEST_DIR") {
        Ok(path) => PathBuf::from(path)
            .join("../../../")
            .canonicalize()
            .expect("failed to canonicalize path"),
        Err(_) => PathBuf::from(env::var("PWD").expect("CARGO_MANIFEST_DIR and PWD are not set")),
    }
}
