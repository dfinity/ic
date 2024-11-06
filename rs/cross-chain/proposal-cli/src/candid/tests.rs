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

        let upgrade_args = encode_upgrade_args(&path, canister.default_upgrade_args());

        assert_eq!(
            hex::encode(upgrade_args.upgrade_args_bin()),
            expected,
            "failed to encode default upgrade args for: {:?}",
            canister
        );
    }
}

#[test]
fn should_encode_non_empty_ledger_upgrade_args() {
    let canister = TargetCanister::CkEthLedger;
    let path = repository_root().join(canister.candid_file());

    let upgrade_args = encode_upgrade_args(&path, "(variant {Upgrade})");

    assert_matches!(
        hex::encode(upgrade_args.upgrade_args_bin()).as_str(),
        "4449444c1e6b02fcb88b840301b0ced18403186e026c0992cdb6f902039efeb9a40309f2c794ae030aefcee780040b8484d5c0070585f199f40710b0d7c3920b1591c9aafe0d09bea3d1c30f166e046c089ea581d20105b2a7c2d20305a495a5e90605ffb08aab0806e0ab86ef0805e4d8cce80b0593c8e6c70c05dec5d8ae0e086e786e076d686e686e716e7d6e0c6d0d6c020071010e6b04cf89df017cc189ee017dfdd2c9df020fcdf1cbbe03716d7b6e116b029d83f46a12c9c5f1d0037f6c02b3b0dac30368ad86ca8305136e146d7b6e7a6e176c01c7bfe7b60b7e6c0dc295a99301199efeb9a40371f2c794ae037defcee780040caecbeb880412b2a4dab2051a97aabdbb06058484d5c0070582babe82081ca1e5f7a10a1db0d7c3920b1591c9aafe0d71bea3d1c30f166e7b6d1b6c020012017d6e126c089ea581d20178b2a7c2d20305a495a5e90678ffb08aab0806e0ab86ef0805e4d8cce80b0593c8e6c70c05dec5d8ae0e6801000000"
    );
}

#[test]
fn should_parse_constructor_parameters() {
    for canister in TargetCanister::iter() {
        if canister == TargetCanister::IcpArchive1
            || canister == TargetCanister::IcpArchive2
            || canister == TargetCanister::IcpArchive3
            //canister lives outside the monorepo
            || canister == TargetCanister::EvmRpc
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
            ) | (TargetCanister::CkBtcIndex, "(opt IndexArg)")
                | (TargetCanister::CkBtcKyt, "(LifecycleArg)")
                | (TargetCanister::CkBtcLedger, "(LedgerArg)")
                | (TargetCanister::CkBtcMinter, "(MinterArg)")
                | (
                    TargetCanister::CkEthArchive,
                    "(principal, nat64, opt nat64, opt nat64)"
                )
                | (TargetCanister::CkEthIndex, "(opt IndexArg)")
                | (TargetCanister::CkEthLedger, "(LedgerArg)")
                | (TargetCanister::CkEthMinter, "(MinterArg)")
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
    let upgrade_args = encode_upgrade_args(&path, "(variant {UpgradeArg = record {} })");

    let didc_encode_cmd = upgrade_args.didc_encode_cmd();

    assert_eq!(
        didc_encode_cmd,
        "didc encode -d cketh_minter.did -t '(MinterArg)' '(variant {UpgradeArg = record {} })'"
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
