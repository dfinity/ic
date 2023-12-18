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
            upgrade_args.upgrade_args_hex(),
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

    assert_eq!(
        upgrade_args.upgrade_args_hex(),
        "4449444c196b02fcb88b840301b0ced18403136e026c099efeb9a40303f2c794ae0304efcee780040597aabdbb060a8484d5c0070a85f199f4070bb0d7c3920b1091c9aafe0d03bea3d1c30f116e716e7d6e066d076c02007101086b04cf89df017cc189ee017dfdd2c9df0209cdf1cbbe03716d7b6e786e0c6b029d83f46a0dc9c5f1d0037f6c02b3b0dac30368ad86ca83050e6e0f6d7b6e7a6e126c01c7bfe7b60b7e6c0dc295a99301149efeb9a40371f2c794ae037defcee7800406aecbeb88040db2a4dab2051597aabdbb060a8484d5c0070a82babe820817a1e5f7a10a18b0d7c3920b1091c9aafe0d71bea3d1c30f116e7b6d166c02000d017d6e0d6c079ea581d20178b2a7c2d2030aa495a5e90678e0ab86ef080ae4d8cce80b0a93c8e6c70c0adec5d8ae0e6801000000",
        "failed to encode default upgrade args for: {:?}",
        canister
    );
}

#[test]
fn should_parse_constructor_parameters() {
    for canister in TargetCanister::iter() {
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
        );
    }
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
