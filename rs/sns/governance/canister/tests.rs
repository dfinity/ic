use super::*;
use assert_matches::assert_matches;
use candid_parser::utils::{CandidSource, service_equal};
use ic_sns_governance::pb::v1::{
    UpgradeJournal, UpgradeJournalEntry,
    governance::{Version, Versions},
    upgrade_journal_entry::{Event, UpgradeStepsRefreshed},
};
use pretty_assertions::assert_eq;
use std::collections::HashSet;

/// This is NOT affected by
///
///   1. comments (in ./registry.did)
///   2. whitespace
///   3. order of type definitions
///   4. names of types
///   5. etc.
///
/// Whereas, this test fails in the following cases
///
///   1. extra (or missing) fields
///   2. differences in field names
///   3. etc.
///
/// If this test passes, that does NOT mean that the API has evolved safely;
/// there is a different test for that (namely,
/// candid_changes_are_backwards_compatible). This test does not compare the
/// current working copy against master. Rather, it only compares ./canister.rs
/// to governance.did.
#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    #[cfg(feature = "test")]
    let declared_interface = include_str!("governance_test.did");
    #[cfg(not(feature = "test"))]
    let declared_interface = include_str!("governance.did");
    let declared_interface = CandidSource::Text(declared_interface);

    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(declared_interface, implemented_interface);
    assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
}

/// A test that checks that set_time_warp advances time correctly.
#[test]
fn test_set_time_warp() {
    let mut environment = CanisterEnv::new();

    let start = environment.now();
    environment.set_time_warp(TimeWarp { delta_s: 1_000 });
    let delta_s = environment.now() - start;

    assert!(delta_s >= 1000, "delta_s = {delta_s}");
    assert!(delta_s < 1005, "delta_s = {delta_s}");
}

#[test]
fn test_upgrade_journal() {
    let journal = UpgradeJournal {
        entries: vec![UpgradeJournalEntry {
            timestamp_seconds: Some(1000),
            event: Some(Event::UpgradeStepsRefreshed(UpgradeStepsRefreshed {
                upgrade_steps: Some(Versions {
                    versions: vec![Version {
                        root_wasm_hash: vec![0, 0, 0, 0],
                        governance_wasm_hash: vec![0, 0, 0, 1],
                        swap_wasm_hash: vec![0, 0, 0, 2],
                        index_wasm_hash: vec![0, 0, 0, 3],
                        ledger_wasm_hash: vec![0, 0, 0, 4],
                        archive_wasm_hash: vec![0, 0, 0, 5],
                    }],
                }),
            })),
        }],
    };

    // Currently, the `/journal` Http endpoint serves the entries directly, rather than the whole
    // journal object.
    let http_response = serve_journal(journal);
    let expected_headers: HashSet<(_, _)> = HashSet::from_iter([
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Content-Length".to_string(), "277".to_string()),
    ]);
    let (observed_headers, observed_body) = assert_matches!(
        http_response,
        HttpResponse {
            status_code: 200,
            headers,
            body
        } => (headers, body)
    );

    let observed_headers = HashSet::from_iter(observed_headers);

    assert!(
        expected_headers.is_subset(&observed_headers),
        "{expected_headers:?} is expected to be a subset of {observed_headers:?}"
    );

    let observed_journal_str = std::str::from_utf8(&observed_body).unwrap();

    assert_eq!(
        observed_journal_str,
        r#"[
            {
                "timestamp_seconds": 1000,
                "event": {
                    "UpgradeStepsRefreshed": {
                        "upgrade_steps": {
                            "versions": [
                                {
                                    "root_wasm_hash":       "00000000",
                                    "governance_wasm_hash": "00000001",
                                    "swap_wasm_hash":       "00000002",
                                    "index_wasm_hash":      "00000003",
                                    "ledger_wasm_hash":     "00000004",
                                    "archive_wasm_hash":    "00000005"
                                }
                            ]
                        }
                    }
                }
            }
        ]"#
        .replace(" ", "")
        .replace("\n", "")
    );
}
