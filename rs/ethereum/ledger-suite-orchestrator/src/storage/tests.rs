use crate::state::{
    Archive, ArchiveWasm, GitCommitHash, Index, IndexWasm, Ledger, LedgerWasm, Wasm,
};
use crate::storage::test_fixtures::empty_wasm_store;
use crate::storage::{
    wasm_store_try_get, wasm_store_try_insert, StorableWasm, WasmStore, WasmStoreError,
};
use proptest::arbitrary::any;
use proptest::array::uniform20;
use proptest::collection::{hash_set, vec};
use proptest::prelude::{Strategy, TestCaseError};
use proptest::{prop_assert_eq, proptest};
use std::collections::BTreeSet;
use std::fmt::Debug;

#[test]
fn should_have_unique_markers() {
    let markers: BTreeSet<_> = vec![Ledger::MARKER, Index::MARKER, Archive::MARKER]
        .into_iter()
        .collect();

    assert_eq!(markers.len(), 3);
}

proptest! {
    #[test]
    fn should_record_and_retrieve_wasm(timestamp in any::<u64>(), git_commit in arb_git_commit_hash(), (ledger_wasm, index_wasm, archive_wasm) in arb_distinct_wasms()) {
        fn test_retrieve <T: StorableWasm + Debug>(store: &WasmStore, wasm: &Wasm<T>) -> Result<(), TestCaseError> {
            let retrieved_wasm = wasm_store_try_get(store, wasm.hash()).unwrap().unwrap();
            prop_assert_eq!(&retrieved_wasm, wasm);
            Ok(())
        }
        let mut wasm_store = empty_wasm_store();

        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store, timestamp, git_commit.clone(), ledger_wasm.clone()), Ok(()));
        test_retrieve(&wasm_store, &ledger_wasm)?;

        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store, timestamp, git_commit.clone(), index_wasm.clone()), Ok(()));
        test_retrieve(&wasm_store, &ledger_wasm)?;
        test_retrieve(&wasm_store, &index_wasm)?;

        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store, timestamp, git_commit, archive_wasm.clone()), Ok(()));
        test_retrieve(&wasm_store, &ledger_wasm)?;
        test_retrieve(&wasm_store, &index_wasm)?;
        test_retrieve(&wasm_store, &archive_wasm)?;
    }

    #[test]
    fn should_not_overwrite_existing_wasm(first_timestamp in any::<u64>(), second_timestamp in any::<u64>(), git_commit in arb_git_commit_hash(), wasm in arb_wasm::<Ledger>()) {
        let mut wasm_store = empty_wasm_store();
        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store, first_timestamp, git_commit.clone(), wasm.clone()), Ok(()));
        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store, second_timestamp, git_commit, wasm.clone()), Ok(()));

        prop_assert_eq!(wasm_store.get(wasm.hash()).unwrap().timestamp, first_timestamp);
    }

    #[test]
    fn should_error_when_mixing_wasms_on_record(timestamp in any::<u64>(), git_commit in arb_git_commit_hash(), binary in arb_binary()) {
        let mut wasm_store = empty_wasm_store();
        let ledger_wasm = LedgerWasm::from(binary.clone());
        let index_wasm = IndexWasm::from(binary.clone());
        let _archive_wasm = ArchiveWasm::from(binary.clone());
        let wasm_hash = ledger_wasm.hash().clone();

        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store,timestamp, git_commit.clone(), ledger_wasm), Ok(()));
        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store,timestamp, git_commit, index_wasm), Err(WasmStoreError::WasmMismatch {
            wasm_hash,
            expected_marker: Index::MARKER,
            actual_marker: Ledger::MARKER,
        }));
    }

    #[test]
    fn should_panic_when_mixing_wasms_on_retrieve(timestamp in any::<u64>(), git_commit in arb_git_commit_hash(), binary in arb_binary()) {
        let mut wasm_store = empty_wasm_store();
        let ledger_wasm = LedgerWasm::from(binary.clone());
        let wasm_hash = ledger_wasm.hash().clone();
        prop_assert_eq!(wasm_store_try_insert(&mut wasm_store,timestamp, git_commit, ledger_wasm), Ok(()));

         prop_assert_eq!(wasm_store_try_get::<Index>(&wasm_store, &wasm_hash), Err(WasmStoreError::WasmMismatch {
            wasm_hash,
            expected_marker: Index::MARKER,
            actual_marker: Ledger::MARKER,
        }));
    }
}

mod validate_wasm_hashes {
    use crate::state::{GitCommitHash, WasmHash};
    use crate::storage::test_fixtures::{embedded_ledger_suite_version, empty_wasm_store};
    use crate::storage::{
        record_icrc1_ledger_suite_wasms, validate_wasm_hashes, WasmHashError, WasmStore,
    };
    use assert_matches::assert_matches;
    use proptest::array::uniform32;
    use proptest::prelude::any;
    use proptest::{prop_assert_eq, proptest};

    proptest! {
         #[test]
        fn should_error_on_invalid_wasm_hash(invalid_hash in "[0-9a-fA-F]{0,63}|[0-9a-fA-F]{65,}") {
            let wasm_store = empty_wasm_store();
            let (ledger_hash, index_hash, archive_hash) = valid_wasm_hashes();

            let result = validate_wasm_hashes(&wasm_store, Some(&invalid_hash), Some(&index_hash), Some(&archive_hash));
            assert_matches!(result, Err(WasmHashError::Invalid(_)));

            let result = validate_wasm_hashes(&wasm_store, Some(&ledger_hash), Some(&invalid_hash), Some(&archive_hash));
            assert_matches!(result, Err(WasmHashError::Invalid(_)));

            let result = validate_wasm_hashes(&wasm_store, Some(&ledger_hash), Some(&index_hash), Some(&invalid_hash));
            assert_matches!(result, Err(WasmHashError::Invalid(_)));
        }

         #[test]
        fn should_error_when_wasm_hash_not_found(hash in uniform32(any::<u8>())) {
            let wasm_store = wasm_store_with_icrc1_ledger_suite();
            let (ledger_hash, index_hash, archive_hash) = valid_wasm_hashes();
            let unknown_hash = WasmHash::from(hash);

            let result = validate_wasm_hashes(&wasm_store, Some(&unknown_hash.to_string()), Some(&index_hash), Some(&archive_hash));
            prop_assert_eq!(result, Err(WasmHashError::NotFound(unknown_hash.clone())));

            let result = validate_wasm_hashes(&wasm_store, Some(&ledger_hash), Some(&unknown_hash.to_string()), Some(&archive_hash));
            prop_assert_eq!(result, Err(WasmHashError::NotFound(unknown_hash.clone())));

            let result = validate_wasm_hashes(&wasm_store, Some(&ledger_hash), Some(&index_hash), Some(&unknown_hash.to_string()));
            prop_assert_eq!(result, Err(WasmHashError::NotFound(unknown_hash)));

        }

    }

    #[test]
    fn should_error_when_hashes_collide() {
        let wasm_store = wasm_store_with_icrc1_ledger_suite();
        let (ledger_hash, index_hash, archive_hash) = valid_wasm_hashes();

        let result = validate_wasm_hashes(
            &wasm_store,
            Some(&ledger_hash),
            Some(&ledger_hash),
            Some(&archive_hash),
        );
        assert_matches!(result, Err(WasmHashError::Invalid(_)));

        let result = validate_wasm_hashes(
            &wasm_store,
            Some(&ledger_hash),
            Some(&index_hash),
            Some(&index_hash),
        );
        assert_matches!(result, Err(WasmHashError::Invalid(_)));

        let result = validate_wasm_hashes(
            &wasm_store,
            Some(&ledger_hash),
            Some(&index_hash),
            Some(&ledger_hash),
        );
        assert_matches!(result, Err(WasmHashError::Invalid(_)));

        let result = validate_wasm_hashes(
            &wasm_store,
            Some(&ledger_hash),
            Some(&ledger_hash),
            Some(&ledger_hash),
        );
        assert_matches!(result, Err(WasmHashError::Invalid(_)));
    }

    #[test]
    fn should_accept_valid_wasm_hashes() {
        let wasm_store = wasm_store_with_icrc1_ledger_suite();
        let (ledger_hash, index_hash, archive_hash) = valid_wasm_hashes();

        assert_eq!(
            validate_wasm_hashes(&wasm_store, None, None, None),
            Ok([None, None, None])
        );

        assert_eq!(
            validate_wasm_hashes(&wasm_store, Some(&ledger_hash), None, None),
            Ok([Some(ledger_hash.parse().unwrap()), None, None])
        );

        assert_eq!(
            validate_wasm_hashes(&wasm_store, None, Some(&index_hash), None),
            Ok([None, Some(index_hash.parse().unwrap()), None,])
        );

        assert_eq!(
            validate_wasm_hashes(&wasm_store, None, None, Some(&archive_hash)),
            Ok([None, None, Some(archive_hash.parse().unwrap())])
        );

        assert_eq!(
            validate_wasm_hashes(
                &wasm_store,
                Some(&ledger_hash),
                Some(&index_hash),
                Some(&archive_hash),
            ),
            Ok([
                Some(ledger_hash.parse().unwrap()),
                Some(index_hash.parse().unwrap()),
                Some(archive_hash.parse().unwrap())
            ])
        );
    }

    fn wasm_store_with_icrc1_ledger_suite() -> WasmStore {
        let mut store = empty_wasm_store();
        assert_eq!(
            record_icrc1_ledger_suite_wasms(
                &mut store,
                1_620_328_630_000_000_000,
                GitCommitHash::default(),
            ),
            Ok(embedded_ledger_suite_version())
        );
        store
    }

    fn valid_wasm_hashes() -> (String, String, String) {
        use crate::storage::LedgerSuiteVersion;
        let LedgerSuiteVersion {
            ledger_compressed_wasm_hash,
            index_compressed_wasm_hash,
            archive_compressed_wasm_hash,
        } = embedded_ledger_suite_version();
        (
            ledger_compressed_wasm_hash.to_string(),
            index_compressed_wasm_hash.to_string(),
            archive_compressed_wasm_hash.to_string(),
        )
    }
}

fn arb_binary() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..1000)
}

fn arb_wasm<T: Debug>() -> impl Strategy<Value = Wasm<T>> {
    arb_binary().prop_map(Wasm::from)
}

fn arb_git_commit_hash() -> impl Strategy<Value = GitCommitHash> {
    uniform20(any::<u8>()).prop_map(GitCommitHash::from)
}

fn arb_distinct_wasms() -> impl Strategy<Value = (LedgerWasm, IndexWasm, ArchiveWasm)> {
    hash_set(arb_binary(), 3..=3).prop_map(|wasm_hashes| {
        let wasm_hashes: Vec<_> = wasm_hashes.into_iter().collect();
        (
            LedgerWasm::from(wasm_hashes[0].clone()),
            IndexWasm::from(wasm_hashes[1].clone()),
            ArchiveWasm::from(wasm_hashes[2].clone()),
        )
    })
}
