use std::{collections::BTreeMap, path::Path, time::Duration};

use candid::Encode;
use ic_crypto_test_utils_reproducible_rng::{ReproducibleRng, reproducible_rng};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_interfaces_registry::{RegistryClient, RegistryRecord, ZERO_REGISTRY_VERSION};
use ic_nervous_system_integration_tests::pocket_ic_helpers::install_canister;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{NnsInitPayloadsBuilder, build_test_registry_wasm};
use ic_registry_local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStore, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_replicator::RegistryReplicator;
use ic_registry_transport::{
    deserialize_atomic_mutate_response,
    pb::v1::{RegistryMutation, registry_mutation::Type},
    serialize_atomic_mutate_request,
};
use ic_test_utilities_logger::with_test_replica_logger;
use ic_types::{
    RegistryVersion, crypto::threshold_sig::ThresholdSigPublicKey, registry::RegistryClientError,
};
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use rand::{Rng, RngCore};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use url::Url;

const INIT_NUM_VERSIONS: usize = 5;
const TEST_POLL_DELAY: Duration = Duration::from_secs(1);
const DELAY_LEEWAY: Duration = Duration::from_millis(200);

struct PocketIcHelper {
    pocket_ic: PocketIc,
    registry_canister: RegistryCanister,
    nns_pub_key: ThresholdSigPublicKey,
}

impl PocketIcHelper {
    async fn setup() -> (Self, Vec<Url>, ThresholdSigPublicKey) {
        let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
        let mut nns_configuration = NnsInitPayloadsBuilder::new();
        let registry_init_args = nns_configuration
            .with_initial_invariant_compliant_mutations()
            .build()
            .registry;
        install_canister(
            &pocket_ic,
            "Registry",
            REGISTRY_CANISTER_ID,
            Encode!(&registry_init_args).unwrap(),
            build_test_registry_wasm(),
            Some(REGISTRY_CANISTER_ID.get()),
        )
        .await;

        let nns_url = pocket_ic.make_live(None).await;
        let nns_pub_key_bytes = pocket_ic.root_key().await.unwrap();
        let nns_pub_key = parse_threshold_sig_key_from_der(nns_pub_key_bytes.as_slice()).unwrap();

        (
            Self {
                pocket_ic,
                registry_canister: RegistryCanister::new(vec![nns_url.clone()]),
                nns_pub_key,
            },
            vec![nns_url],
            nns_pub_key,
        )
    }

    async fn get_all_certified_records(&self) -> (Vec<RegistryRecord>, RegistryVersion) {
        let (records, latest_version, _t) = self
            .registry_canister
            .get_certified_changes_since(0, &self.nns_pub_key)
            .await
            .unwrap();

        (records, latest_version)
    }

    async fn atomic_mutate(&self, mutation: RegistryMutation) -> Result<u64, String> {
        let encoded_request = serialize_atomic_mutate_request(vec![mutation], vec![]);
        let response = self
            .pocket_ic
            .update_call(
                REGISTRY_CANISTER_ID.into(),
                GOVERNANCE_CANISTER_ID.into(),
                "atomic_mutate",
                encoded_request,
            )
            .await
            .map_err(|e| e.to_string())?;

        deserialize_atomic_mutate_response(response)
            .map_err(|_| "Could not decode response".to_string())
    }
}

// Function duplicate in registry_replicator/src/lib.rs
fn random_init(local_store_path: &Path, n: usize, rng: &mut ReproducibleRng) {
    fn key_mutation(k: usize, rng: &mut ReproducibleRng) -> KeyMutation {
        let s = rng.next_u64() & 64;
        let set: bool = rng.r#gen();
        KeyMutation {
            key: k.to_string(),
            value: if set {
                Some((0..s as u8).collect())
            } else {
                None
            },
        }
    }

    let random_changelog = (0..n)
        .map(|_i| {
            let k = rng.r#gen::<usize>() % 64 + 1;
            (0..k).map(|k| key_mutation(k, rng)).collect()
        })
        .collect::<Changelog>();

    let store = LocalStoreImpl::new(local_store_path);
    for (i, c) in random_changelog.iter().enumerate() {
        store
            .store(RegistryVersion::from((i + 1) as u64), c.clone())
            .unwrap()
    }
}

async fn new_test_replicator(
    num_versions_to_init: Option<usize>,
    nns_urls: Vec<Url>,
    nns_pub_key: Option<ThresholdSigPublicKey>,
) -> RegistryReplicator {
    let local_store_path = TempDir::new().unwrap().keep();

    if let Some(n) = num_versions_to_init {
        random_init(&local_store_path, n, &mut reproducible_rng())
    }

    with_test_replica_logger(|logger| {
        RegistryReplicator::new(
            logger,
            local_store_path,
            TEST_POLL_DELAY,
            nns_urls,
            nns_pub_key,
        )
    })
    .await
}

fn assert_replicator_not_up_to_date_yet(
    replicator: &RegistryReplicator,
    previous_latest_version: RegistryVersion,
    previous_records: &[RegistryRecord],
    new_record: &RegistryRecord,
) {
    assert_registry_client_and_local_store_have_expected_records(
        replicator.get_registry_client().as_ref(),
        replicator.get_local_store().as_ref(),
        previous_latest_version,
        previous_records,
    );

    assert_eq!(
        replicator
            .get_registry_client()
            .get_value(&new_record.key, new_record.version),
        Err(RegistryClientError::VersionNotAvailable {
            version: new_record.version
        })
    );
}

async fn assert_replicator_up_to_date(
    replicator: &RegistryReplicator,
    latest_version: RegistryVersion,
    records: &[RegistryRecord],
    new_record: &RegistryRecord,
) {
    assert_registry_client_and_local_store_have_expected_records(
        replicator.get_registry_client().as_ref(),
        replicator.get_local_store().as_ref(),
        latest_version,
        records,
    );

    assert_eq!(
        replicator
            .get_registry_client()
            .get_value(&new_record.key, new_record.version)
            .unwrap(),
        new_record.value
    );
}

fn assert_registry_client_and_local_store_have_expected_records(
    registry_client: &dyn RegistryClient,
    local_store: &dyn LocalStore,
    expected_latest_version: RegistryVersion,
    expected_records: &[RegistryRecord],
) {
    //
    // Check registry client
    //
    assert_eq!(
        registry_client.get_latest_version(),
        expected_latest_version
    );
    for record in expected_records {
        assert_eq!(
            registry_client
                .get_value(&record.key, record.version)
                .unwrap(),
            record.value
        );
    }

    //
    // Check local store
    //
    let mut expected_changelog: BTreeMap<RegistryVersion, ChangelogEntry> = BTreeMap::new();
    for record in expected_records {
        expected_changelog
            .entry(record.version)
            .or_default()
            .push(KeyMutation {
                key: record.key.clone(),
                value: record.value.clone(),
            });
    }
    assert_eq!(
        expected_changelog.len(),
        expected_latest_version.get() as usize
    );
    assert_eq!(
        local_store
            .get_changelog_since_version(ZERO_REGISTRY_VERSION)
            .unwrap(),
        expected_changelog.values().cloned().collect::<Vec<_>>()
    );
}

async fn random_mutate(pocket_ic: &PocketIcHelper, rng: &mut ReproducibleRng) -> RegistryRecord {
    let (_, version) = pocket_ic.get_all_certified_records().await;
    let key = format!("key_{}", version.get() + 1);
    let value = (0..(rng.next_u64() & 64) as u8).collect::<Vec<_>>();

    let mutation = RegistryMutation {
        mutation_type: Type::Insert as i32,
        key: key.clone().into_bytes(),
        value: value.clone(),
    };

    let new_version = pocket_ic.atomic_mutate(mutation).await.unwrap();

    RegistryRecord {
        key,
        version: RegistryVersion::from(new_version),
        value: Some(value),
    }
}

#[tokio::test]
#[should_panic(expected = "Registry Local Store is empty and no NNS Public Key is provided.")]
async fn test_new_replicator_panics_on_empty_store_without_nns_pub_key() {
    let (_pocket_ic, nns_urls, _nns_pub_key) = PocketIcHelper::setup().await;

    let _replicator = new_test_replicator(None, nns_urls, None).await;
}

#[tokio::test]
#[should_panic(expected = "empty list of URLs passed to RegistryCanister::new()")]
async fn test_new_replicator_panics_on_empty_store_without_nns_urls() {
    let (_pocket_ic, _nns_urls, nns_pub_key) = PocketIcHelper::setup().await;

    let _replicator = new_test_replicator(None, vec![], Some(nns_pub_key)).await;
}

#[tokio::test]
async fn test_poll_is_error_without_nns_pub_key_nor_in_store_nor_in_config() {
    let (_pocket_ic, nns_urls, _nns_pub_key) = PocketIcHelper::setup().await;

    let replicator = new_test_replicator(Some(INIT_NUM_VERSIONS), nns_urls, None).await;

    assert_eq!(
        replicator.poll().await,
        Err("NNS public key not set in the registry and not configured.".to_string())
    );
}

#[tokio::test]
async fn test_poll_is_error_without_nns_urls_nor_in_store_nor_in_config() {
    let (_pocket_ic, _nns_urls, nns_pub_key) = PocketIcHelper::setup().await;

    let replicator = new_test_replicator(Some(INIT_NUM_VERSIONS), vec![], Some(nns_pub_key)).await;

    assert_eq!(
        replicator.poll().await,
        Err("No remote registry canister configured.".to_string())
    );
}

#[tokio::test]
async fn test_poll_and_start_polling_and_stop_polling_correctly_update_local_store_and_client() {
    let mut rng = reproducible_rng();
    let (pocket_ic, nns_urls, nns_pub_key) = PocketIcHelper::setup().await;
    let replicator = new_test_replicator(None, nns_urls, Some(nns_pub_key)).await;
    let token = CancellationToken::new();

    let (records, latest_version) = pocket_ic.get_all_certified_records().await;

    let new_record = random_mutate(&pocket_ic, &mut rng).await;
    tokio::time::sleep(replicator.get_poll_delay() + DELAY_LEEWAY).await;

    // Even though we waited for the poll delay, registry replicator was not set to start
    // polling yet, so local store and client should still contain initial state
    assert_replicator_not_up_to_date_yet(&replicator, latest_version, &records, &new_record);

    // Poll once, local store and client should contain latest changes
    replicator.poll().await.unwrap();

    let (records, latest_version) = pocket_ic.get_all_certified_records().await;
    assert_replicator_up_to_date(&replicator, latest_version, &records, &new_record).await;

    let new_record = random_mutate(&pocket_ic, &mut rng).await;
    tokio::time::sleep(replicator.get_poll_delay() + DELAY_LEEWAY).await;

    // Again, even though we waited for the poll delay, registry replicator was not set to
    // start polling yet, so local store and client should still contain the previous state
    assert_replicator_not_up_to_date_yet(&replicator, latest_version, &records, &new_record);

    //
    // Start polling
    //
    tokio::spawn(replicator.start_polling(token).unwrap());

    // `start_polling` polls the registry canister in the background, so we wait until the
    // replicator has updated to the latest version
    while replicator.get_registry_client().get_latest_version() < new_record.version {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Starting to poll should update local store and client to latest changes
    let (records, latest_version) = pocket_ic.get_all_certified_records().await;
    assert_replicator_up_to_date(&replicator, latest_version, &records, &new_record).await;

    let new_record = random_mutate(&pocket_ic, &mut rng).await;

    // Even though, we started polling, we haven't waited for the poll delay yet, so local store
    // and client should still contain the previous state
    assert_replicator_not_up_to_date_yet(&replicator, latest_version, &records, &new_record);

    tokio::time::sleep(replicator.get_poll_delay() + DELAY_LEEWAY).await;

    // Now that we waited for the poll delay, local store and client should contain latest
    // changes
    let (records, latest_version) = pocket_ic.get_all_certified_records().await;
    assert_replicator_up_to_date(&replicator, latest_version, &records, &new_record).await;

    let new_record = random_mutate(&pocket_ic, &mut rng).await;

    // Again, we haven't waited for the poll delay yet, so local store and client should still
    // contain the previous state
    assert_replicator_not_up_to_date_yet(&replicator, latest_version, &records, &new_record);

    replicator.poll().await.unwrap();

    // But after manually polling, local store and client should contain latest changes
    let (records, latest_version) = pocket_ic.get_all_certified_records().await;
    assert_replicator_up_to_date(&replicator, latest_version, &records, &new_record).await;

    //
    // Stop polling
    //
    replicator.stop_polling();

    let new_record = random_mutate(&pocket_ic, &mut rng).await;
    tokio::time::sleep(replicator.get_poll_delay() + DELAY_LEEWAY).await;

    // After stopping polling, ensure that replicator is indeed not polling after waiting for
    // the poll delay
    assert!(!replicator.is_polling());

    // Since we stopped polling, even though we waited for the poll delay, local store and
    // client should still contain the previous state
    assert_replicator_not_up_to_date_yet(&replicator, latest_version, &records, &new_record);

    // Poll once, local store and client should contain latest changes
    replicator.poll().await.unwrap();

    let (records, latest_version) = pocket_ic.get_all_certified_records().await;
    assert_replicator_up_to_date(&replicator, latest_version, &records, &new_record).await;
}

#[tokio::test]
async fn test_drop_stops_polling() {
    let mut rng = reproducible_rng();
    let (pocket_ic, nns_urls, nns_pub_key) = PocketIcHelper::setup().await;
    let replicator = new_test_replicator(None, nns_urls, Some(nns_pub_key)).await;
    let token = CancellationToken::new();

    let new_record = random_mutate(&pocket_ic, &mut rng).await;

    tokio::spawn(replicator.start_polling(token).unwrap());

    // `start_polling` polls the registry canister in the background, so we wait until the
    // replicator has updated to the latest version
    while replicator.get_registry_client().get_latest_version() < new_record.version {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Ensure that replicator is up to date
    let (records, latest_version) = pocket_ic.get_all_certified_records().await;
    assert_replicator_up_to_date(&replicator, latest_version, &records, &new_record).await;

    // Clone parameters before dropping replicator
    let registry_client = replicator.get_registry_client();
    let local_store = replicator.get_local_store();
    let poll_delay = replicator.get_poll_delay();

    drop(replicator);

    let new_record = random_mutate(&pocket_ic, &mut rng).await;
    tokio::time::sleep(poll_delay + DELAY_LEEWAY).await;

    // Even though we waited for the poll delay, replicator was dropped and thus stopped
    // polling, so local store and client should still contain the previous state
    assert_registry_client_and_local_store_have_expected_records(
        registry_client.as_ref(),
        local_store.as_ref(),
        latest_version,
        &records,
    );

    assert_eq!(
        registry_client.get_value(&new_record.key, new_record.version),
        Err(RegistryClientError::VersionNotAvailable {
            version: new_record.version
        })
    );
}
