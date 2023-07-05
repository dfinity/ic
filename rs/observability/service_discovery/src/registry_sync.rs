use futures::TryFutureExt;
use std::{
    ops::Add,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use ic_interfaces_registry::{RegistryClient, RegistryValue, ZERO_REGISTRY_VERSION};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_registry_client::client::ThresholdSigPublicKey;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_common_proto::pb::local_store::v1::{
    ChangelogEntry as PbChangelogEntry, KeyMutation as PbKeyMutation, MutationType,
};
use ic_registry_keys::{make_crypto_threshold_signing_pubkey_key, ROOT_SUBNET_ID_KEY};
use ic_registry_local_store::{
    Changelog, ChangelogEntry, KeyMutation, LocalStoreImpl, LocalStoreWriter,
};
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_types::{PrincipalId, RegistryVersion, SubnetId};
use registry_canister::mutations::common::decode_registry_value;
use slog::{error, info, Logger};
use url::Url;

pub async fn sync_local_registry(
    log: Logger,
    local_path: PathBuf,
    nns_urls: Vec<Url>,
    use_current_version: bool,
    public_key: Option<ThresholdSigPublicKey>,
) {
    let start = Instant::now();
    let local_store = Arc::new(LocalStoreImpl::new(local_path.clone()));
    let registry_canister = RegistryCanister::new(nns_urls);

    let mut latest_version = if !Path::new(&local_path).exists() {
        ZERO_REGISTRY_VERSION
    } else {
        let registry_cache = FakeRegistryClient::new(local_store.clone());
        registry_cache.update_to_latest_version();
        registry_cache.get_latest_version()
    };
    info!(
        log,
        "Syncing registry version from version : {}", latest_version
    );

    if use_current_version && latest_version != ZERO_REGISTRY_VERSION {
        info!(log, "Skipping syncing with registry, using local version");
        return;
    } else if use_current_version {
        info!(
            log,
            "Unable to use current version of registry since its a zero registry version"
        );
    }

    let mut latest_certified_time = 0;
    let mut updates = vec![];
    let nns_public_key = match public_key {
        Some(pk) => Ok(pk),
        _ => nns_public_key(&registry_canister)
            .await
            .map_err(|e| anyhow::format_err!("Failed to get nns_public_key: {}", e)),
    };

    loop {
        if match registry_canister.get_latest_version().await {
            Ok(v) => {
                info!(log, "Latest registry version: {}", v);
                v == latest_version.get()
            }
            Err(e) => {
                error!(log, "Failed to get latest registry version: {}", e);
                false
            }
        } {
            break;
        }

        if let Ok((mut initial_records, _, t)) = registry_canister
            .get_certified_changes_since(latest_version.get(), nns_public_key.as_ref().unwrap())
            .await
        {
            initial_records.sort_by_key(|r| r.version);
            let changelog = initial_records
                .iter()
                .fold(Changelog::default(), |mut cl, r| {
                    let rel_version = (r.version - latest_version).get();
                    if cl.len() < rel_version as usize {
                        cl.push(ChangelogEntry::default());
                    }
                    cl.last_mut().unwrap().push(KeyMutation {
                        key: r.key.clone(),
                        value: r.value.clone(),
                    });
                    cl
                });

            let versions_count = changelog.len();

            changelog.into_iter().enumerate().for_each(|(i, ce)| {
                let v = RegistryVersion::from(i as u64 + 1 + latest_version.get());
                let local_registry_path = local_path.clone();
                updates.push(async move {
                    let path_str = format!("{:016x}.pb", v.get());
                    let v_path = &[
                        &path_str[0..10],
                        &path_str[10..12],
                        &path_str[12..14],
                        &path_str[14..19],
                    ]
                    .iter()
                    .collect::<PathBuf>();

                    let path = local_registry_path.join(v_path.as_path());
                    tokio::fs::create_dir_all(path.clone().parent().unwrap())
                        .and_then(|_| async {
                            tokio::fs::write(
                                path,
                                PbChangelogEntry {
                                    key_mutations: ce
                                        .iter()
                                        .map(|km| {
                                            let mutation_type = if km.value.is_some() {
                                                MutationType::Set as i32
                                            } else {
                                                MutationType::Unset as i32
                                            };
                                            PbKeyMutation {
                                                key: km.key.clone(),
                                                value: km.value.clone().unwrap_or_default(),
                                                mutation_type,
                                            }
                                        })
                                        .collect(),
                                }
                                .encode_to_vec(),
                            )
                            .await
                        })
                        .await
                })
            });

            latest_version = latest_version.add(RegistryVersion::new(versions_count as u64));

            latest_certified_time = t.as_nanos_since_unix_epoch();
            info!(log, "Initial sync reached version {}", latest_version);
        }
    }

    futures::future::join_all(updates).await;
    local_store
        .update_certified_time(latest_certified_time)
        .unwrap();
    info!(
        log,
        "Synced all registry versions in : {:?}",
        start.elapsed()
    )
}

async fn nns_public_key(
    registry_canister: &RegistryCanister,
) -> anyhow::Result<ThresholdSigPublicKey> {
    let (nns_subnet_id_vec, _) = registry_canister
        .get_value(ROOT_SUBNET_ID_KEY.as_bytes().to_vec(), None)
        .await
        .map_err(|e| anyhow::format_err!("failed to get root subnet: {}", e))?;
    let nns_subnet_id =
        decode_registry_value::<ic_protobuf::types::v1::SubnetId>(nns_subnet_id_vec);
    let (nns_pub_key_vec, _) = registry_canister
        .get_value(
            make_crypto_threshold_signing_pubkey_key(SubnetId::new(
                PrincipalId::try_from(nns_subnet_id.principal_id.unwrap().raw).unwrap(),
            ))
            .as_bytes()
            .to_vec(),
            None,
        )
        .await
        .map_err(|e| anyhow::format_err!("failed to get public key: {}", e))?;
    Ok(ThresholdSigPublicKey::try_from(
        PublicKey::decode(nns_pub_key_vec.as_slice()).expect("invalid public key"),
    )
    .expect("failed to create thresholdsig public key"))
}
