use structopt::StructOpt;

use ic_crypto_internal_threshold_sig_bls12381 as bls12_381;
use ic_crypto_utils_threshold_sig::parse_threshold_sig_key;
use ic_rosetta_api::rosetta_server::{RosettaApiServer, RosettaApiServerOpt};
use ic_rosetta_api::{
    ledger_client::{self},
    store::SQLiteStore,
    RosettaRequestHandler,
};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{CanisterId, PrincipalId};
use std::{path::Path, path::PathBuf, str::FromStr, sync::Arc};
use url::Url;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    listen_address: String,
    #[structopt(short = "p", long = "port", default_value = "8080")]
    listen_port: u16,
    #[structopt(short = "c", long = "canister-id")]
    ic_canister_id: Option<String>,
    /// Id of the governance canister to use for neuron management.
    #[structopt(short = "g", long = "governance-canister-id")]
    governance_canister_id: Option<String>,
    #[structopt(long = "ic-url")]
    ic_url: Option<String>,
    #[structopt(
        short = "l",
        long = "log-config-file",
        default_value = "log_config.yml"
    )]
    log_config_file: PathBuf,
    #[structopt(long = "root-key")]
    root_key: Option<PathBuf>,
    /// Supported options: sqlite, sqlite-in-memory
    #[structopt(long = "store-type", default_value = "sqlite")]
    store_type: String,
    #[structopt(long = "store-location", default_value = "./data")]
    store_location: PathBuf,
    #[structopt(long = "store-max-blocks")]
    store_max_blocks: Option<u64>,
    #[structopt(long = "exit-on-sync")]
    exit_on_sync: bool,
    #[structopt(long = "offline")]
    offline: bool,
    #[structopt(long = "mainnet", about = "Connect to the Internet Computer Mainnet")]
    mainnet: bool,
    #[structopt(long = "not-whitelisted")]
    not_whitelisted: bool,
    #[structopt(long = "expose-metrics")]
    expose_metrics: bool,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();

    if let Err(e) = log4rs::init_file(opt.log_config_file.as_path(), Default::default()) {
        panic!(
            "rosetta-api failed to load log configuration file: {}, error: {}. (current_dir is: {:?})",
            &opt.log_config_file.as_path().display(),
            e,
            std::env::current_dir()
        );
    }

    let pkg_name = env!("CARGO_PKG_NAME");
    let pkg_version = env!("CARGO_PKG_VERSION");
    log::info!("Starting {}, pkg_version: {}", pkg_name, pkg_version);
    log::info!("Listening on {}:{}", opt.listen_address, opt.listen_port);
    let addr = format!("{}:{}", opt.listen_address, opt.listen_port);

    let (root_key, canister_id, governance_canister_id, url) = if opt.mainnet {
        let root_key = match opt.root_key {
            Some(root_key_path) => parse_threshold_sig_key(root_key_path.as_path())?,
            None => {
                // The mainnet root key
                let root_key_text = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;
                let decoded = base64::decode(root_key_text).unwrap();
                let pubkey_bytes = bls12_381::api::public_key_from_der(&decoded).unwrap();
                ThresholdSigPublicKey::from(pubkey_bytes)
            }
        };

        let canister_id = match opt.ic_canister_id {
            Some(cid) => CanisterId::new(PrincipalId::from_str(&cid[..]).unwrap()).unwrap(),
            None => ic_nns_constants::LEDGER_CANISTER_ID,
        };

        let governance_canister_id = match opt.governance_canister_id {
            Some(cid) => CanisterId::new(PrincipalId::from_str(&cid[..]).unwrap()).unwrap(),
            None => ic_nns_constants::GOVERNANCE_CANISTER_ID,
        };

        let url = match opt.ic_url {
            Some(url) => Url::parse(&url[..]).unwrap(),
            None => {
                if opt.not_whitelisted {
                    Url::parse("https://ic0.app").unwrap()
                } else {
                    Url::parse("https://rosetta-exchanges.ic0.app").unwrap()
                }
            }
        };

        (Some(root_key), canister_id, governance_canister_id, url)
    } else {
        let root_key = match opt.root_key {
            Some(root_key_path) => Some(parse_threshold_sig_key(root_key_path.as_path())?),
            None => {
                log::warn!("Data certificate will not be verified due to missing root key");
                None
            }
        };

        let canister_id = match opt.ic_canister_id {
            Some(cid) => CanisterId::new(PrincipalId::from_str(&cid[..]).unwrap()).unwrap(),
            None => ic_nns_constants::LEDGER_CANISTER_ID,
        };

        let governance_canister_id = match opt.governance_canister_id {
            Some(cid) => CanisterId::new(PrincipalId::from_str(&cid[..]).unwrap()).unwrap(),
            None => ic_nns_constants::GOVERNANCE_CANISTER_ID,
        };

        // Not connecting to the mainnet, so default to the exchanges url
        let url = Url::parse(
            &opt.ic_url
                .unwrap_or_else(|| "https://exchanges.dfinity.network".to_string())[..],
        )
        .unwrap();
        (root_key, canister_id, governance_canister_id, url)
    };

    let store = store(opt.store_type, &opt.store_location);

    let Opt {
        store_max_blocks,
        offline,
        exit_on_sync,
        mainnet,
        not_whitelisted,
        expose_metrics,
        ..
    } = opt;
    let client = ledger_client::LedgerClient::new(
        url,
        canister_id,
        governance_canister_id,
        store,
        store_max_blocks,
        offline,
        root_key,
    )
    .await
    .map_err(|e| {
        let msg = if mainnet && !not_whitelisted && e.is_internal_error_403() {
            ", You may not be whitelisted; please try running the Rosetta server again with the '--not_whitelisted' flag"
        } else {""};
        (e, msg)
    })
    .unwrap_or_else(|(e, is_403)| panic!("Failed to initialize ledger client{}: {:?}", is_403, e));

    let ledger = Arc::new(client);
    let req_handler = RosettaRequestHandler::new(ledger.clone());

    log::info!("Network id: {:?}", req_handler.network_id());
    let serv = RosettaApiServer::new(ledger, req_handler, addr, expose_metrics)
        .expect("Error creating RosettaApiServer");

    // actix server catches kill signals. After that we still need to stop our
    // server properly
    serv.run(RosettaApiServerOpt {
        exit_on_sync,
        offline,
        mainnet,
        not_whitelisted,
    })
    .await
    .unwrap();
    serv.stop().await;
    log::info!("Th-th-th-that's all folks!");
    Ok(())
}

fn store(store_type: String, store_location: &Path) -> SQLiteStore {
    match store_type.as_ref() {
        "sqlite" => sqlite_store(store_location),
        "sqlite-in-memory" | "in-memory" => sqlite_in_memory_store(),
        "on-disk" => {
            log::error!("On-disk storage is not supported anymore.");
            panic!("On-disk storage is not supported anymore.");
        }
        _ => {
            log::error!("Invalid store type: {}", store_type);
            panic!("Invalid store type");
        }
    }
}

fn sqlite_store(store_location: &Path) -> SQLiteStore {
    log::info!("Using SQLite block store");
    SQLiteStore::new_on_disk(store_location).expect("Failed to initialize sqlite on-disk store")
}

fn sqlite_in_memory_store() -> SQLiteStore {
    log::info!("Using in-memory SQLite block store");
    SQLiteStore::new_in_memory().expect("Failed to initialize sqlite in-memory store")
}
