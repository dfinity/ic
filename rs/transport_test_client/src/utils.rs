//! Helper functionality for the tests

use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_tls_cert_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::{NodeId, PrincipalId, RegistryVersion};
use notify::{watcher, RecursiveMode, Watcher};
use std::convert::TryFrom;
use std::fs;
use std::io::{Read, Result, Write};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Converts the node_id in u8 -> NodeId format
pub fn to_node_id(node_id: u8) -> NodeId {
    let v: Vec<u8> = vec![node_id; 8];
    NodeId::from(PrincipalId::try_from(v.as_slice()).unwrap())
}

// The suggestion is ridiculously complicated and unreadable
#[allow(clippy::needless_range_loop)]
pub fn create_crypto(
    node_index: usize,
    nodes: usize,
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> Result<Arc<dyn TlsHandshake + Send + Sync>> {
    if node_index == 1 {
        for i in 1..(nodes + 1) {
            let filename = format!("tls_pubkey_cert.{}", i);
            if fs::remove_file(filename).is_ok() {
                println!("removing {}", node_id);
            }
        }
    }
    println!("create crypto {}", node_id);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as Arc<_>));
    let (crypto, tls_pubkey_cert) =
        TempCryptoComponent::new_with_tls_key_generation(Arc::clone(&registry) as Arc<_>, node_id);
    {
        let filename = format!("tls_pubkey_cert.{}", node_index);
        println!("writing {}", filename);
        let mut file = fs::File::create(filename).expect("write tls cert");
        file.write_all(tls_pubkey_cert.as_der())?;
    }
    data_provider
        .add(
            &make_crypto_tls_cert_key(node_id),
            registry_version,
            Some(tls_pubkey_cert.to_proto()),
        )
        .expect("failed to add TLS cert to registry");
    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(10)).unwrap();
    watcher.watch("./", RecursiveMode::NonRecursive).unwrap();
    let mut done = vec![true, false, false, false];
    done[node_index] = true;
    let mut ndone = 1;
    // Remove certs when starting node 1.
    for _ in 1..5 {
        for i in 1..(nodes + 1) {
            if done[i] {
                continue;
            }
            let filename = format!("tls_pubkey_cert.{}", i);
            if let Ok(mut file) = fs::File::open(filename.clone()) {
                let mut contents = vec![];
                file.read_to_end(&mut contents)?;
                let peer_id = to_node_id(i as u8);
                data_provider
                    .add(
                        &make_crypto_tls_cert_key(peer_id),
                        registry_version,
                        Some(contents),
                    )
                    .expect("failed to add TLS cert to registry");
                println!("read {}", filename);
                done[i] = true;
                ndone += 1;
            } else {
                println!("unable to open {}", filename);
                // Wait for 3 seconds between retries. Maximum of 5 retries.
                thread::sleep(Duration::from_secs(3))
            }
        }
        println!("ndone = {}", ndone);
        if ndone >= 3 {
            break;
        }
        match rx.recv() {
            Ok(event) => {
                println!("watch {:?}", event);
            }
            Err(e) => {
                println!("watch error: {:?}", e);
            }
        }
    }
    registry.update_to_latest_version();
    Ok(Arc::new(crypto))
}
