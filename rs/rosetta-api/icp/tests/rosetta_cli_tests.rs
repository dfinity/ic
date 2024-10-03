use crate::test_utils::TestLedger;
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::Scribe;
use ic_rosetta_api::request_handler::RosettaRequestHandler;
use ic_rosetta_api::rosetta_server::RosettaApiServer;
use std::process::Command;
use std::sync::Arc;
use tracing::log::debug;

mod test_utils;

fn rosetta_cli() -> String {
    match std::env::var("ROSETTA_CLI").ok() {
        Some(binary) => binary,
        None => String::from("rosetta-cli"),
    }
}

fn local(file: &str) -> String {
    match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(path) => std::path::PathBuf::from(path)
            .join(file)
            .into_os_string()
            .into_string()
            .unwrap(),
        Err(_) => String::from(file),
    }
}

#[actix_rt::test]
async fn rosetta_cli_data_test() {
    let addr = "127.0.0.1:8091".to_string();

    let mut scribe = Scribe::new();
    let num_transactions = 1000;
    let num_accounts = 100;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger.clone());
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    let serv_ledger = ledger.clone();
    let serv_req_handler = req_handler.clone();

    let serv = Arc::new(
        RosettaApiServer::new(serv_ledger, serv_req_handler, addr.clone(), None, false).unwrap(),
    );
    let serv_run = serv.clone();
    let arbiter = actix_rt::Arbiter::new();
    arbiter.spawn(Box::pin(async move {
        debug!("Spawning server");
        serv_run.run(Default::default()).await.unwrap();
        debug!("Server thread done");
    }));

    let output = Command::new(rosetta_cli())
        .args([
            "check:data",
            "--configuration-file",
            local("tests/rosetta-cli_data_test.json").as_str(),
        ])
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        "rosetta-cli did not finish successfully: {},/\
             \n\n--------------------------\nstdout: {}, \
             \n\n--------------------------\nstderr: {}",
        output.status,
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap()
    );

    serv.stop().await;
    arbiter.stop();
    arbiter.join().unwrap();
}

#[actix_rt::test]
async fn rosetta_cli_construction_create_account_test() {
    let addr = "127.0.0.1:8092".to_string();

    let mut scribe = Scribe::new();
    let num_transactions: u32 = 10;

    scribe.add_account(
        "42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5",
        1_000_000_001,
    );
    scribe.add_account(
        "35548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b127",
        1_000_000_001,
    );
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger.clone());
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    let serv_ledger = ledger.clone();
    let serv_req_handler = req_handler.clone();

    let serv = Arc::new(
        RosettaApiServer::new(serv_ledger, serv_req_handler, addr.clone(), None, false).unwrap(),
    );
    let serv_run = serv.clone();
    let arbiter = actix_rt::Arbiter::new();
    arbiter.spawn(Box::pin(async move {
        debug!("Spawning server");
        serv_run.run(Default::default()).await.unwrap();
        debug!("Server thread done");
    }));

    let output = Command::new(rosetta_cli())
        .args([
            "check:construction",
            "--configuration-file",
            local("tests/rosetta-cli_construction_create_account_test.json").as_str(),
        ])
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        "rosetta-cli did not finish successfully: {},/\
             \n\n--------------------------\nstdout: {}, \
             \n\n--------------------------\nstderr: {}",
        output.status,
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap()
    );

    serv.stop().await;
    arbiter.stop();
    arbiter.join().unwrap();
}

#[actix_rt::test]
async fn rosetta_cli_construction_test() {
    let addr = "127.0.0.1:8093".to_string();

    let mut scribe = Scribe::new();
    let num_accounts = 2;

    scribe.gen_accounts(num_accounts, 1_000 * 100_000_000);

    scribe.add_account(
        "35548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b127",
        100_000_000_001,
    );
    scribe.add_account(
        "42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5",
        100_000_000_002,
    );
    scribe.add_account(
        "eaf407f7fa3770edb621ce920f6c83cefb63df333044d1cdcd2a300ceb85cb1c",
        100_000_000_003,
    );
    scribe.add_account(
        "ba5b33d11f93033ba45b0a0136d4f7f6310ee482cfb1cfebdb4cea55f4aeda17",
        100_000_000_004,
    );
    scribe.add_account(
        "776ab0ef12a63f5b1bd605f202b1b5cefeaf5791c0241c773fc8e76a6c4a8b40",
        100_000_000_005,
    );
    scribe.add_account(
        "88bf52d6380bf2ed7b5fd4010afd145dc351cbf386def9b9be017bbeb640a919",
        100_000_000_006,
    );
    scribe.add_account(
        "92c9c807da64528240f65ec29b58c839bf2374e9c1c38b7661da65fd8710124e",
        100_000_000_007,
    );

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger.clone());
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    let serv_ledger = ledger.clone();
    let serv_req_handler = req_handler.clone();

    let serv = Arc::new(
        RosettaApiServer::new(serv_ledger, serv_req_handler, addr.clone(), None, false).unwrap(),
    );
    let serv_run = serv.clone();
    let arbiter = actix_rt::Arbiter::new();
    arbiter.spawn(Box::pin(async move {
        debug!("Spawning server");
        serv_run.run(Default::default()).await.unwrap();
        debug!("Server thread done");
    }));

    let output = Command::new(rosetta_cli())
        .args([
            "check:construction",
            "--configuration-file",
            local("tests/rosetta-cli_construction_test.json").as_str(),
        ])
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        "rosetta-cli did not finish successfully: {},/\
             \n\n--------------------------\nstdout: {}, \
             \n\n--------------------------\nstderr: {}",
        output.status,
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap()
    );

    serv.stop().await;
    arbiter.stop();
    arbiter.join().unwrap();
}
