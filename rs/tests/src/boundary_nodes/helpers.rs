use std::time::Duration;

use crate::driver::{
    test_env::TestEnv,
    test_env_api::{
        HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, TopologySnapshot,
    },
};

use anyhow::{anyhow, Error};
use futures::future::join_all;
use ic_agent::{export::Principal, Agent};
use ic_base_types::PrincipalId;
use ic_utils::interfaces::ManagementCanister;
use slog::debug;

pub fn get_install_url(env: &TestEnv) -> Result<(url::Url, PrincipalId), Error> {
    let subnet = env
        .topology_snapshot()
        .subnets()
        .next()
        .ok_or_else(|| anyhow!("missing subnet"))?;

    let node = subnet
        .nodes()
        .next()
        .ok_or_else(|| anyhow!("missing node"))?;

    Ok((node.get_public_url(), node.effective_canister_id()))
}

pub async fn create_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    canister_bytes: &[u8],
    arg: Option<Vec<u8>>,
) -> Result<Principal, String> {
    // Create a canister.
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
        .0;

    let mut install_code = mgr.install_code(&canister_id, canister_bytes);
    if let Some(arg) = arg {
        install_code = install_code.with_raw_arg(arg)
    }

    install_code
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't install canister: {}", err))?;

    Ok::<_, String>(canister_id)
}

#[derive(Copy, Clone)]
pub enum BoundaryNodeHttpsConfig {
    /// Acquire a playnet certificate (or fail if all have been acquired already)
    /// for the domain `ic{ix}.farm.dfinity.systems`
    /// where `ix` is the index of the acquired playnet.
    ///
    /// Then create an AAAA record pointing
    /// `ic{ix}.farm.dfinity.systems` to the IPv6 address of the BN.
    ///
    /// Also add CNAME records for
    /// `*.ic{ix}.farm.dfinity.systems` and
    /// `*.raw.ic{ix}.farm.dfinity.systems`
    /// pointing to `ic{ix}.farm.dfinity.systems`.
    ///
    /// If IPv4 has been enabled for the BN (`has_ipv4`),
    /// also add a corresponding A record pointing to the IPv4 address of the BN.
    ///
    /// Finally configure the BN with the playnet certificate.
    ///
    /// Note that if multiple BNs are created within the same
    /// farm-group, they will share the same certificate and
    /// domain name.
    /// Also all their IPv6 addresses will be added to the AAAA record
    /// and all their IPv4 addresses will be added to the A record.
    UseRealCertsAndDns,

    /// Don't create real certificates and DNS records,
    /// instead dangerously accept self-signed certificates and
    /// resolve domains on the client-side without querying DNS.
    AcceptInvalidCertsAndResolveClientSide,
}

pub async fn install_canisters(
    topology: TopologySnapshot,
    canister_bytes: &[u8],
    canisters_count: u32,
) -> Vec<Principal> {
    // Select one node from each subnet.
    let nodes: Vec<IcNodeSnapshot> = topology
        .subnets()
        .map(|subnet| subnet.nodes().next().unwrap())
        .collect();
    // Install canisters in parallel via joining multiple futures.
    let mut futures = vec![];
    for node in nodes.iter() {
        for _ in 0..canisters_count {
            futures.push(async {
                let agent = node.build_default_agent_async().await;
                let effective_canister_id = node.effective_canister_id();
                let mgr = ManagementCanister::create(&agent);
                let (canister_id,) = mgr
                    .create_canister()
                    .as_provisional_create_with_amount(None)
                    .with_effective_canister_id(effective_canister_id)
                    .call_and_wait()
                    .await
                    .map_err(|err| {
                        format!("Couldn't create canister with provisional API: {}", err)
                    })
                    .unwrap();
                let install_code = mgr.install_code(&canister_id, canister_bytes);
                install_code
                    .call_and_wait()
                    .await
                    .map_err(|err| format!("Couldn't install canister: {}", err))
                    .unwrap();
                canister_id
            });
        }
    }
    join_all(futures).await
}

pub async fn set_counters_on_counter_canisters(
    log: &slog::Logger,
    agent: Agent,
    canisters: Vec<Principal>,
    counter_values: Vec<u32>,
    max_attempts: usize,
) {
    // Perform update calls in parallel via multiple futures.
    let mut futures = Vec::new();
    for (idx, canister_id) in canisters.iter().enumerate() {
        let agent = agent.clone();
        let calls = counter_values[idx];
        futures.push(async move {
            for call in 1..calls + 1 {
                let mut attempt = 1;
                let write_result: Vec<u8> = loop {
                    if attempt > max_attempts {
                        panic!("write call on canister={canister_id} failed after {max_attempts} attempts");
                    }
                    let result = agent.update(canister_id, "write").call_and_wait().await;
                    if let Err(err) = result {
                        debug!(log,
                            "write call on canister={canister_id} failed on attempt {attempt}, err: {err:?}",
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    } else {
                        break result.unwrap();
                    }
                    attempt += 1;
                };
                let counter = u32::from_le_bytes(
                    write_result.as_slice()
                        .try_into()
                        .expect("slice with incorrect length"),
                );
                assert_eq!(call, counter);
            }
        });
    }
    join_all(futures).await;
}

pub async fn read_counters_on_counter_canisters(
    log: &slog::Logger,
    agent: Agent,
    canisters: Vec<Principal>,
    max_attempts: usize,
) -> Vec<u32> {
    // Perform query calls in parallel via multiple futures.
    let mut futures = Vec::new();
    for canister_id in canisters {
        let agent = agent.clone();
        futures.push(async move {
            let mut attempt = 1;
            let read_result: Vec<u8> = loop {
                if attempt > max_attempts {
                    panic!("read call on canister={canister_id} failed after {max_attempts} attempts");
                }
                let result = agent.query(&canister_id, "read").call().await;
                if let Err(err) = result {
                    debug!(log,
                        "read call on canister={canister_id} failed on attempt {attempt}, err: {err:?}",
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    break result.unwrap();
                }
                attempt += 1;
            };
            u32::from_le_bytes(
                read_result.as_slice()
                    .try_into()
                    .expect("slice with incorrect length"),
            )
        });
    }
    join_all(futures).await
}
