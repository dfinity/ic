use std::time::Duration;

use anyhow::{anyhow, bail, Context, Error};
use futures::future::join_all;
use ic_agent::{export::Principal, Agent};
use ic_base_types::PrincipalId;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, TopologySnapshot,
        },
    },
    retry_with_msg_async,
};
use ic_utils::interfaces::ManagementCanister;

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
    backoff: Duration,
    retry_timeout: Duration,
) {
    let mut requests = vec![];
    for (idx, canister_id) in canisters.into_iter().enumerate() {
        let calls_count = counter_values[idx];
        for _ in 0..calls_count {
            let agent_clone = agent.clone();

            let request = move || {
                let agent_clone = agent_clone.clone();

                async move {
                    agent_clone
                        .update(&canister_id, "write")
                        .call_and_wait()
                        .await
                        .map(|_| ())
                        .with_context(|| "write call failed")
                }
            };

            let request = retry_with_msg_async!(
                format!("write call on canister={canister_id}"),
                log,
                retry_timeout,
                backoff,
                request
            );

            requests.push(request);
        }
    }

    // Dispatch all requests in parallel.
    futures::future::try_join_all(requests).await.unwrap();
}

pub async fn read_counters_on_counter_canisters(
    log: &slog::Logger,
    agent: Agent,
    canisters: Vec<Principal>,
    backoff: Duration,
    retry_timeout: Duration,
) -> Vec<u32> {
    // Perform query read calls on canisters sequentially.
    let mut results = vec![];
    for canister_id in canisters {
        let read_result = ic_system_test_driver::retry_with_msg_async!(
            format!("call read on canister={canister_id}"),
            log,
            retry_timeout,
            backoff,
            || async {
                let read_result = agent.query(&canister_id, "read").call().await;
                if let Ok(bytes) = read_result {
                    Ok(bytes)
                } else {
                    bail!(
                        "read call on canister={canister_id} failed, err: {:?}",
                        read_result.unwrap_err()
                    )
                }
            }
        )
        .await
        .expect("read call on canister={canister_id} failed after {max_attempts} attempts");

        let counter = u32::from_le_bytes(
            read_result
                .as_slice()
                .try_into()
                .expect("slice with incorrect length"),
        );

        results.push(counter)
    }
    results
}
