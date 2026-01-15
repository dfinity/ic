/* tag::catalog[]
Title:: Canister signature verification cache test

Goal:: Verify that the cache statistics are sound after performing some n
requests by some m users.

Start an IC with 3 subnets, 1 node per subnet. Install NNS, II and a counter
canister on different subnets. Issue identities for the users delegated from the II canister.
Between issuing delegations for the 1st and 2nd users, ensure that the certified height
of the II subnet increases to ensure a different BLS signature for the 2nd user which
enables additional tests (see below). Make update (increasing the count) and
query (checking the count) calls for each user to the counter canister. Then, scrape p8s data
from the node directly, fetching the cache statistics. Finally, check that the cache statistics are sound:
- cache size == number of cache misses
- number of cache misses is between 2 and number of users + 1
- number of cache hits + number of cache misses equals number of BLS sig verification per
  request * user_id * number of calls per user, for each user
- for the 1st user, number of cache misses is exactly 2
- for the 1st user, implicitly ensures the correct number of cache hits after *each* counter canister call
- for the 2nd user, number of cache misses is exactly 3
end::catalog[] */

use anyhow::Result;
use candid::Principal;
use core::ops::RangeInclusive;
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, Identity};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::InternetComputer;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    IcNodeSnapshot,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::delegations::*;
use ic_system_test_driver::util::{
    MetricsFetcher, agent_with_identity, block_on, random_ed25519_identity,
};
use ic_types::messages::Blob;
use rand::Rng;
use serde_bytes::ByteBuf;
use slog::info;
use std::env;
use std::time::Duration;

const HITS_STR: &str = "crypto_bls12_381_sig_cache_hits";
const MISSES_STR: &str = "crypto_bls12_381_sig_cache_misses";
const SIZE_STR: &str = "crypto_bls12_381_sig_cache_size";
/// in the current implementation, for a single-replica subnet, a user call requires
/// 8 BLS signature verifications for updating the counter of the counter canister
const NUM_BLS_SIG_VERS_PER_CALL: usize = 8;

/// delay for retrying a failed action in this test
const RETRY_DELAY: Duration = Duration::from_secs(1);
const NUM_RETRIES: usize = 100;

/// Range for the random initialization of the number of users in this test
const NUM_USERS_RANGE: RangeInclusive<usize> = 5..=10;
/// Range for the random initialization of the number of calls per user in this test
const NUM_CALLS_PER_USER_RANGE: RangeInclusive<usize> = 5..=10;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    // one system subnet for NNS
    // another system subnet for II
    // and the application subnet for the counter canister
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let ii_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let ii_canister_id = install_ii_canister(&env, &ii_node);
    let ctr_canister_id = install_counter_canister(&env, &app_node);

    let mut rng = ReproducibleRng::new();
    info!(env.logger(), "Generated a ReproducibleRng\n{rng:?}");

    let num_users = rng.gen_range(NUM_USERS_RANGE);
    let num_calls_per_user = rng.gen_range(NUM_CALLS_PER_USER_RANGE);
    info!(
        env.logger(),
        "Randomly generated num_users={num_users} and num_calls_per_user={num_calls_per_user}"
    );
    block_on(async move {
        let (delegation_identities, users) =
            new_random_users(&env, num_users, &ii_node, ii_canister_id, ctr_canister_id).await;
        let app_agents_with_delegation: Vec<_> = delegation_identities
            .iter()
            .zip(users.iter())
            .map(|(delegation_identity, user)| AgentWithDelegation {
                node_url: app_node.get_public_url(),
                pubkey: user.ii_derived_public_key.clone(),
                signed_delegation: user.signed_delegation.clone(),
                delegation_identity,
                polling_timeout: UPDATE_POLLING_TIMEOUT,
            })
            .collect();

        for user_i in 0..num_users {
            for call_j in 0..num_calls_per_user {
                increment_counter_canister(
                    &env,
                    &app_agents_with_delegation[..],
                    ctr_canister_id,
                    user_i,
                    call_j,
                )
                .await;
                // check after each call only for the first user
                if user_i == 0 {
                    scrape_metrics_and_check_cache_stats(&env, user_i, call_j).await;
                }
            }
            // for efficiency, check only once for all other users
            if user_i != 0 {
                scrape_metrics_and_check_cache_stats(&env, user_i, num_calls_per_user - 1).await;
            }
        }
    });
}

fn install_ii_canister(env: &TestEnv, ii_node: &IcNodeSnapshot) -> Principal {
    let ii_canister_id = ii_node.create_and_install_canister_with_arg(
        &env::var("II_WASM_PATH").expect("II_WASM_PATH not set"),
        None,
    );
    info!(
        env.logger(),
        "II canister with id={ii_canister_id} installed on subnet with id={}",
        ii_node.subnet_id().unwrap()
    );
    ii_canister_id
}

fn install_counter_canister(env: &TestEnv, app_node: &IcNodeSnapshot) -> Principal {
    let canister_id = app_node.create_and_install_canister_with_arg(COUNTER_CANISTER_WAT, None);
    info!(
        env.logger(),
        "Counter canister with id={canister_id} installed on subnet with id={}",
        app_node.subnet_id().unwrap()
    );
    canister_id
}

struct UserData {
    pub signed_delegation: SignedDelegation,
    pub ii_derived_public_key: ByteBuf,
}

async fn new_random_users(
    env: &TestEnv,
    num_users: usize,
    ii_node: &IcNodeSnapshot,
    ii_canister_id: Principal,
    ctr_canister_id: Principal,
) -> (Vec<BasicIdentity>, Vec<UserData>) {
    let user_ii_agents = ii_agents_for_new_random_users(num_users, ii_node, ii_canister_id).await;
    info!(env.logger(), "{num_users} users registered successfully");

    let (delegation_identities, signed_delegations, ii_derived_public_keys) =
        new_random_delegations(
            env,
            &user_ii_agents[..],
            ctr_canister_id,
            ii_canister_id,
            ii_node,
        )
        .await;
    info!(env.logger(), "Delegations received");

    (
        delegation_identities,
        signed_delegations
            .into_iter()
            .zip(ii_derived_public_keys)
            .map(|(signed_delegation, ii_derived_public_key)| UserData {
                signed_delegation,
                ii_derived_public_key,
            })
            .collect(),
    )
}

async fn ii_agents_for_new_random_users(
    num_users: usize,
    ii_node: &IcNodeSnapshot,
    ii_canister_id: Principal,
) -> Vec<Agent> {
    let mut agents = Vec::with_capacity(num_users);
    for i in 0..num_users as u64 {
        let user_identity = random_ed25519_identity();
        let pubkey = copy_pk(&user_identity);
        let ii_agent = agent_with_identity(ii_node.get_public_url().as_str(), user_identity)
            .await
            .unwrap();
        register_user(&ii_agent, pubkey, ii_canister_id, USER_NUMBER_OFFSET + i).await;
        agents.push(ii_agent);
    }
    agents
}

async fn new_random_delegations(
    env: &TestEnv,
    user_ii_agents: &[Agent],
    ctr_canister_id: Principal,
    ii_canister_id: Principal,
    ii_node: &IcNodeSnapshot,
) -> (Vec<BasicIdentity>, Vec<SignedDelegation>, Vec<ByteBuf>) {
    let mut delegation_identities = Vec::with_capacity(user_ii_agents.len());
    let mut signed_delegations = Vec::with_capacity(user_ii_agents.len());
    let mut ii_derived_pks = Vec::with_capacity(user_ii_agents.len());
    let mut first_certified_height = None;
    for i in 0..user_ii_agents.len() {
        if i == 1 {
            while ii_node.status().unwrap().certified_height.unwrap()
                == first_certified_height.unwrap()
            {
                info!(
                    env.logger(),
                    "Waiting for ii subnet to advance its certified height s.t. the second \
                    user's session key delegation has a distinct BLS signature"
                );
                std::thread::sleep(RETRY_DELAY);
            }
        }
        delegation_identities.push(random_ed25519_identity());
        let delegation_pubkey = copy_pk(&delegation_identities[i]);
        let frontend_hostname = format!("https://{}.ic0.app", ctr_canister_id.to_text());
        let (signed_delegation, ii_derived_pk) = create_delegation(
            &user_ii_agents[i],
            delegation_pubkey.clone(),
            ii_canister_id,
            frontend_hostname.clone(),
            USER_NUMBER_OFFSET + i as u64,
        )
        .await;
        signed_delegations.push(signed_delegation);
        ii_derived_pks.push(ii_derived_pk);
        if i == 0 {
            first_certified_height = ii_node.status().unwrap().certified_height;
        }
    }
    (delegation_identities, signed_delegations, ii_derived_pks)
}

fn copy_pk(identity: &BasicIdentity) -> Vec<u8> {
    identity.public_key().unwrap()
}

async fn increment_counter_canister(
    env: &TestEnv,
    app_agents_with_delegation: &[AgentWithDelegation<'_>],
    ctr_canister_id: Principal,
    user_i: usize,
    call_j: usize,
) {
    info!(
        env.logger(),
        "Making an update call #{call_j} for user #{user_i} on counter canister with delegation (increment counter)"
    );
    let _ = app_agents_with_delegation[user_i]
        .update(&ctr_canister_id, "write", Blob(vec![]))
        .await;
}

async fn scrape_metrics_and_check_cache_stats(env: &TestEnv, user_i: usize, call_j: usize) {
    info!(
        env.logger(),
        "Scraping metrics and checking cache stats for user={user_i}, call={call_j}"
    );
    let app_subnet = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap();
    let metrics = MetricsFetcher::new(
        app_subnet.nodes(),
        vec![HITS_STR.into(), MISSES_STR.into(), SIZE_STR.into()],
    );
    let mut count_fetching_metrics: usize = 0;
    let mut count_waiting_for_expected_values: usize = 0;
    loop {
        match metrics.fetch::<u64>().await {
            Ok(val) => {
                let num_cache_hits = val[HITS_STR][0];
                let num_cache_misses = val[MISSES_STR][0];
                let cache_size = val[SIZE_STR][0];
                if (num_cache_hits + num_cache_misses) as usize
                    == (NUM_BLS_SIG_VERS_PER_CALL * (user_i + 1) * (call_j + 1))
                {
                    assert_eq!(
                        cache_size, num_cache_misses,
                        "the cache size is large s.t. all misses should be stored in the cache"
                    );
                    assert!(
                        num_cache_misses >= 2,
                        "at least 2 signatures: subnet delegation and a sig for `certified_data`, but found {num_cache_misses}"
                    );
                    assert!(
                        num_cache_misses as usize <= user_i + 2,
                        "at most `{} + 1` delegations: 1 x subnet delegation and up to `num_users` sigs for `certified_data`, \
                        but found {num_cache_misses}",
                        user_i + 1,
                    );
                    if user_i == 0 {
                        assert!(
                            num_cache_misses == 2,
                            "for the 1st user it is guaranteed that there are only 2 distinct signatures, hence exactly 2 cache misses, \
                            but found {num_cache_misses}"
                        );
                    }
                    if user_i == 1 {
                        assert!(
                            num_cache_misses == 3,
                            "for the 2nd user it is guaranteed that there are only 3 distinct signatures, hence exactly 3 cache misses, \
                            but found {num_cache_misses}"
                        );
                    }
                    break;
                } else {
                    count_waiting_for_expected_values += 1;
                    if count_waiting_for_expected_values > NUM_RETRIES {
                        panic!(
                            "Expected cache state was not observed after {NUM_RETRIES} retries \
                            each with the timeout of {} secs",
                            RETRY_DELAY.as_secs_f64()
                        )
                    }

                    info!(
                        env.logger(),
                        "For user={user_i} after call={call_j}, \
                        observed (num_cache_hits={num_cache_hits}, num_cache_misses={num_cache_misses}, cache_size={cache_size}) = \
                        with num_cache_hits + num_cache_misses = {} \
                        while expecting (NUM_BLS_SIG_VERS_PER_CALL * (user + 1) * (call + 1)) = {} -> Retrying \
                        {count_waiting_for_expected_values}/{NUM_RETRIES}",
                        num_cache_hits + num_cache_misses,
                        (NUM_BLS_SIG_VERS_PER_CALL * (user_i + 1) * (call_j + 1))
                    );
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
            Err(err) => {
                info!(
                    env.logger(),
                    "Could not connect to metrics yet {err:?}, \
                    retrying {count_waiting_for_expected_values}/{NUM_RETRIES}"
                );
            }
        }
        count_fetching_metrics += 1;
        if count_fetching_metrics > NUM_RETRIES {
            panic!(
                "Failed to connect to metrics after {NUM_RETRIES} retries
                each with the timeout of {} secs",
                RETRY_DELAY.as_secs_f64()
            )
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
}
