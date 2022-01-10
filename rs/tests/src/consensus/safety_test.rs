/* tag::catalog[]
Title:: Consensus Safety Test

Goal:: Demonstrate that there are no conflicting states for different
replicas in the presence of malicious behavior.

Runbook::
. Set up one subnets with 3f+1 nodes, f of which malicious.
. Install a universal canister in an honest node.
. Continuously push messages to the canister's stable memory
. Pull the last sent message and compare with the expectation.

Success:: Check the messages have really been written to memory
by pulling the last one from a different node.
The `ekg::finalized_hashes_agree` does not detect different
hashes for the same height. This is part of `ekg::basic_monitoring`, and
hence, checked by default.

Coverage::
. Consensus doesn't break in the presence of simple malicious behavior

Caveats and Future Work::
. Add a check that certified state hashes also agree
. Work on a `certified_state_safety_test` where we flip bits of certified state and observe the replica restart.


end::catalog[] */

use crate::util::*;
use ic_agent::export::Principal;
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use rand::Rng;
use slog::{debug, info, Logger};
use url::Url;

pub fn config() -> InternetComputer {
    let malicious_beh = MaliciousBehaviour::new(true)
        .set_maliciously_propose_empty_blocks()
        .set_maliciously_notarize_all()
        .set_maliciously_finalize_all();

    InternetComputer::new().add_subnet(
        Subnet::new(SubnetType::System)
            .add_nodes(3)
            .add_malicious_nodes(1, malicious_beh),
    )
}

pub fn test(mut handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // choose two different nodes to use in our test. Note the handle
    // does _not_ contain handle for malicious nodes, so we are guarnateed
    // to take two honest ones.
    let mut rng = ctx.rng.clone();
    let n1 = handle.take_one(&mut rng).expect("Not enough nodes");
    block_on(n1.assert_ready(ctx));
    let n2 = handle.take_one(&mut rng).expect("Not enough nodes");
    block_on(n2.assert_ready(ctx));

    // Make sure we've selected two different nodes
    assert_ne!(n1.url, n2.url);

    // The test in itself consists in installing the universal canister and
    // pushing a number of messages to stable memory. Finally, we read the
    // last pushed message and check it matches what we expect.
    //
    // We'll run for `n` rounds and expect the stable memory to be:
    //
    //  |   msg1  |    msg2    |     ....    |    msgN    |
    //  0        len         2*len      (n-1)*len        n*len
    //
    debug!(ctx.logger, "Starting tokio::runtime");
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    debug!(ctx.logger, "tokio::runtime successful start");

    let (last_pulled_msg, last_pushed_msg) =
        rt.block_on(do_the_work(&ctx.logger, &mut rng, &n1.url, &n2.url));
    assert_eq!(last_pulled_msg, last_pushed_msg);
}

const MSG_LEN: usize = 8;

async fn do_the_work<R: Rng>(
    logger: &Logger,
    rng: &mut R,
    n1: &Url,
    n2: &Url,
) -> (Vec<u8>, Vec<u8>) {
    debug!(logger, "Starting do_the_work");
    let (rs, last_pushed_msg, ucan) = push_messages_to(logger, rng, n1).await;
    let last_pulled_msg = pull_message_from(logger, rs, n2, ucan).await;
    (last_pulled_msg, last_pushed_msg.to_vec())
}

async fn push_messages_to<R: Rng>(
    logger: &Logger,
    rng: &mut R,
    url: &Url,
) -> (u32, [u8; MSG_LEN], Principal) {
    debug!(logger, "Creating the agent");
    let agent = assert_create_agent(url.as_str()).await;
    debug!(logger, "Preparing to install universal canister");
    let can = UniversalCanister::new(&agent).await;
    info!(
        logger,
        "Installed universal canister";
        "principal" => format!("{:?}", can.canister_id()),
        "url" => url.as_str(),
    );

    info!(logger, "Sending messages to stable storage");
    let rounds: u32 = rng.gen_range(2..5);
    let mut msg: [u8; MSG_LEN] = [0; MSG_LEN];
    for i in 0..rounds {
        rng.fill_bytes(&mut msg);
        can.store_to_stable(i * (MSG_LEN as u32), &msg).await;

        let sleep_t = rng.gen_range(200..1200);
        tokio::time::sleep(std::time::Duration::from_millis(sleep_t)).await;
        debug!(logger, "push_message_to_stable";
                 "message" => format!("{:?}", msg),
                 "sleep" => sleep_t
        );
    }

    (rounds, msg, can.canister_id())
}

async fn pull_message_from(logger: &Logger, rounds: u32, url: &Url, ucan: Principal) -> Vec<u8> {
    info!(
        logger,
        "Reading from universal canister";
        "principal" => format!("{:?}", ucan),
        "url" => url.as_str(),
    );

    let agent = assert_create_agent(url.as_str()).await;
    let can = UniversalCanister::from_canister_id(&agent, ucan);
    let last_msg = can
        .try_read_stable((rounds - 1) * (MSG_LEN as u32), MSG_LEN as u32)
        .await;
    info!(logger, "try_to_read_message_from_stable"; "message" => format!("{:?}", last_msg));
    last_msg
}
