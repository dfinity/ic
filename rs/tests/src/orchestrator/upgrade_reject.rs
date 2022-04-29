/* tag::catalog[]
Title:: Upgrade Reject on a Hash Mismatch

Goal:: Ensure an NNS subnet does not upgrade if the hash of the release package does not match.

Runbook::
. Setup a single-node subnet with NNS canisters
. Trigger an upgrade of the NNS subnet with a broken hash. To that end, we first submit a BlessReplicaVersion proposal for the given (version, upgrade_url, sha256) and then submit an UpdateSubnetReplicaVersion proposal for the same version.
. Make sure the replica version does not change within 8 minutes

Success:: replica version did not change within the specified time

Covered:
. an upgrade of a replica **fails** if the image hash does not match the 'sha256' argument of the BlessReplicaVersion proposal.

NotCovered:
. an upgrade of a replica **succeeds** if the image hash matches the 'sha256' argument of the BlessReplicaVersion proposal.

end::catalog[] */

use std::convert::TryFrom;
use std::time::Duration;

use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;

use crate::driver::ic::{InternetComputer, Subnet};
use ic_base_types::SubnetId;
use ic_fondue::ic_manager::IcHandle;
use ic_nns_common::types::NeuronId;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};

use ic_canister_client::Sender;

use crate::{
    nns::{
        self, await_proposal_execution, await_replica_status_change, get_software_version,
        submit_bless_replica_version_proposal, submit_update_subnet_replica_version_proposal,
        NnsExt,
    },
    orchestrator::utils::upgrade::{get_update_image_url, UpdateImageType},
    util::{get_random_nns_node_endpoint, runtime_from_url},
};

use ic_nns_test_utils::ids::TEST_NEURON_1_ID;

pub fn config() -> InternetComputer {
    // 19 blocks till checkpoint
    InternetComputer::new().add_subnet(
        Subnet::fast_single_node(SubnetType::System).with_dkg_interval_length(Height::from(19)),
    )
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    let mut rng = ctx.rng.clone();

    ctx.install_nns_canisters(&handle, true);

    let endpoint = get_random_nns_node_endpoint(&handle, &mut rng);
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    // This hash is a hardcoded value of "0", which should differ from the hash of
    // the new image.
    let sha256 = String::from("9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa");

    // These are the URL and version of *some* replica image; since we are testing a
    // rejection scenario, it does not matter that it is outdated.
    let git_revision = String::from("72670d259dc14936955d9f722677285a40342e0f");
    let upgrade_url = get_update_image_url(UpdateImageType::ImageTest, &git_revision);
    let version = ReplicaVersion::try_from(format!("{}-test", git_revision)).unwrap();

    rt.block_on(async move {
        endpoint.assert_ready(ctx).await;

        let original_replica_version = get_software_version(endpoint)
            .await
            .expect("Could not obtain software version after installing NNS");

        let nns = runtime_from_url(endpoint.url.clone());
        let governance = nns::get_governance_canister(&nns);

        let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
        let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);

        // submit the 1st proposal to bless the replica version with these (version,
        // sha256, url). Note: The condition "sha256 == hash(curl(url))" is not
        // checked at this point and is purposfully violated in our payload.
        let proposal_id = submit_bless_replica_version_proposal(
            &governance,
            proposal_sender.clone(),
            test_neuron_id,
            version.clone(),
            sha256,
            upgrade_url,
        )
        .await;

        // check that the proposal succeeded
        assert!(
            await_proposal_execution(
                ctx,
                &governance,
                proposal_id,
                Duration::from_millis(200),
                Duration::from_secs(5)
            )
            .await
        );

        let subnet_id: SubnetId = endpoint.subnet_id().unwrap();

        // submit the 2nd proposal to trigger an update of a blessed replica
        let proposal_id = submit_update_subnet_replica_version_proposal(
            &governance,
            proposal_sender.clone(),
            test_neuron_id,
            version.clone(),
            subnet_id,
        )
        .await;

        // check that the proposal succeeded
        assert!(
            await_proposal_execution(
                ctx,
                &governance,
                proposal_id,
                Duration::from_millis(200),
                Duration::from_secs(5)
            )
            .await
        );

        // check installed replica version multiple times to gain confidence that the
        // update did not go through. TODO: how could we strengthen this assertion?

        let version_changed = await_replica_status_change(
            ctx,
            endpoint,
            Duration::from_secs(20),
            Duration::from_secs(6 * 60 + 30),
            |new_status: &ic_agent::agent::status::Status| {
                new_status
                .impl_version
                .as_ref()
                .expect(
                    "Could not obtain software version at the end of the upgrade_reject scenario",
                )
                .ne(&String::from(original_replica_version.clone()))
            },
        )
        .await;

        assert!(!version_changed);
    });
}
