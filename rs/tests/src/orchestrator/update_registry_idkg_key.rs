/* tag::catalog[]

Title:: Update the registry with the previously missing iDKG keys

Goal:: Ensure that we can at a later stage set the iDKG keys in the registry.

Description::
We deploy an IC without iDKG keys. Then we let the orchestrator run until they
are all set. Then check if they were set properly by examining the registry
version history.

Runbook::
. Deploy an IC without iDKG keys and let it run for a while.
. Wait until the registry reaches version 3.
. Check both NNS and application node for iDKG key presence at each version of
  the registry.

Success::
. On version 1 of the registry both keys should be missing.
. On version 2 only one should be present.
. On version 3 both keys should be present.

end::catalog[] */

use core::time;
use std::thread;

use crate::driver::ic::InternetComputer;
use crate::nns::NnsExt;
use crate::util::{block_on, get_random_application_node_endpoint, get_random_nns_node_endpoint};
use ic_base_types::NodeId;
use ic_fondue::{ic_manager::IcHandle, pot::Context};
use ic_registry_keys::make_crypto_node_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_types::crypto::KeyPurpose;

pub fn config() -> InternetComputer {
    InternetComputer::new()
        .without_idkg_key()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
}

pub fn test(handle: IcHandle, ctx: &Context) {
    let mut rng = ctx.rng.clone();

    ctx.install_nns_canisters(&handle, true);
    let nns_node = get_random_nns_node_endpoint(&handle, &mut rng);
    block_on(nns_node.assert_ready(ctx));

    let app_node = get_random_application_node_endpoint(&handle, &mut rng);
    block_on(app_node.assert_ready(ctx));

    let registry_canister = RegistryCanister::new(vec![nns_node.url.clone()]);

    // wait 2 minutes for the registry to reach to a version 3
    let mut i = 0;
    let version_3_reached = loop {
        i += 1;
        if i > 60 {
            break false;
        }
        if block_on(registry_canister.get_latest_version()) == Ok(3u64) {
            break true;
        }
        thread::sleep(time::Duration::from_secs(2));
    };
    assert!(version_3_reached);

    // fetch the state at registry version 1,
    let pk_app_1 = block_on(get_public_key(&registry_canister, app_node.node_id, 1));
    let pk_nns_1 = block_on(get_public_key(&registry_canister, nns_node.node_id, 1));
    // then version 2,
    let pk_app_2 = block_on(get_public_key(&registry_canister, app_node.node_id, 2));
    let pk_nns_2 = block_on(get_public_key(&registry_canister, nns_node.node_id, 2));
    // and version 3
    let pk_app_3 = block_on(get_public_key(&registry_canister, app_node.node_id, 3));
    let pk_nns_3 = block_on(get_public_key(&registry_canister, nns_node.node_id, 3));

    // both application and NNS nodes had no iDKG key initially...
    assert!(pk_app_1.is_err());
    assert!(pk_nns_1.is_err());
    // first one of them got it...
    assert!(pk_app_2.is_ok() != pk_nns_2.is_ok());
    // then the other one got it too.
    assert!(pk_app_3.is_ok());
    assert!(pk_nns_3.is_ok());
}

async fn get_public_key(
    registry_canister: &RegistryCanister,
    node_id: NodeId,
    version: u64,
) -> Result<Vec<u8>, String> {
    match registry_canister
        .get_value(
            make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption)
                .as_bytes()
                .to_vec(),
            Some(version),
        )
        .await
    {
        Ok(public_key) => {
            if public_key.0.is_empty() {
                Err("Error: empty value.".to_string())
            } else {
                Ok(public_key.0)
            }
        }
        Err(err) => Err(err.to_string()),
    }
}
