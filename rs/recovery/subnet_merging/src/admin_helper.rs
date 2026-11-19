use ic_base_types::SubnetId;
use ic_recovery::admin_helper::{AdminHelper, CommandHelper, IcAdmin, SUMMARY_ARG, quote};
use ic_types::Height;

use std::time::SystemTime;

const SUBNET_ARG: &str = "subnet";
const SOURCE_SUBNET_ARG: &str = "source-subnet";
const DESTINATION_SUBNET_ARG: &str = "destination-subnet";

/// Propose to label the subnet as "cooling down".
pub(crate) fn get_propose_to_cool_down_subnet_command(
    admin_helper: &AdminHelper,
    subnet_id: SubnetId,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();

    ic_admin
        .add_positional_argument("propose-to-update-subnet")
        .add_argument(SUBNET_ARG, subnet_id)
        .add_argument(
            SUMMARY_ARG,
            quote(format!("Label subnet {subnet_id} as cooling down")),
        )
        .add_argument("cooling-down", true);

    admin_helper.add_proposer_args(&mut ic_admin);

    ic_admin
}

/// Propose to reroute the canister ID ranges of the source subnet to the
/// destination subnet, i.e. to merge the former into the latter.
pub(crate) fn get_propose_to_merge_subnets_command(
    admin_helper: &AdminHelper,
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();

    ic_admin
        .add_positional_argument("propose-to-merge-subnets")
        .add_argument(
            SUMMARY_ARG,
            quote(format!(
                "Merge subnet {source_subnet_id} into subnet {destination_subnet_id}",
            )),
        )
        .add_argument(SOURCE_SUBNET_ARG, source_subnet_id)
        .add_argument(DESTINATION_SUBNET_ARG, destination_subnet_id);

    admin_helper.add_proposer_args(&mut ic_admin);

    ic_admin
}

/// Propose the recovery CUP of the destination subnet at the merged state,
/// with a summary naming the merge rather than a plain subnet recovery.
pub(crate) fn get_propose_recovery_cup_command(
    admin_helper: &AdminHelper,
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
    height: Height,
    state_hash: String,
    time: SystemTime,
) -> IcAdmin {
    admin_helper.get_propose_to_update_recovery_cup_command(
        destination_subnet_id,
        height,
        state_hash,
        /*initial_dkg_subnet_id=*/ None,
        /*chain_key_config=*/ None,
        /*replacement_nodes=*/ &[],
        /*registry_params=*/ None,
        Some(format!(
            "Recover subnet {destination_subnet_id} at the state merged from it and subnet \
             {source_subnet_id}, which is merged into it",
        )),
        time,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_base_types::PrincipalId;
    use url::Url;

    use std::{path::PathBuf, str::FromStr};

    const FAKE_IC_ADMIN: &str = "/fake/ic/admin/dir/ic-admin";
    const FAKE_NNS_URL: &str = "https://fake_nns_url.com:8080";
    const FAKE_SUBNET_ID_1: &str =
        "gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe";
    const FAKE_SUBNET_ID_2: &str =
        "mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe";

    #[test]
    fn get_propose_to_cool_down_subnet_command_test() {
        let result = get_propose_to_cool_down_subnet_command(
            &fake_admin_helper(),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-subnet \
            --subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --summary \"Label subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe as cooling down\" \
            --cooling-down true \
            --test-neuron-proposer"
        );
    }

    #[test]
    fn get_propose_to_merge_subnets_command_test() {
        let result = get_propose_to_merge_subnets_command(
            &fake_admin_helper(),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
            subnet_id_from_str(FAKE_SUBNET_ID_2),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-merge-subnets \
            --summary \"Merge subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe into subnet mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe\" \
            --source-subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --destination-subnet mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe \
            --test-neuron-proposer"
        );
    }

    #[test]
    fn get_propose_recovery_cup_command_test() {
        let result = get_propose_recovery_cup_command(
            &fake_admin_helper(),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
            subnet_id_from_str(FAKE_SUBNET_ID_2),
            Height::from(666),
            "fake_state_hash".to_string(),
            std::time::UNIX_EPOCH + std::time::Duration::from_nanos(123456),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-recovery-cup \
            --subnet-index mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe \
            --height 666 \
            --state-hash fake_state_hash \
            --summary \"Recover subnet mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe at the state merged from it and subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe, which is merged into it\" \
            --time-ns 123456 \
            --test-neuron-proposer"
        );
    }

    fn fake_admin_helper() -> AdminHelper {
        AdminHelper::new(
            PathBuf::from(FAKE_IC_ADMIN),
            Url::try_from(FAKE_NNS_URL).unwrap(),
            /*neuron_args=*/ None,
        )
    }

    fn subnet_id_from_str(subnet_id: &str) -> SubnetId {
        PrincipalId::from_str(subnet_id)
            .map(SubnetId::from)
            .unwrap()
    }
}
