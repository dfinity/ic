use crate::utils::canister_id_range_to_string;

use ic_base_types::SubnetId;
use ic_recovery::admin_helper::{
    AdminHelper, CommandHelper, IcAdmin, SSH_READONLY_ACCESS_ARG, SUMMARY_ARG, quote,
};
use ic_registry_routing_table::CanisterIdRange;

const SOURCE_SUBNET_ARG: &str = "source-subnet";
const DESTINATION_SUBNET_ARG: &str = "destination-subnet";
const CANISTER_ID_RANGES_ARG: &str = "canister-id-ranges";
const MIGRATION_TRACE_ARG: &str = "migration-trace";

/// Propose additions or updates to `canister_migrations`.
///
/// Step 1 of canister migration.
pub(crate) fn get_propose_to_prepare_canister_migration_command(
    admin_helper: &AdminHelper,
    canister_id_ranges: &[CanisterIdRange],
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();

    ic_admin
        .add_positional_argument("propose-to-prepare-canister-migration")
        .add_argument(SUMMARY_ARG, quote("Add canister migration entry"))
        .add_argument(SOURCE_SUBNET_ARG, source_subnet_id)
        .add_argument(DESTINATION_SUBNET_ARG, destination_subnet_id)
        .add_arguments(
            CANISTER_ID_RANGES_ARG,
            canister_id_ranges.iter().map(canister_id_range_to_string),
        );

    admin_helper.add_proposer_args(&mut ic_admin);

    ic_admin
}

/// Propose to modify the routing table.
///
/// Step 2 of canister migration.
pub(crate) fn get_propose_to_reroute_canister_ranges_command(
    admin_helper: &AdminHelper,
    canister_id_ranges: &[CanisterIdRange],
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();

    ic_admin
        .add_positional_argument("propose-to-reroute-canister-ranges")
        .add_argument(SUMMARY_ARG, quote("Add canister migration entry"))
        .add_argument(SOURCE_SUBNET_ARG, source_subnet_id)
        .add_argument(DESTINATION_SUBNET_ARG, destination_subnet_id)
        .add_arguments(
            CANISTER_ID_RANGES_ARG,
            canister_id_ranges.iter().map(canister_id_range_to_string),
        );

    admin_helper.add_proposer_args(&mut ic_admin);

    ic_admin
}

/// Propose to remove entries from `canister_migrations`.
///
/// Step 3 of canister migration.
pub(crate) fn get_propose_to_complete_canister_migration_command(
    admin_helper: &AdminHelper,
    canister_id_ranges: &[CanisterIdRange],
    source_subnet_id: SubnetId,
    destination_subnet_id: SubnetId,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();

    ic_admin
        .add_positional_argument("propose-to-complete-canister-migration")
        .add_argument(SUMMARY_ARG, quote("Complete canister migration"))
        .add_arguments(
            MIGRATION_TRACE_ARG,
            [source_subnet_id, destination_subnet_id],
        )
        .add_arguments(
            CANISTER_ID_RANGES_ARG,
            canister_id_ranges.iter().map(canister_id_range_to_string),
        );

    admin_helper.add_proposer_args(&mut ic_admin);

    ic_admin
}

/// Propose to make the Subnet halt after reaching the next CUP height.
///
/// Optionally adds a ssh-readonly-access key to the Subnet.
pub(crate) fn get_halt_subnet_at_cup_height_command(
    admin_helper: &AdminHelper,
    subnet_id: SubnetId,
    key: &Option<String>,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();
    admin_helper.add_propose_to_update_subnet_base(&mut ic_admin, subnet_id);

    ic_admin
        .add_argument(
            SUMMARY_ARG,
            quote(format!(
                "Halt subnet {subnet_id} at cup height and optionally update ssh readonly access",
            )),
        )
        .add_argument("halt-at-cup-height", true);

    if let Some(key) = key {
        ic_admin.add_argument(SSH_READONLY_ACCESS_ARG, quote(key));
    }

    ic_admin
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
    const FAKE_CANISTER_ID_RANGES: &[&str] = &[
        "53zcu-tiaaa-aaaaa-qaaba-cai:54yea-6qaaa-aaaaa-qaabq-cai",
        "5h5yf-eiaaa-aaaaa-qaada-cai:5a46r-jqaaa-aaaaa-qaadq-cai",
    ];
    const SSH_KEY: &str = "fake ssh key";

    #[test]
    fn get_halt_subnet_at_cup_height_command_test() {
        let result = get_halt_subnet_at_cup_height_command(
            &fake_admin_helper(),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
            &Some(SSH_KEY.to_string()),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-subnet \
            --subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --test-neuron-proposer \
            --summary \"Halt subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe at cup height and optionally update ssh readonly access\" \
            --halt-at-cup-height true \
            --ssh-readonly-access \"fake ssh key\""
        );
    }

    #[test]
    fn get_propose_to_prepare_canister_migration_command_test() {
        let result = get_propose_to_prepare_canister_migration_command(
            &fake_admin_helper(),
            &canister_id_ranges_from_strs(FAKE_CANISTER_ID_RANGES),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
            subnet_id_from_str(FAKE_SUBNET_ID_2),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-prepare-canister-migration \
            --summary \"Add canister migration entry\" \
            --source-subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --destination-subnet mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe \
            --canister-id-ranges 53zcu-tiaaa-aaaaa-qaaba-cai:54yea-6qaaa-aaaaa-qaabq-cai 5h5yf-eiaaa-aaaaa-qaada-cai:5a46r-jqaaa-aaaaa-qaadq-cai \
            --test-neuron-proposer"
        );
    }

    #[test]
    fn get_propose_to_reroute_canister_ranges_command_test() {
        let result = get_propose_to_reroute_canister_ranges_command(
            &fake_admin_helper(),
            &canister_id_ranges_from_strs(FAKE_CANISTER_ID_RANGES),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
            subnet_id_from_str(FAKE_SUBNET_ID_2),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-reroute-canister-ranges \
            --summary \"Add canister migration entry\" \
            --source-subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --destination-subnet mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe \
            --canister-id-ranges 53zcu-tiaaa-aaaaa-qaaba-cai:54yea-6qaaa-aaaaa-qaabq-cai 5h5yf-eiaaa-aaaaa-qaada-cai:5a46r-jqaaa-aaaaa-qaadq-cai \
            --test-neuron-proposer"
        );
    }

    #[test]
    fn get_propose_to_complete_canister_migration_command_test() {
        let result = get_propose_to_complete_canister_migration_command(
            &fake_admin_helper(),
            &canister_id_ranges_from_strs(FAKE_CANISTER_ID_RANGES),
            subnet_id_from_str(FAKE_SUBNET_ID_1),
            subnet_id_from_str(FAKE_SUBNET_ID_2),
        )
        .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-complete-canister-migration \
            --summary \"Complete canister migration\" \
            --migration-trace gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe mklno-zzmhy-zutel-oujwg-dzcli-h6nfy-2serg-gnwru-vuwck-hcxit-wqe \
            --canister-id-ranges 53zcu-tiaaa-aaaaa-qaaba-cai:54yea-6qaaa-aaaaa-qaabq-cai 5h5yf-eiaaa-aaaaa-qaada-cai:5a46r-jqaaa-aaaaa-qaadq-cai \
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

    fn canister_id_ranges_from_strs(canister_id_ranges: &[&str]) -> Vec<CanisterIdRange> {
        canister_id_ranges
            .iter()
            .map(|string| std::str::FromStr::from_str(string).unwrap())
            .collect::<Vec<_>>()
    }
}
