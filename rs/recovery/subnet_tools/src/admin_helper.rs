//! `ic-admin` command builders shared by the subnet splitting and subnet
//! merging tools.

use ic_base_types::SubnetId;
use ic_recovery::admin_helper::{
    AdminHelper, CommandHelper, IcAdmin, SSH_READONLY_ACCESS_ARG, SUMMARY_ARG, quote,
};

/// Arguments naming the two subnets an operation moves canister id ranges
/// between, and the subnet an `ic-admin` subnet command applies to.
pub const SOURCE_SUBNET_ARG: &str = "source-subnet";
pub const DESTINATION_SUBNET_ARG: &str = "destination-subnet";
pub const SUBNET_ARG: &str = "subnet";

/// Propose to make the subnet halt after reaching the next CUP height, i.e. at
/// a checkpoint whose state is certified and whose hash the subnet agreed on.
///
/// Optionally adds a ssh-readonly-access key to the subnet, which is what the
/// state is then downloaded with.
pub fn get_halt_subnet_at_cup_height_command(
    admin_helper: &AdminHelper,
    subnet_id: SubnetId,
    key: &Option<String>,
) -> IcAdmin {
    let mut ic_admin = admin_helper.get_ic_admin_cmd_base();

    ic_admin
        .add_positional_argument("propose-to-update-subnet")
        .add_argument(SUBNET_ARG, subnet_id)
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

    admin_helper.add_proposer_args(&mut ic_admin);

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
    const FAKE_SUBNET_ID: &str = "gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe";
    const SSH_KEY: &str = "fake ssh key";

    #[test]
    fn get_halt_subnet_at_cup_height_command_test() {
        let admin_helper = AdminHelper::new(
            PathBuf::from(FAKE_IC_ADMIN),
            Url::try_from(FAKE_NNS_URL).unwrap(),
            /*neuron_args=*/ None,
        );
        let subnet_id = PrincipalId::from_str(FAKE_SUBNET_ID)
            .map(SubnetId::from)
            .unwrap();

        let result =
            get_halt_subnet_at_cup_height_command(&admin_helper, subnet_id, &Some(SSH_KEY.into()))
                .join(" ");

        assert_eq!(
            result,
            "/fake/ic/admin/dir/ic-admin \
            --nns-url \"https://fake_nns_url.com:8080/\" \
            propose-to-update-subnet \
            --subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe \
            --summary \"Halt subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe at cup height and optionally update ssh readonly access\" \
            --halt-at-cup-height true \
            --ssh-readonly-access \"fake ssh key\" \
            --test-neuron-proposer"
        );
    }
}
