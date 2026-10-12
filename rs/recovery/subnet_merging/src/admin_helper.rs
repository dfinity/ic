use ic_base_types::SubnetId;
use ic_recovery::admin_helper::{
    AdminHelper, CommandHelper, IcAdmin, SSH_READONLY_ACCESS_ARG, SUMMARY_ARG, quote,
};

const SUBNET_ARG: &str = "subnet";

/// Propose to label the subnet as "cooling down", i.e. to have it stop
/// accepting ingress messages, answering queries and executing canister
/// messages, so that it quiesces and can be merged into another subnet.
///
/// Optionally adds a ssh-readonly-access key to the subnet, which is needed to
/// download its state later on.
pub(crate) fn get_propose_to_cool_down_subnet_command(
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
                "Label subnet {subnet_id} as cooling down and optionally update ssh readonly access",
            )),
        )
        .add_argument("cooling-down", true);

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
    const FAKE_SUBNET_ID_1: &str =
        "gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe";
    const SSH_KEY: &str = "fake ssh key";

    #[test]
    fn get_propose_to_cool_down_subnet_command_test() {
        let result = get_propose_to_cool_down_subnet_command(
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
            --summary \"Label subnet gpvux-2ejnk-3hgmh-cegwf-iekfc-b7rzs-hrvep-5euo2-3ywz3-k3hcb-cqe as cooling down and optionally update ssh readonly access\" \
            --cooling-down true \
            --ssh-readonly-access \"fake ssh key\" \
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
