use ic_certification::{DelegationSubnetInfo, verify_delegation_certificate};
use ic_state_machine_tests::two_subnets_simple;

/// Regression test: `get_delegation_for_subnet` must include the `/subnet/<id>/type` path
/// in the delegation certificate so that `subnet_type` is never `None`.
///
/// The certification library rejects delegations with `subnet_type == None` when
/// verifying canister signatures, so a missing `type` leaf causes every
/// canister-signature validation through a pocket-ic-issued delegation to fail
/// with "the source subnet <id> is not trusted for delegations".
#[test]
fn delegation_cert_includes_subnet_type() {
    // two_subnets_simple creates two Application subnets that share a registry,
    // so env1 knows about env2 and can issue a delegation for it.
    let (env1, env2) = two_subnets_simple();
    let subnet_id = env2.get_subnet_id();

    // Execute a round so the network topology (including env2's subnet type)
    // is propagated from the registry into env1's replicated state.
    env1.execute_round();

    let delegation = env1
        .get_delegation_for_subnet(subnet_id)
        .expect("get_delegation_for_subnet should succeed");

    let cert_bytes = delegation.certificate.0;
    let (_key, info): (_, DelegationSubnetInfo) =
        verify_delegation_certificate(&cert_bytes, &subnet_id, &env1.root_key(), None, false)
            .expect("delegation certificate should be valid");

    assert_eq!(
        info.subnet_type,
        Some("application".to_string()),
        "delegation cert must contain the subnet type leaf; \
         got None which would cause canister-signature validation to fail",
    );
}
