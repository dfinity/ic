use dfn_core::api::PrincipalId;
use ic_crypto_sha2::Sha256;
use icp_ledger::Subaccount as IcpSubaccount;
/// Computes the bytes of the subaccount to which neuron staking transfers are made. This
/// function must be kept in sync with the Nervous System UI equivalent.
pub fn compute_neuron_staking_subaccount_bytes(controller: PrincipalId, nonce: u64) -> [u8; 32] {
    compute_neuron_domain_subaccount_bytes(controller, b"neuron-stake", nonce)
}

/// Computes the subaccount to which neuron staking transfers are made. This
/// function must be kept in sync with the Nervous System UI equivalent.
pub fn compute_neuron_staking_subaccount(controller: PrincipalId, nonce: u64) -> IcpSubaccount {
    IcpSubaccount(compute_neuron_staking_subaccount_bytes(controller, nonce))
}

/// Computes the subaccount to which locked token distributions are initialized to.
pub fn compute_distribution_subaccount_bytes(principal_id: PrincipalId, nonce: u64) -> [u8; 32] {
    compute_neuron_domain_subaccount_bytes(principal_id, b"token-distribution", nonce)
}

// Computes the subaccount to which neuron disburse transfers are made.
pub fn compute_neuron_disburse_subaccount_bytes(controller: PrincipalId, nonce: u64) -> [u8; 32] {
    // The "domain" for neuron disburse was unfortunately chosen to be "neuron-split". It might be
    // possible to change to a more meaningful name, but there is no strong reason to do so, and
    // there is some risk that this behavior is depended on.
    compute_neuron_domain_subaccount_bytes(controller, b"neuron-split", nonce)
}

// Computes the subaccount to which neuron split transfers are made.
pub fn compute_neuron_split_subaccount_bytes(controller: PrincipalId, nonce: u64) -> [u8; 32] {
    // Unfortunately "neuron-split" is used for disburse, so we need to use a different domain.
    compute_neuron_domain_subaccount_bytes(controller, b"split-neuron", nonce)
}

fn compute_neuron_domain_subaccount_bytes(
    controller: PrincipalId,
    domain: &[u8],
    nonce: u64,
) -> [u8; 32] {
    let domain_length: [u8; 1] = [domain.len() as u8];
    let mut hasher = Sha256::new();
    hasher.write(&domain_length);
    hasher.write(domain);
    hasher.write(controller.as_slice());
    hasher.write(&nonce.to_be_bytes());
    hasher.finish()
}

/// Computes the subaccount to which locked token distributions are initialized to.
pub fn compute_distribution_subaccount(principal_id: PrincipalId, nonce: u64) -> IcpSubaccount {
    IcpSubaccount(compute_distribution_subaccount_bytes(principal_id, nonce))
}
