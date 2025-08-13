use ic_crypto_tree_hash::{
    lookup_lower_bound, sparse_labeled_tree_from_paths, FilterBuilder, LabeledTree,
    LookupLowerBoundStatus, Path,
};
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation},
    CanisterId, SubnetId,
};
use tokio::sync::watch;

#[derive(Clone, Copy)]
enum CanisterRangesFilter {
    /// Keep only the `/subnet/<subnet_id>/canister_ranges` leaf.
    Flat,
    /// Keep only the `/canister_ranges/subnet_id/canister_id_label` leaf.
    Tree(CanisterId),
    /// Discard both ranges.
    None,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NNSDelegationBuilderPriv {
    full_certificate: Certificate,
    full_labeled_tree: LabeledTree<Vec<u8>>,
    full_filter_builder: FilterBuilder,
    subnet_id: SubnetId,
}

impl NNSDelegationBuilderPriv {
    fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        subnet_id: SubnetId,
    ) -> Self {
        Self {
            full_filter_builder: full_certificate.tree.filter_builder(),
            full_certificate,
            full_labeled_tree,
            subnet_id,
        }
    }

    fn try_build(&self, filter: CanisterRangesFilter) -> Result<CertificateDelegation, String> {
        let mut paths = vec![
            Path::new(vec![
                b"subnet".into(),
                self.subnet_id.get().into(),
                b"public_key".into(),
            ]),
            Path::new(vec![b"time".into()]),
        ];

        match filter {
            // Don't include any paths.
            CanisterRangesFilter::None => {}
            // Additionally include `/subnet/<subnet_id>/canister_ranges`
            CanisterRangesFilter::Flat => {
                paths.push(Path::new(vec![
                    b"subnet".into(),
                    self.subnet_id.get().into(),
                    b"canister_ranges".into(),
                ]));
            }
            // Additionally include `/canister_ranges/<subnet_id>/<canister_id_label>`
            CanisterRangesFilter::Tree(canister_id) => {
                let label = match lookup_lower_bound(
                    &self.full_labeled_tree,
                    &[b"canister_ranges".as_ref(), &self.subnet_id.get().to_vec()],
                    &canister_id.get().to_vec(),
                ) {
                    LookupLowerBoundStatus::Found(label, _labeled_subtree) => label,
                    LookupLowerBoundStatus::PrefixNotFound
                    | LookupLowerBoundStatus::LabelNotFound => {
                        // The canister id is not assigned to the subnet according to the NNS delegation.
                        // This could mean that the routing table has changed but we haven't refreshed the
                        // NNS delegation just yet.
                        // In that case, we return the delegation without canister ranges.
                        return Err(String::from("Not found"));
                    }
                };

                paths.push(Path::new(vec![
                    b"canister_ranges".into(),
                    self.subnet_id.get().into(),
                    label.clone(),
                ]));
            }
        }

        let tree = sparse_labeled_tree_from_paths(&paths).map_err(|err| {
            format!("Failed to build labeled tree from paths ({paths:?}): {err:?}")
        })?;

        let filtered_tree = self
            .full_filter_builder
            .filtered(&tree)
            .map_err(|err| format!("Failed to filter tree: {err:?}"))?;

        let certificate = Certificate {
            tree: filtered_tree,
            signature: self.full_certificate.signature.clone(),
            delegation: self.full_certificate.delegation.clone(),
        };

        Ok(CertificateDelegation {
            subnet_id: Blob(self.subnet_id.get().to_vec()),
            certificate: Blob(
                serde_cbor::ser::to_vec(&certificate)
                    .map_err(|err| format!("Failed to serialize certificate: {err}"))?,
            ),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NNSDelegationBuilder {
    builder: NNSDelegationBuilderPriv,
    precomputed_delegation_with_flat_canister_ranges: CertificateDelegation,
    precomputed_delegation_without_canister_ranges: CertificateDelegation,
}

impl NNSDelegationBuilder {
    pub(crate) fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        subnet_id: SubnetId,
    ) -> Self {
        let builder = NNSDelegationBuilderPriv::new(full_certificate, full_labeled_tree, subnet_id);
        let precomputed_delegation_without_canister_ranges = builder
            .try_build(CanisterRangesFilter::None)
            .expect("FIXME");
        let precomputed_delegation_with_flat_canister_ranges = builder
            .try_build(CanisterRangesFilter::Flat)
            .expect("FIXME");

        Self {
            builder,
            precomputed_delegation_with_flat_canister_ranges,
            precomputed_delegation_without_canister_ranges,
        }
    }

    fn with_tree_canister_ranges(
        &self,
        canister_id: CanisterId,
    ) -> Result<CertificateDelegation, String> {
        self.builder
            .try_build(CanisterRangesFilter::Tree(canister_id))
    }
}

#[derive(Clone)]
// TODO(CON-1487): Consider caching the delegations.
pub struct NNSDelegationReader {
    pub(crate) receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
}

impl NNSDelegationReader {
    pub(crate) fn new(receiver: watch::Receiver<Option<NNSDelegationBuilder>>) -> Self {
        Self { receiver }
    }

    /// Returns the most recent NNS delegation with the canister id ranges in the flat format,
    /// i.e. the state tree in the delegation will have the /subnet/{subnet_id}/canister_ranges path
    /// and the /canister_ranges/{subnet_id} subtree will be pruned out.
    pub fn get_delegation_with_flat_canister_ranges(&self) -> Option<CertificateDelegation> {
        self.receiver.borrow().as_ref().map(|builder| {
            builder
                .precomputed_delegation_with_flat_canister_ranges
                .clone()
        })
    }

    pub fn get_delegation_without_canister_ranges(&self) -> Option<CertificateDelegation> {
        self.receiver.borrow().as_ref().map(|builder| {
            builder
                .precomputed_delegation_without_canister_ranges
                .clone()
        })
    }

    pub fn get_delegation_with_tree_canister_ranges(
        &self,
        canister_id: CanisterId,
    ) -> Option<Result<CertificateDelegation, String>> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.with_tree_canister_ranges(canister_id))
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }

    pub fn new_for_test_only(certificate: Option<Certificate>, subnet_id: SubnetId) -> Self {
        let builder = certificate.map(|certificate| {
            NNSDelegationBuilder::new(
                certificate.clone(),
                LabeledTree::try_from(certificate.tree.clone()).unwrap(),
                subnet_id,
            )
        });
        let (_sender, receiver) = watch::channel(builder);

        Self { receiver }
    }
}
