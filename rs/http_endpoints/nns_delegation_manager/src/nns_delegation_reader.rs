use ic_crypto_tree_hash::{
    lookup_lower_bound, sparse_labeled_tree_from_paths, LabeledTree, Path, TooLongPathError,
};
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation},
    CanisterId, SubnetId,
};
use tokio::sync::watch;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NNSDelegationBuilder {
    delegation_with_flat_canister_ranges: CertificateDelegation,
    delegation_without_canister_ranges: CertificateDelegation,
    certificate_with_tree_canister_ranges: Certificate,
    labeled_tree_with_both_canister_ranges_formats: LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
}

impl NNSDelegationBuilder {
    pub(crate) fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        subnet_id: SubnetId,
    ) -> Self {
        let flat_certificate = Self::prune_state_tree(
            &full_certificate,
            vec![Path::new(vec![
                b"subnet".into(),
                subnet_id.get().into(),
                b"canister_ranges".into(),
            ])],
            subnet_id,
        )
        .expect("FIXME");

        let certification_without_ranges =
            Self::prune_state_tree(&full_certificate, vec![], subnet_id).expect("FIXME");

        let tree_certificate = Self::prune_state_tree(
            &full_certificate,
            vec![Path::new(vec![
                b"canister_ranges".into(),
                subnet_id.get().into(),
            ])],
            subnet_id,
        )
        .expect("FIXME");

        Self {
            subnet_id,
            delegation_with_flat_canister_ranges: Self::create_certificate_delegation(
                flat_certificate,
                subnet_id,
            )
            .expect("FIXME"),
            delegation_without_canister_ranges: Self::create_certificate_delegation(
                certification_without_ranges,
                subnet_id,
            )
            .expect("FIXME"),
            certificate_with_tree_canister_ranges: tree_certificate,
            labeled_tree_with_both_canister_ranges_formats: full_labeled_tree,
        }
    }

    fn with_tree_canister_ranges(&self, canister_id: CanisterId) -> CertificateDelegation {
        // Find the leaf in which canister id *could* belong to.
        // Note: even if the function does return `Some` it is not guaranteed, that the leaf
        // actually contains the canister id.
        let Some((label, _subtree)) = lookup_lower_bound(
            &self.labeled_tree_with_both_canister_ranges_formats,
            &[&b"canister_ranges".to_vec(), &self.subnet_id.get().to_vec()],
            &canister_id.get().to_vec(),
        ) else {
            // The canister id is not assigned to the subnet according to the NNS delegation.
            // This could mean that the routing table has changed but we haven't refreshed the
            // NNS delegation just yet.
            // In that case, we return the delegation without canister ranges.
            return self.delegation_without_canister_ranges.clone();
        };

        let certificate = match Self::prune_state_tree(
            &self.certificate_with_tree_canister_ranges,
            vec![Path::new(vec![
                b"canister_ranges".into(),
                self.subnet_id.get().into(),
                label.clone(),
            ])],
            self.subnet_id,
        ) {
            Ok(certificate) => certificate,
            Err(_err) => {
                // FIXME(kpop): return a full delegation instead.
                // FIXME(kpop): log an error
                return self.delegation_without_canister_ranges.clone();
            }
        };

        match Self::create_certificate_delegation(certificate, self.subnet_id) {
            Ok(delegation) => delegation,
            Err(_err) => {
                // FIXME(kpop): return a full delegation instead.
                // FIXME(kpop): log an error
                self.delegation_without_canister_ranges.clone()
            }
        }
    }

    fn create_certificate_delegation(
        certificate: Certificate,
        subnet_id: SubnetId,
    ) -> Result<CertificateDelegation, String> {
        Ok(CertificateDelegation {
            subnet_id: Blob(subnet_id.get().to_vec()),
            // FIXME(kpop):
            certificate: Blob(
                serde_cbor::ser::to_vec(&certificate)
                    .map_err(|err| format!("Failed to serialize certificate: {err}"))?,
            ),
        })
    }

    fn prune_state_tree(
        certificate: &Certificate,
        additional_path: Vec<Path>,
        subnet_id: SubnetId,
    ) -> Result<Certificate, String> {
        let paths = Self::paths(additional_path, subnet_id)?;
        let filtered_tree = certificate
            .tree
            .filtered(&paths)
            .map_err(|err| format!("Failed to filter tree: {err:?}"))?;

        Ok(Certificate {
            tree: filtered_tree,
            signature: certificate.signature.clone(),
            delegation: certificate.delegation.clone(),
        })
    }

    fn paths(
        mut additional_paths: Vec<Path>,
        subnet_id: SubnetId,
    ) -> Result<LabeledTree<()>, String> {
        let mut paths = vec![
            Path::new(vec![
                b"subnet".into(),
                subnet_id.get().into(),
                b"public_key".into(),
            ]),
            Path::new(vec![b"time".into()]),
        ];

        paths.append(&mut additional_paths);

        sparse_labeled_tree_from_paths(&paths)
            .map_err(|err| format!("Failed to build labeled tree from paths ({paths:?}): {err:?}"))
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
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.delegation_with_flat_canister_ranges.clone())
    }

    pub fn get_delegation_without_canister_ranges(&self) -> Option<CertificateDelegation> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.delegation_without_canister_ranges.clone())
    }

    pub fn get_delegation_with_tree_canister_ranges(
        &self,
        canister_id: CanisterId,
    ) -> Option<CertificateDelegation> {
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
