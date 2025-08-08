use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, LabeledTree, Path, TooLongPathError};
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation},
    SubnetId,
};
use tokio::sync::watch;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NNSDelegationBuilder {
    flat_delegation: CertificateDelegation,
    delegation_without_ranges: CertificateDelegation,
    tree_certificate: Certificate,
    subnet_id: SubnetId,
}

impl NNSDelegationBuilder {
    pub(crate) fn new(full_certificate: Certificate, subnet_id: SubnetId) -> Self {
        let flat_certificate = Self::filter_paths(
            &full_certificate,
            vec![Path::new(vec![
                b"subnet".into(),
                subnet_id.get().into(),
                b"canister_ranges".into(),
            ])],
            subnet_id,
        );

        let certification_without_ranges = Self::filter_paths(&full_certificate, vec![], subnet_id);

        let tree_certificate = Self::filter_paths(
            &full_certificate,
            vec![Path::new(vec![
                b"canister_ranges".into(),
                subnet_id.get().into(),
            ])],
            subnet_id,
        );

        Self {
            subnet_id,
            flat_delegation: Self::create_certificate_delegation(flat_certificate, subnet_id),
            delegation_without_ranges: Self::create_certificate_delegation(
                certification_without_ranges,
                subnet_id,
            ),
            tree_certificate,
        }
    }

    fn create_certificate_delegation(
        certificate: Certificate,
        subnet_id: SubnetId,
    ) -> CertificateDelegation {
        CertificateDelegation {
            subnet_id: Blob(subnet_id.get().to_vec()),
            certificate: Blob(serde_cbor::ser::to_vec(&certificate).expect("FIXME")),
        }
    }

    fn filter_paths(
        certificate: &Certificate,
        additional_path: Vec<Path>,
        subnet_id: SubnetId,
    ) -> Certificate {
        let paths = Self::paths(additional_path, subnet_id).expect("FIXME");
        let filtered_tree = certificate.tree.filtered(&paths).expect("FIXME");

        Certificate {
            tree: filtered_tree,
            signature: certificate.signature.clone(),
            delegation: certificate.delegation.clone(),
        }
    }

    fn paths(
        mut additional_paths: Vec<Path>,
        subnet_id: SubnetId,
    ) -> Result<LabeledTree<()>, TooLongPathError> {
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
    }
}

#[derive(Clone)]
// TODO(CON-1487): Consider caching the delegations.
pub struct NNSDelegationReader {
    pub(crate) receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
    subnet_id: SubnetId,
}

// TODO(CON-1487): allow getting the delegation with both canister ranges pruned
// TODO(CON-1487): allow getting the delegation with only the /canister_ranges/{subnet_id} subtree in it.
impl NNSDelegationReader {
    pub(crate) fn new(
        receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
        subnet_id: SubnetId,
    ) -> Self {
        Self {
            receiver,
            subnet_id,
        }
    }

    /// Returns the most recent NNS delegation with the canister id ranges in the flat format,
    /// i.e. the state tree in the delegation will have the /subnet/{subnet_id}/canister_ranges path
    /// and the /canister_ranges/{subnet_id} subtree will be pruned out.
    pub fn get_delegation_with_flat_canister_ranges(&self) -> Option<CertificateDelegation> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.flat_delegation.clone())
    }

    pub fn get_delegation_without_canister_ranges(&self) -> Option<CertificateDelegation> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.delegation_without_ranges.clone())
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }

    pub fn new_for_test_only(certificate: Option<Certificate>, subnet_id: SubnetId) -> Self {
        let builder =
            certificate.map(|certificate| NNSDelegationBuilder::new(certificate, subnet_id));
        let (_sender, receiver) = watch::channel(builder);

        Self {
            receiver,
            subnet_id,
        }
    }
}
