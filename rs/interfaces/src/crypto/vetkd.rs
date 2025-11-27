use ic_types::NodeId;
use ic_types::crypto::vetkd::{
    VetKdArgs, VetKdEncryptedKey, VetKdEncryptedKeyShare, VetKdKeyShareCombinationError,
    VetKdKeyShareCreationError, VetKdKeyShareVerificationError, VetKdKeyVerificationError,
};
use std::collections::BTreeMap;

pub trait VetKdProtocol {
    #[allow(clippy::result_large_err)]
    fn create_encrypted_key_share(
        &self,
        args: VetKdArgs,
    ) -> Result<VetKdEncryptedKeyShare, VetKdKeyShareCreationError>;

    fn verify_encrypted_key_share(
        &self,
        signer: NodeId,
        key_share: &VetKdEncryptedKeyShare,
        args: &VetKdArgs,
    ) -> Result<(), VetKdKeyShareVerificationError>;

    fn combine_encrypted_key_shares(
        &self,
        shares: &BTreeMap<NodeId, VetKdEncryptedKeyShare>,
        args: &VetKdArgs,
    ) -> Result<VetKdEncryptedKey, VetKdKeyShareCombinationError>;

    fn verify_encrypted_key(
        &self,
        key: &VetKdEncryptedKey,
        args: &VetKdArgs,
    ) -> Result<(), VetKdKeyVerificationError>;
}
