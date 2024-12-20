use crate::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet};
use crate::crypto::vetkd::{
    VetKdArgs, VetKdEncryptedKey, VetKdEncryptedKeyShare, VetKdEncryptedKeyShareContent,
};
use crate::crypto::ExtendedDerivationPath;
use crate::Height;
use ic_base_types::PrincipalId;
use ic_base_types::SubnetId;

mod display_and_debug {
    use super::*;

    #[test]
    fn should_correctly_print_vetkd_args() {
        let input = VetKdArgs {
            ni_dkg_id: NiDkgId {
                start_block_height: Height::new(7),
                dealer_subnet: SubnetId::from(PrincipalId::new_subnet_test_id(42)),
                dkg_tag: NiDkgTag::HighThreshold,
                target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new(
                    [42; NiDkgTargetId::SIZE],
                )),
            },
            derivation_path: ExtendedDerivationPath {
                caller: PrincipalId::new_node_test_id(17),
                derivation_path: vec![b"dp".to_vec()],
            },
            derivation_id: b"did".to_vec(),
            encryption_public_key: b"ek".to_vec(),
        };
        let output = "VetKdArgs { \
            ni_dkg_id: NiDkgId { start_block_height: 7, dealer_subnet: ot5wk-sbkaa-aaaaa-aaaap-yai, dkg_tag: HighThreshold, target_subnet: Remote(0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a) }, \
            derivation_path: ExtendedDerivationPath { caller: 7xzs3-rqraa-aaaaa-aaaap-2ai, \
            derivation_path: { 6470 } }, \
            derivation_id: 0x646964, \
            encryption_public_key: 0x656b \
        }"
        .to_string();

        assert_eq!(output, format!("{:?}", input));
        assert_eq!(output, format!("{}", input));
    }

    #[test]
    fn should_correctly_print_vetkd_encrypted_key_share() {
        let input = VetKdEncryptedKeyShare {
            encrypted_key_share: VetKdEncryptedKeyShareContent(b"eks".to_vec()),
            node_signature: b"ns".to_vec(),
        };
        let output = "VetKdEncryptedKeyShare { \
            encrypted_key_share: VetKdEncryptedKeyShareContent(0x656b73), \
            node_signature: 0x6e73 \
        }"
        .to_string();

        assert_eq!(output, format!("{:?}", input));
        assert_eq!(output, format!("{}", input));
    }

    #[test]
    fn should_correctly_print_vetkd_encrypted_key() {
        let input = VetKdEncryptedKey {
            encrypted_key: b"ek".to_vec(),
        };
        let output = "VetKdEncryptedKey { \
             encrypted_key: 0x656b \
        }"
        .to_string();

        assert_eq!(output, format!("{:?}", input));
        assert_eq!(output, format!("{}", input));
    }
}
