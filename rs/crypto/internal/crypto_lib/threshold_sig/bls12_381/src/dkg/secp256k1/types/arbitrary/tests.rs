use super::*;

proptest! {
    /// Verify that arbitrary `EphemeralSecretKey`s can be made:
    #[test]
    fn secp256k1_secret_key(_: EphemeralSecretKey) {}

    /// Verify that arbitrary `EphemeralSecretKeyBytes`s can be made:
    #[test]
    fn secp256k1_secret_key_bytes(_: EphemeralSecretKey) {}

    /// Verify that arbitrary `EphemeralPublicKey`s can be made:
    #[test]
    fn secp256k1_public_key(_: EphemeralPublicKey) {}

    /// Verify that arbitrary `EphemeralPublicKeyBytes`s can be made:
    #[test]
    fn secp256k1_public_key_bytes(_: EphemeralPublicKey) {}


    /// Verify that arbitrary `EphemeralPop`s can be made:
    #[test]
    fn secp256k1_pop(_: EphemeralPop) {}

    /// Verify that arbitrary `EphemeralPopBytes`s can be made:
    #[test]
    fn secp256k1_pop_bytes(_: EphemeralPop) {}

    /// Verify that arbitrary `EphemeralKeySetBytes`s can be made:
    #[test]
    fn ephemeral_key_set_bytes(_: EphemeralKeySetBytes) {}
}
