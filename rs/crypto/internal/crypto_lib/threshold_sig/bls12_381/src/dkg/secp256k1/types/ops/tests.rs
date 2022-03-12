use super::*;
use libsecp256k1::curve::Scalar;
use proptest::prelude::*;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

impl From<u32> for EphemeralSecretKey {
    fn from(number: u32) -> EphemeralSecretKey {
        EphemeralSecretKey(Scalar::from_int(number))
    }
}

impl From<u32> for EphemeralPublicKey {
    fn from(number: u32) -> EphemeralPublicKey {
        EphemeralPublicKey::from(&EphemeralSecretKey(Scalar::from_int(number)))
    }
}

mod arithmetic {
    //! Verify that the arithmetic works as we expect, in particular:
    //! * SecretKey(int_a) + SecretKey(int_b) = SecretKey(int_a + int_b)
    //! * SecretKey(int_a) * SecretKey(int_b) = SecretKey(int_a * int_b)
    //! * SecretKey.zero() is an additive identity
    //! * SecretKey.zero() is a multiplicative zero
    //! * SecretKey.one() is a multiplicative identity
    //! * SecretKey(a) + -SecretKey(a) = SecretKey.zero()
    //! * PublicKey(x) + PublicKey(y) == PublicKey(x + y)
    //! * PublicKey(x) + scalar == PublicKey(x + scalar)
    //! * PublicKey(x) * scalar == PublicKey(x * scalar)
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            max_shrink_iters: 0,
            .. ProptestConfig::default()
        })]

        /// Verifies secret addition for small values:
        /// * `SecretKey(int_a) + SecretKey(int_b) = SecretKey(int_a + int_b)`
        #[test]
        fn secret_key_addition_is_correct(int_a: u32, int_b: u32) {
            let (sum, overflow) = int_a.overflowing_add(int_b);
            prop_assume!(!overflow);
            let left = EphemeralSecretKey::from(int_a) + EphemeralSecretKey::from(int_b);
            let right = EphemeralSecretKey::from(sum);
            assert_eq!(left, right);
        }

        /// Verifies secret multiplication for small values:
        /// * `SecretKey(int_a) * SecretKey(int_b) = SecretKey(int_a * int_b)`
        #[test]
        fn secret_key_multiplication_is_correct(int_a: u16, int_b: u16) {
            let int_a = int_a as u32;
            let int_b = int_b as u32;
            let left = EphemeralSecretKey::from(int_a) * EphemeralSecretKey::from(int_b);
            let right = EphemeralSecretKey::from(int_a *  int_b);
            assert_eq!(left, right);
        }

        /// Verifies that the secret key zero is both a left and a right identity:
        /// * `zero + any == any == any + zero`
        #[test]
        fn secret_key_zero_is_additive_identity(secret_key: EphemeralSecretKey) {
            let left = EphemeralSecretKey::zero() + secret_key.clone();
            let right = secret_key.clone() + EphemeralSecretKey::zero();
            assert_eq!(&left, &secret_key, "EphemeralSecretKey::zero() is not a left identity.");
            assert_eq!(&right, &secret_key, "EphemeralSecretKey::zero() is not a right identity.");
        }

        /// Verifies that the secret key zero is both a left and a right zero:
        /// * `zero * any == zero == any * zero`
        #[test]
        fn secret_key_zero_is_multiplicative_zero(secret_key: EphemeralSecretKey) {
            let left = EphemeralSecretKey::zero() * secret_key.clone();
            let right = secret_key * EphemeralSecretKey::zero();
            assert_eq!(left, EphemeralSecretKey::zero(), "EphemeralSecretKey::zero() is not a left zero.");
            assert_eq!(right, EphemeralSecretKey::zero(), "EphemeralSecretKey::zero() is not a right zero.");
        }

        /// Verifies that the secret key one is both a left and a right identity:
        /// * `one * any == any == any * one`
        #[test]
        fn secret_key_one_is_multiplicative_identity(secret_key: EphemeralSecretKey) {
            let left = EphemeralSecretKey::one() * secret_key.clone();
            let right = secret_key.clone() * EphemeralSecretKey::one();
            assert_eq!(&left, &secret_key, "EphemeralSecretKey::one() is not a left identity.");
            assert_eq!(&right, &secret_key, "EphemeralSecretKey::one() is not a right identity.");
        }

        /// Verifies that secret keys satisfy:
        /// * `x + -x == zero`
        #[test]
        fn adding_negative_secret_key_yields_zero(secret_key: EphemeralSecretKey) {
            let left = secret_key.clone() + -secret_key;
            let right = EphemeralSecretKey::zero();
            assert_eq!(left, right);
        }

        /// Verifies that public key infinity is a multiplicative left zero.
        ///
        /// Note: `scalar * public_key` is not defined so we don't need to test that it is also a right zero.
        ///
        /// * `PublicKey::infinity() * scalar == PublicKey::infinity()`
        #[test]
        fn public_key_infinity_is_multiplicative_zero(secret_key: EphemeralSecretKey) {
            let left = EphemeralPublicKey::infinity() * secret_key;
            assert_eq!(left, EphemeralPublicKey::infinity(), "EphemeralPublicKey::infinity() is not a left zero.");
        }

        /// Verifies that public key infinity is the "identity" when adding scalars.
        ///
        /// * `PublicKey::infinity() + scalar == PublicKey(scalar)`
        #[test]
        fn public_key_infinity_is_additive_identity_for_scalars(secret_key: EphemeralSecretKey) {
            let right = EphemeralPublicKey::from(&secret_key);
            let left = EphemeralPublicKey::infinity() + secret_key;
            assert_eq!(left, right, "EphemeralPublicKey::infinity() is not the additive identity for scalars.");
        }

        /// Verifies that public key addition is correct for small values:
        /// * `PublicKey(x) + PublicKey(y) == PublicKey(x + y)`
        #[test]
        fn public_key_addition_is_correct(int_a: u32, int_b: u32) {
            let (sum, overflow) = int_a.overflowing_add(int_b);
            prop_assume!(!overflow);
            let left = EphemeralPublicKey::from(int_a) + EphemeralPublicKey::from(int_b);
            let right = EphemeralPublicKey::from(sum);
            assert_eq!(left, right);
        }

        /// Verifies that adding scalars to a public key works for small values:
        /// * `PublicKey(x) + scalar == PublicKey(x + scalar)`
        #[test]
        fn public_key_secret_addition_is_correct(int_a: u32, int_b: u32) {
            let (sum, overflow) = int_a.overflowing_add(int_b);
            prop_assume!(!overflow);
            let left = EphemeralPublicKey::from(int_a) + EphemeralSecretKey::from(int_b);
            let right = EphemeralPublicKey::from(sum);
            assert_eq!(left, right);
        }

        /// Verifies that multiplying scalars to a public key works for small values:
        /// * `PublicKey(x) * scalar == PublicKey(x * scalar)`
        #[test]
        fn public_key_multiplication_is_correct(int_a: u16, int_b: u16) {
            let int_a = int_a as u32;
            let int_b = int_b as u32;
            let left = EphemeralPublicKey::from(int_a) * EphemeralSecretKey::from(int_b);
            let right = EphemeralPublicKey::from(int_a *  int_b);
            assert_eq!(left, right);
        }

        /// Verifies that public key addition is correct for arbitrary values:
        /// * `PublicKey(x) + PublicKey(y) == PublicKey(x + y)`
        #[test]
        fn public_key_add_assign_is_correct(seed: [u8; 32]) {
            let mut rng = ChaChaRng::from_seed(seed);
            let x = EphemeralSecretKey::random(&mut rng);
            let y = EphemeralSecretKey::random(&mut rng);

            let public_x = EphemeralPublicKey::from(&x);
            let public_y = EphemeralPublicKey::from(&y);
            let left = public_x + public_y;

            let mut right = x;
            right += &y;
            let right = EphemeralPublicKey::from(&right);

            assert_eq!(left, right);
        }

        /// Verifies that adding scalars to a public key works for arbitrary values:
        /// * `PublicKey(x) + scalar == PublicKey(x + scalar)`
        #[test]
        fn public_key_add_assign_secret_is_correct(seed: [u8; 32]) {
            let mut rng = ChaChaRng::from_seed(seed);
            let x = EphemeralSecretKey::random(&mut rng);
            let scalar = EphemeralSecretKey::random(&mut rng);

            let mut left = EphemeralPublicKey::from(&x);
            left += &scalar;

            let mut right = x;
            right += &scalar;
            let right = EphemeralPublicKey::from(&right);

            assert_eq!(left, right);
        }

        /// Verifies that multiplying scalars to a public key works for arbitrary values:
        /// * `PublicKey(x) * scalar == PublicKey(x * scalar)`
        #[test]
        fn public_key_mul_assign_secret_is_correct(seed: [u8; 32]) {
            let mut rng = ChaChaRng::from_seed(seed);
            let x = EphemeralSecretKey::random(&mut rng);
            let scalar = EphemeralSecretKey::random(&mut rng);

            let mut left = EphemeralPublicKey::from(&x);
            left *= &scalar;

            let mut right = x;
            right *= &scalar;
            let right = EphemeralPublicKey::from(&right);

            assert_eq!(left, right);
        }
    }
}
