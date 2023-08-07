mod transaction_nonce {
    use crate::numeric::TransactionNonce;

    #[test]
    fn should_overflow() {
        let nonce = TransactionNonce(ethnum::u256::MAX);
        assert_eq!(nonce.checked_increment(), None);
    }

    #[test]
    fn should_not_overflow() {
        let nonce = TransactionNonce(ethnum::u256::MAX - 1);
        assert_eq!(
            nonce.checked_increment(),
            Some(TransactionNonce(ethnum::u256::MAX))
        );
    }
}
