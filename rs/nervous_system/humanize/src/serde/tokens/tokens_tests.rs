use super::*;
use crate::E8;
use serde::Serialize;

#[test]
fn test_round_trip() {
    fn assert_survives_round_trip(
        original_amount_str: &str,
        expected_e8s: u64,
        expected_formatted_str: &str,
    ) {
        #[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
        struct T {
            #[serde(with = "crate::serde::tokens")]
            amount: Tokens,
        }

        let yaml = format!("amount: {original_amount_str}");
        let t: T = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(
            t,
            T {
                amount: Tokens {
                    e8s: Some(expected_e8s)
                }
            },
            "original_amount_str = {original_amount_str:?}",
        );

        assert_eq!(
            serde_yaml::to_string(&t).unwrap(),
            format!("amount: {expected_formatted_str}\n"),
            "original_amount_str = {:?}",
            original_amount_str,
        );
    }

    assert_survives_round_trip("0 tokens", 0, "0 tokens");
    assert_survives_round_trip("1 token", E8, "1 token");
    assert_survives_round_trip("1.2 tokens", E8 + 2 * E8 / 10, "1.2 tokens");
    assert_survives_round_trip("1_2.3 tokens", 123 * E8 / 10, "12.3 tokens");
    assert_survives_round_trip("25 tokens", 25 * E8, "25 tokens");
    assert_survives_round_trip("123 tokens", 123 * E8, "123 tokens");
    assert_survives_round_trip("123 e8s", 123, "123 e8s");
    assert_survives_round_trip("123_456 e8s", 123_456, "123_456 e8s");
}
