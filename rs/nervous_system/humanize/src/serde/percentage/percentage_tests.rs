use super::*;
use serde::Serialize;

#[test]
fn test_round_trip() {
    fn assert_survives_round_trip(
        original_percentage_str: &str,
        expected_basis_points: u64,
        expected_formatted_str: &str,
    ) {
        #[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
        struct T {
            #[serde(with = "crate::serde::percentage")]
            homelessness_rate: Percentage,
        }

        let yaml = format!("homelessness_rate: {original_percentage_str}");
        let t: T = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(
            t,
            T {
                homelessness_rate: Percentage {
                    basis_points: Some(expected_basis_points),
                }
            },
            "original_percentage_str = {original_percentage_str:?}",
        );

        assert_eq!(
            serde_yaml::to_string(&t).unwrap(),
            format!("homelessness_rate: {expected_formatted_str}\n"),
            "original_percentage_str = {:?}",
            original_percentage_str,
        );
    }

    assert_survives_round_trip("0%", 0, "0%");
    assert_survives_round_trip("0.1%", 10, "0.1%");
    assert_survives_round_trip("0.89%", 89, "0.89%");
    assert_survives_round_trip("1%", 100, "1%");
    assert_survives_round_trip("2.30%", 230, "2.3%");
    assert_survives_round_trip("57.68%", 57_68, "57.68%");
    assert_survives_round_trip("1_234.56%", 12_34_56, "1_234.56%");
}
