use super::*;
use maplit::btreemap;
use pretty_assertions::assert_eq;

#[test]
fn test_validate_and_render_set_topics_for_custom_proposals() {
    for (set_topics_for_custom_proposals, existing_custom_functions, expected) in [
        (
            SetTopicsForCustomProposals {
                custom_function_id_to_topic: btreemap! {
                    111_u64 => Topic::DaoCommunitySettings as i32,
                },
            },
            btreemap! {
                111 => ("AAA".to_string(), Some(Topic::Governance)),
            },
            Ok::<String, String>(
                r#"# Set topics for custom SNS proposal types

### If adopted, the following proposals will be categorized under the specified topics:

  - AAA under topic DaoCommunitySettings (changing from Governance)"#
                    .to_string(),
            ),
        ),
        (
            SetTopicsForCustomProposals {
                custom_function_id_to_topic: btreemap! {
                    222_u64 => Topic::DaoCommunitySettings as i32,
                    111_u64 => Topic::DaoCommunitySettings as i32,
                    444_u64 => Topic::DaoCommunitySettings as i32,
                },
            },
            btreemap! {
                111 => ("AAA".to_string(), Some(Topic::DaoCommunitySettings)),
                222 => ("BBB".to_string(), Some(Topic::Governance)),
                333 => ("CCC".to_string(), Some(Topic::Governance)),
                444 => ("DDD".to_string(), None),
            },
            Ok::<String, String>(
                r#"# Set topics for custom SNS proposal types

### If adopted, the following proposals will be categorized under the specified topics:

  - AAA under topic DaoCommunitySettings (keeping unchanged)
  - BBB under topic DaoCommunitySettings (changing from Governance)
  - DDD under topic DaoCommunitySettings (topic not currently set)"#
                    .to_string(),
            ),
        ),
        (
            SetTopicsForCustomProposals {
                custom_function_id_to_topic: btreemap! {},
            },
            btreemap! {
                111 => ("AAA".to_string(), Some(Topic::Governance)),
            },
            Err::<String, String>(
                "SetTopicsForCustomProposals.custom_function_id_to_topic must not be empty."
                    .to_string(),
            ),
        ),
        (
            SetTopicsForCustomProposals {
                custom_function_id_to_topic: btreemap! {
                    111_u64 => Topic::DaoCommunitySettings as i32,
                },
            },
            btreemap! {
                222 => ("BBB".to_string(), Some(Topic::Governance)),
            },
            Err::<String, String>(
                "Cannot set topic for proposal(s) with ID(s) 111 since they have not been \
                 registered as custom proposals in this SNS yet. Please use \
                 `AddGenericNervousSystemFunction` proposals to register new custom SNS proposals."
                    .to_string(),
            ),
        ),
    ] {
        let observed = validate_and_render_set_topics_for_custom_proposals(
            &set_topics_for_custom_proposals,
            &existing_custom_functions,
        );
        assert_eq!(observed, expected);
    }
}
