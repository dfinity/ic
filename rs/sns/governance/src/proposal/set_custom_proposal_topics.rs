use super::*;
use maplit::btreemap;
use pretty_assertions::assert_eq;

#[test]
fn test_validate_and_render_set_custom_proposal_topics() {
    for (set_custom_proposal_topics, existing_custom_functions, expected) in [(
        SetCustomProposalTopics {
            custom_function_id_to_topic: btreemap! {
                111_u64 => Topic::DaoCommunitySettings as i32,
            },
        },
        btreemap! {
            111 => Some(Topic::Governance),
        },
        Ok::<String, String>(
            r#"# Proposal to set topics for custom SNS proposal types

### If adopted, the following custom functions will be categorized under the specified topics:

DaoCommunitySettings (changing from Governance)"#
                .to_string(),
        ),
    )] {
        let observed = validate_and_render_set_custom_proposal_topics(
            &set_custom_proposal_topics,
            &existing_custom_functions,
        );
        assert_eq!(observed, expected);
    }
}
