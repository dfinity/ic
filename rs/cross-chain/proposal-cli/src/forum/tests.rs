use crate::dashboard::responses::{ProposalInfo, ProposalPayloadInfo};
use crate::forum::{CreateTopicRequest, ForumTopic};

#[test]
fn should_have_correct_content_when_creating_topic_for_multiple_proposals() {
    let topic = ForumTopic::for_upgrade_proposals(vec![
        ckbtc_ledger_proposal(),
        ckbtc_index_proposal(),
        ckbtc_archive_proposal(),
    ])
    .unwrap();

    let request = CreateTopicRequest::from(topic);

    assert_eq!(
        request,
        CreateTopicRequest {
            title: "Proposals (137359, 137360, 137361) to upgrade the (ckBTC index, ckBTC ledger, ckBTC archive)".to_string(),
            raw: "\
            Hi everyone :waving_hand:\n\n\
            Please use this forum thread to discuss the following proposals:\n\
            * Proposal [137359](https://dashboard.internetcomputer.org/proposal/137359): upgrade the ckBTC index\n\
            * Proposal [137360](https://dashboard.internetcomputer.org/proposal/137360): upgrade the ckBTC ledger\n\
            * Proposal [137361](https://dashboard.internetcomputer.org/proposal/137361): upgrade the ckBTC archive\n\n\
            :information_source: All listed proposals should contain the necessary information to verify them.\
            ".to_string(),
            category:76,
            tags: vec!["Application-canister-mgmt".to_string()],
        }
    );
}

#[test]
fn should_have_correct_content_when_creating_topic_for_single_proposals() {
    let topic = ForumTopic::for_upgrade_proposals(vec![ckbtc_ledger_proposal()]).unwrap();

    let request = CreateTopicRequest::from(topic);

    assert_eq!(
        request,
        CreateTopicRequest {
            title: "Proposal 137360 to upgrade the ckBTC ledger".to_string(),
            raw: "\
            Hi everyone :waving_hand:\n\n\
            Please use this forum thread to discuss the following proposal:\n\
            * Proposal [137360](https://dashboard.internetcomputer.org/proposal/137360): upgrade the ckBTC ledger\n\n\
            :information_source: All listed proposals should contain the necessary information to verify them.\
            ".to_string(),
            category: 76,
            tags: vec!["Application-canister-mgmt".to_string()],
        }
    );
}

fn ckbtc_ledger_proposal() -> ProposalInfo {
    ProposalInfo {
        proposal_id: 137360,
        payload: ProposalPayloadInfo {
            canister_id: "mxzaz-hqaaa-aaaar-qaada-cai".to_string(),
            install_mode_name: "CANISTER_INSTALL_MODE_UPGRADE".to_string(),
        },
    }
}

fn ckbtc_index_proposal() -> ProposalInfo {
    ProposalInfo {
        proposal_id: 137359,
        payload: ProposalPayloadInfo {
            canister_id: "n5wcd-faaaa-aaaar-qaaea-cai".to_string(),
            install_mode_name: "CANISTER_INSTALL_MODE_UPGRADE".to_string(),
        },
    }
}

fn ckbtc_archive_proposal() -> ProposalInfo {
    ProposalInfo {
        proposal_id: 137361,
        payload: ProposalPayloadInfo {
            canister_id: "nbsys-saaaa-aaaar-qaaga-cai".to_string(),
            install_mode_name: "CANISTER_INSTALL_MODE_UPGRADE".to_string(),
        },
    }
}
