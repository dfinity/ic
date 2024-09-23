mod deser {
    use crate::dashboard::responses::CanisterInfo;
    use maplit::btreeset;

    #[test]
    fn should_deserialize_canister_info_and_list_upgrade_proposals() {
        //raw output of curl https://ic-api.internetcomputer.org/api/v3/canisters/vxkom-oyaaa-aaaar-qafda-cai
        let json_info = r#"
        {
          "canister_id": "vxkom-oyaaa-aaaar-qafda-cai",
          "controllers": [
            "r7inp-6aaaa-aaaaa-aaabq-cai",
            "vxkom-oyaaa-aaaar-qafda-cai"
          ],
          "enabled": true,
          "id": 501867,
          "module_hash": "81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea",
          "name": "ckERC20 Ledger Suite Orchestrator",
          "subnet_id": "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae",
          "updated_at": "2024-08-06T18:38:47.130040",
          "upgrades": [
            {
              "executed_timestamp_seconds": 1722241311,
              "module_hash": "81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea",
              "proposal_id": 131388.0
            },
            {
              "executed_timestamp_seconds": 1721896327,
              "module_hash": "81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea",
              "proposal_id": 131374.0
            },
            {
              "executed_timestamp_seconds": 1721894521,
              "module_hash": "81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea",
              "proposal_id": 131373.0
            },
            {
              "executed_timestamp_seconds": 1721030747,
              "module_hash": "9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709",
              "proposal_id": 131053.0
            },
            {
              "executed_timestamp_seconds": 1720426070,
              "module_hash": "9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709",
              "proposal_id": 130982.0
            },
            {
              "executed_timestamp_seconds": 1719822369,
              "module_hash": "9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709",
              "proposal_id": 130806.0
            },
            {
              "executed_timestamp_seconds": 1719478267,
              "module_hash": "9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709",
              "proposal_id": 130755.0
            },
            {
              "executed_timestamp_seconds": 1718631613,
              "module_hash": "9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709",
              "proposal_id": 130395.0
            },
            {
              "executed_timestamp_seconds": 1718348006,
              "module_hash": "9bd512661aba6bd7895d09685f625beca014304b7c1e073e029794d601a86709",
              "proposal_id": 130342.0
            },
            {
              "executed_timestamp_seconds": 1716361206,
              "module_hash": "658c5786cf89ce77e58b3c38e01259c9655e20d83caff346cb5e5719c348cb5e",
              "proposal_id": 129750.0
            },
            {
              "executed_timestamp_seconds": 1715589903,
              "module_hash": "658c5786cf89ce77e58b3c38e01259c9655e20d83caff346cb5e5719c348cb5e",
              "proposal_id": 129688.0
            }
          ]
        }
        "#;

        let canister_info: CanisterInfo = serde_json::from_str(json_info).unwrap();
        assert_eq!(
            canister_info.list_upgrade_proposals(),
            btreeset! {129688, 129750, 130342, 130395, 130755, 130806, 130982, 131053, 131373, 131374, 131388}
        );

        let json_info_without_upgrades = r#"
        {
          "canister_id": "g4tto-rqaaa-aaaar-qageq-cai",
          "controllers": [
            "r7inp-6aaaa-aaaaa-aaabq-cai",
            "vxkom-oyaaa-aaaar-qafda-cai"
          ],
          "enabled": true,
          "id": 521991,
          "module_hash": "9495d67c6e9ab4cec3740d68fa0a103dbcfd788d978f4cb58308d847d59e635b",
          "name": "ckLINK Ledger",
          "subnet_id": "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae",
          "updated_at": "2024-08-07T12:19:56.003853",
          "upgrades":null
        }
        "#;

        let canister_info: CanisterInfo = serde_json::from_str(json_info_without_upgrades).unwrap();
        assert_eq!(canister_info.list_upgrade_proposals(), btreeset! {});

        let json_info_with_integer_proposal_id = r#"
        {
          "canister_id": "vxkom-oyaaa-aaaar-qafda-cai",
          "controllers": [
            "r7inp-6aaaa-aaaaa-aaabq-cai",
            "vxkom-oyaaa-aaaar-qafda-cai"
          ],
          "enabled": true,
          "id": 501867,
          "module_hash": "81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea",
          "name": "ckERC20 Ledger Suite Orchestrator",
          "subnet_id": "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae",
          "updated_at": "2024-08-06T18:38:47.130040",
          "upgrades": [
            {
              "executed_timestamp_seconds": 1722241311,
              "module_hash": "81f426bcc52140fdcf045d02d00b04bfb4965445b8aed7090d174fcdebf8beea",
              "proposal_id": 131388
            }
          ]
        }
        "#;
        let canister_info: CanisterInfo =
            serde_json::from_str(json_info_with_integer_proposal_id).unwrap();
        assert_eq!(canister_info.list_upgrade_proposals(), btreeset! {131388});
    }
}
