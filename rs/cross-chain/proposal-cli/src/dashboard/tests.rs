mod deser {
    use crate::dashboard::responses::{CanisterInfo, ProposalInfo, ProposalPayloadInfo};
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

    #[test]
    fn should_deserialize_proposal_info() {
        //raw output of curl https://ic-api.internetcomputer.org/api/v3/proposals/137875
        let json_info = r##"
        {
            "action": "InstallCode",
            "action_nns_function": null,
            "deadline_timestamp_seconds": 1755462381,
            "decided_timestamp_seconds": 1755180499,
            "executed_timestamp_seconds": 1755180499,
            "failed_timestamp_seconds": 0,
            "failure_reason": null,
            "id": 118001,
            "known_neurons_ballots": [
              {
                "id": "27",
                "name": "DFINITY Foundation",
                "vote": 1
              },
              {
                "id": "4966884161088437903",
                "name": "Synapse.vote (original)",
                "vote": 1
              },
              {
                "id": "5967494994762486275",
                "name": "Arthur’s Neuron (used to be cycle_dao)",
                "vote": 1
              },
              {
                "id": "14231996777861930328",
                "name": "ICDevs.org",
                "vote": 1
              },
              {
                "id": "428687636340283207",
                "name": "CryptoIsGood",
                "vote": 1
              },
              {
                "id": "10843833286193887500",
                "name": "Anvil",
                "vote": 1
              },
              {
                "id": "55674167450360693",
                "name": "ICPL.app",
                "vote": 1
              },
              {
                "id": "7766735497505253681",
                "name": "Inactive (Request Removal) - The Fools' Court",
                "vote": 0
              },
              {
                "id": "12860062727199510685",
                "name": "ysyms",
                "vote": 1
              },
              {
                "id": "8959053254051540391",
                "name": "The Accumulators’ Neuron",
                "vote": 1
              },
              {
                "id": "6362091663310642824",
                "name": "RawTech Venture",
                "vote": 1
              },
              {
                "id": "8777656085298269769",
                "name": "Paul Young",
                "vote": 0
              },
              {
                "id": "5728549712200490799",
                "name": "ICPMANUAL",
                "vote": 0
              },
              {
                "id": "13538714184009896865",
                "name": "8yeargangDAO",
                "vote": 1
              },
              {
                "id": "12911334408382674412",
                "name": "John Wiegley",
                "vote": 0
              },
              {
                "id": "13765488517578645474",
                "name": "Isaac Valadez",
                "vote": 1
              },
              {
                "id": "5944070935127277981",
                "name": "Krzysztof Żelazko",
                "vote": 1
              },
              {
                "id": "12890113924500239096",
                "name": "Always Rejects",
                "vote": 0
              },
              {
                "id": "11053086394920719168",
                "name": "Nicolas.ic",
                "vote": 2
              },
              {
                "id": "16335946240875077438",
                "name": "Smaug’s Neuron for Retail Investors",
                "vote": 1
              },
              {
                "id": "11595773061053702367",
                "name": "ICLight.io",
                "vote": 0
              },
              {
                "id": "5553849921138062661",
                "name": "Synapse.vote (NEW)",
                "vote": 1
              },
              {
                "id": "16737374299031693047",
                "name": "Taggr Network",
                "vote": 2
              },
              {
                "id": "2649066124191664356",
                "name": "CodeGov",
                "vote": 1
              },
              {
                "id": "10323780370508631162",
                "name": "Sonic AMM",
                "vote": 0
              },
              {
                "id": "6914974521667616512",
                "name": "Rakeoff.io",
                "vote": 1
              },
              {
                "id": "11974742799838195634",
                "name": "$STACK",
                "vote": 0
              },
              {
                "id": "17682165960669268263",
                "name": "OpenChat",
                "vote": 1
              },
              {
                "id": "4714336137769716208",
                "name": "ELNA AI",
                "vote": 0
              },
              {
                "id": "1767081890685465163",
                "name": "GEEKFACTORY",
                "vote": 1
              },
              {
                "id": "2776371642396604393",
                "name": "ICP Hub México",
                "vote": 0
              },
              {
                "id": "5132308922522452058",
                "name": "ICP Hub Poland",
                "vote": 1
              },
              {
                "id": "7902983898778678943",
                "name": "Jerry Banfield",
                "vote": 1
              },
              {
                "id": "433047053926084807",
                "name": "WaterNeuron",
                "vote": 1
              },
              {
                "id": "1100477100620240869",
                "name": "ICP Hub Bulgaria",
                "vote": 0
              },
              {
                "id": "7446549063176501841",
                "name": "Gold DAO",
                "vote": 1
              },
              {
                "id": "8571487073262291504",
                "name": "NeuronPool",
                "vote": 1
              },
              {
                "id": "16459595263909468577",
                "name": "LORIMER ♾️ 🐶",
                "vote": 1
              },
              {
                "id": "16122208542864232355",
                "name": "B3Pay",
                "vote": 1
              },
              {
                "id": "3172308420039087400",
                "name": "ZenithCode",
                "vote": 0
              },
              {
                "id": "12093733865587997066",
                "name": "Aviate Labs",
                "vote": 0
              },
              {
                "id": "4713806069430754115",
                "name": "D-QUORUM",
                "vote": 1
              },
              {
                "id": "16673157401414569992",
                "name": "Yuku AI",
                "vote": 0
              },
              {
                "id": "3099449518038519101",
                "name": "Cosmicrafts",
                "vote": 1
              },
              {
                "id": "5371276303191057244",
                "name": "1e0",
                "vote": 1
              },
              {
                "id": "33138099823745946",
                "name": "CO.DELTA △",
                "vote": 1
              },
              {
                "id": "12977943926061800402",
                "name": "DragginCorp",
                "vote": 1
              },
              {
                "id": "1637856224910350276",
                "name": "Gwojda",
                "vote": 1
              },
              {
                "id": "2334327054503903846",
                "name": "Thyassa",
                "vote": 1
              }
            ],
            "latest_tally": {
              "no": 63497607294091,
              "timestamp_seconds": 1755460866,
              "total": 46334384189105008,
              "yes": 42674270141132169
            },
            "payload": {
              "arg_hash": "0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e",
              "canister_id": "mqygn-kiaaa-aaaar-qaadq-cai",
              "install_mode": 3,
              "install_mode_name": "CANISTER_INSTALL_MODE_UPGRADE",
              "skip_stopping_before_installing": false,
              "wasm_module_hash": "b9688aed7377dc6ec4ec33cb303d73355ee47f2a1faea2bfc111abe2c7fa3186"
            },
            "proposal_id": 137875,
            "proposal_timestamp_seconds": 1755116781,
            "proposer": "17212304975669116357",
            "reject_cost_e8s": 2500000000,
            "reward_status": "SETTLED",
            "settled_at": 1755532800,
            "status": "EXECUTED",
            "summary": "# Proposal to upgrade the ckBTC minter canister\n\nRepository: `https://github.com/dfinity/ic.git`\n\nGit hash: `1db8f933fdadc81a90e7db2389b081e21263a9b6`\n\nNew compressed Wasm hash: `b9688aed7377dc6ec4ec33cb303d73355ee47f2a1faea2bfc111abe2c7fa3186`\n\nUpgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`\n\nTarget canister: `mqygn-kiaaa-aaaar-qaadq-cai`\n\nPrevious ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/137163\n\n---\n\n## Motivation\n\nUpgrade the ckBTC minter to ensure that a transaction signed by the minter does not use too many inputs.\nOtherwise, the resulting transaction may be *non-standard* as the resulting transaction size may be above 100k vbytes,\nwhich implies that the transaction will not be relayed by Bitcoin nodes and this transaction will be effectively stuck.\nThis is currently the case for transaction `87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30`.\n\nThis is a stop-gap solution until a proper solution is implemented.\n\n## Release Notes\n\n```\ngit log --format='%C(auto) %h %s' 47c5931cdafd82167feee85faf1e1dffa30fc3d8..1db8f933fdadc81a90e7db2389b081e21263a9b6 -- rs/bitcoin/ckbtc/minter\n1db8f933fd fix(ckbtc): prevent signing transaction with too many inputs (#6260)\n55ec0283bb build: update ic0 to v1.0.0. (#6216)\n ```\n\n## Upgrade args\n\n```\ngit fetch\ngit checkout 1db8f933fdadc81a90e7db2389b081e21263a9b6\ndidc encode '()' | xxd -r -p | sha256sum\n```\n\n## Wasm Verification\n\nVerify that the hash of the gzipped WASM matches the proposed hash.\n\n```\ngit fetch\ngit checkout 1db8f933fdadc81a90e7db2389b081e21263a9b6\n\"./ci/container/build-ic.sh\" \"--canisters\"\nsha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz\n```\n",
            "title": "Upgrade NNS Canister: mqygn-kiaaa-aaaar-qaadq-cai to wasm with hash: b9688aed7377dc6ec4ec33cb303d73355ee47f2a1faea2bfc111abe2c7fa3186",
            "topic": "TOPIC_NETWORK_CANISTER_MANAGEMENT",
            "total_potential_voting_power": 50559286701411626,
            "updated_at": "2025-08-18T16:01:25.884819",
            "url": ""
        }
        "##;

        let proposal_info: ProposalInfo = serde_json::from_str(json_info).unwrap();

        assert_eq!(
            proposal_info,
            ProposalInfo {
                proposal_id: 137875,
                payload: ProposalPayloadInfo {
                    canister_id: "mqygn-kiaaa-aaaar-qaadq-cai".to_string(),
                    install_mode_name: "CANISTER_INSTALL_MODE_UPGRADE".to_string(),
                },
            }
        );
    }
}
