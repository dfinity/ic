use crate::tests::mock::{MockLogger, MockRuntime};
use crate::types::candid::{
    Block, BlockTag, MultiRpcResult, ProviderError, RpcConfig, RpcError, RpcServices,
};
use crate::EvmRpcClient;
use mockall::Sequence;

#[tokio::test]
async fn should_not_retry_when_no_cycles_error() {
    let mut runtime = MockRuntime::new();
    let min_attached_cycles = 3_000_000_000_u128;
    let expected_result = MultiRpcResult::Consistent(Ok(a_block()));
    runtime
        .expect_call::<_, MultiRpcResult<Block>>()
        .times(1)
        .withf(
            move |_, method, _: &(RpcServices, Option<RpcConfig>, BlockTag), attached_cycles| {
                method == "eth_getBlockByNumber" && attached_cycles == &min_attached_cycles
            },
        )
        .return_const(Ok(expected_result.clone()));

    let client = test_client(runtime, min_attached_cycles, 3);
    let result = client.eth_get_block_by_number(BlockTag::Finalized).await;

    assert_eq!(result, expected_result);
}

#[tokio::test]
async fn should_retry_when_cycles_error() {
    let mut runtime = MockRuntime::new();
    let min_attached_cycles = 3_000_000_000_u128;
    let expected_result =
        MultiRpcResult::Consistent(Err(RpcError::ProviderError(ProviderError::TooFewCycles {
            expected: min_attached_cycles + 1,
            received: min_attached_cycles,
        })));
    let mut seq = Sequence::new();
    runtime
        .expect_call::<_, MultiRpcResult<Block>>()
        .times(1)
        .in_sequence(&mut seq)
        .withf(
            move |_, method, _: &(RpcServices, Option<RpcConfig>, BlockTag), attached_cycles| {
                method == "eth_getBlockByNumber" && attached_cycles == &min_attached_cycles
            },
        )
        .return_const(Ok(expected_result.clone()));

    let expected_result = MultiRpcResult::Consistent(Ok(a_block()));
    runtime
        .expect_call::<_, MultiRpcResult<Block>>()
        .times(1)
        .in_sequence(&mut seq)
        .withf(
            move |_, method, _: &(RpcServices, Option<RpcConfig>, BlockTag), attached_cycles| {
                method == "eth_getBlockByNumber" && attached_cycles == &(2 * min_attached_cycles)
            },
        )
        .return_const(Ok(expected_result.clone()));

    let client = test_client(runtime, min_attached_cycles, 1);
    let result = client.eth_get_block_by_number(BlockTag::Finalized).await;

    assert_eq!(result, expected_result);
}

#[tokio::test]
async fn should_not_retry_when_max_num_retries_reached() {
    let mut runtime = MockRuntime::new();
    let min_attached_cycles = 3_000_000_000_u128;
    let expected_result =
        MultiRpcResult::Consistent(Err(RpcError::ProviderError(ProviderError::TooFewCycles {
            expected: min_attached_cycles + 1,
            received: min_attached_cycles,
        })));
    let mut seq = Sequence::new();
    runtime
        .expect_call::<_, MultiRpcResult<Block>>()
        .times(1)
        .in_sequence(&mut seq)
        .withf(
            move |_, method, _: &(RpcServices, Option<RpcConfig>, BlockTag), attached_cycles| {
                method == "eth_getBlockByNumber" && attached_cycles == &min_attached_cycles
            },
        )
        .return_const(Ok(expected_result.clone()));

    let expected_result =
        MultiRpcResult::Consistent(Err(RpcError::ProviderError(ProviderError::TooFewCycles {
            expected: 2 * min_attached_cycles + 1,
            received: 2 * min_attached_cycles,
        })));
    runtime
        .expect_call::<_, MultiRpcResult<Block>>()
        .times(1)
        .in_sequence(&mut seq)
        .withf(
            move |_, method, _: &(RpcServices, Option<RpcConfig>, BlockTag), attached_cycles| {
                method == "eth_getBlockByNumber" && attached_cycles == &(2 * min_attached_cycles)
            },
        )
        .return_const(Ok(expected_result.clone()));

    let client = test_client(runtime, min_attached_cycles, 1);
    let result = client.eth_get_block_by_number(BlockTag::Finalized).await;

    assert_eq!(result, expected_result);
}

mod max_expected_too_few_cycles_error {
    use super::*;
    use crate::max_expected_too_few_cycles_error;
    use crate::types::candid::{RpcApi, RpcService};

    #[test]
    fn should_get_max_expected_too_few_cycles_for_custom_rpc_service() {
        let result: MultiRpcResult<()> = MultiRpcResult::Inconsistent(vec![
            (
                RpcService::Custom(RpcApi {
                    url: "https://eth.llamarpc.com".to_string(),
                    headers: None,
                }),
                Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                    expected: 701_433_600,
                    received: 350_729_600,
                })),
            ),
            (
                RpcService::Custom(RpcApi {
                    url: "https://ethereum-rpc.publicnode.com".to_string(),
                    headers: None,
                }),
                Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                    expected: 893_894_400,
                    received: 350_729_600,
                })),
            ),
            (
                RpcService::Custom(RpcApi {
                    url: "https://rpc.ankr.com/eth".to_string(),
                    headers: None,
                }),
                Err(RpcError::ProviderError(ProviderError::TooFewCycles {
                    expected: 893_894_400,
                    received: 350_729_600,
                })),
            ),
        ]);

        let max_too_few_cycles = max_expected_too_few_cycles_error(&result);

        assert_eq!(max_too_few_cycles, Some(893_894_400));
    }
}

fn a_block() -> Block {
    Block {
        base_fee_per_gas: 8_876_901_983_u64.into(),
        number: 20_061_336_u32.into(),
        difficulty: 0_u8.into(),
        extra_data: "0xd883010d0e846765746888676f312e32312e36856c696e7578".to_string(),
        gas_limit: 30_000_000_u32.into(),
        gas_used: 2_858_256_u32.into(),
        hash: "0x3a68e81a96d436f421b7cae6a66f78f6aef075340edaec5c7c1db0919c0f909b".to_string(),
        logs_bloom: "0x006000060010410010180000940006000000200040006108008801008022000900a005820000001100000300000d058962202900084080a0000031080022800000480c08100000006800000a20002028841080209044003041000940802448100002002a820085000000008400200d40204c10110810040403000210020004000a20208028104110a48429100033080e000040050501004800850042405230204230800000a0202282019080040040090a858000014014800440000208000008081804124002800030002040080610c000050002502000100005000a08002000001020500100804612440042300c0080040812000a1208420108200000000045".to_string(),
        miner: "0xd2732e3e4c264ab330af53f661f6da91cbbb594a".to_string(),
        mix_hash: "0x472d18a0b90d7007028dded03d7ef9923c2a7fc60f7e276bc6928fa9aeb6cbe8".to_string(),
        nonce: 0_u8.into(),
        parent_hash: "0xc0debe594704702ec9c2e5a56595ccbc285305108286a6a19aa33f8b3755da65".to_string(),
        receipts_root: "0x54179d043f2fe97f122a01366cd6ad18868501253282575fb00cada3fecf8fe1".to_string(),
        sha3_uncles: "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347".to_string(),
        size: 17_484_u32.into(),
        state_root: "0x1e25cbd8eb25aadda3da160fd9b3fd46dfae61d7df1097d7990ca420e5c7c608".to_string(),
        timestamp: 1_718_021_363_u32.into(),
        total_difficulty: 58_750_003_716_598_352_816_469_u128.into(),
        transactions: vec![
            "0x5f17526ee5ab415ed44aa3788f0e8154230faa50f8b6d547a95858a8a90f259e",
            "0x1d0d559a2e113a4a4b738c97536c48e4a047a491614ddefe77c6e0f25b9e3a42",
            "0xd8c4f005fd4c7832205f6eda9bfde5bc5f9e0a1002b325d02348889f39e21850",
            "0xee14faac7f1d05a71ce69b11116a2ed8bf7a020a7b81a6a7a82096fdea7823a5",
            "0x63725de23700e115a48cb969a9e26eea56a65a971d63a21cc9cc660aa0cf4204",
            "0x77cbe1a9c3aef1ee9f345de7c189e9631e5458b194ba91ab2d9dc6d625e7eb68",
            "0x0e3403dcc6dea9dec03203ed9b1b89c66fd606abe3ac8bb33ed440283e5444cb",
            "0x91935e9885348f1ec4d673532c4f6709a28298f804b8054dea406407b00566af",
            "0x728b9eab683e4a59e75ebe03f1f9cdf081c04bc57f505cd8fc157a282e299c08",
            "0xb00dfcae52ef97f4f80965603f7c3a4c7f8c58e3e12caf6b636a522d0fbfef86",
            "0x604737ccc8f69cd4c1cd4c1e8f62655272d0a6db98923e907a5b0404d1822df4",
            "0x079ffeb1040d2490e248eb85047422bf3519c5fb5e3632ec3f245217c540a4b1",
            "0xd0c5a03b82d2b7cb62be59cb691cf5f6b0940b433360545e23e55044741f51dd",
            "0xe5707c1a13739613acec865053b88a03d7417004dec6086b544d92f4d9235880",
            "0x8f8541fa86b636d26b620c15741095e2920c27545b4b42efde1e15a702f99a00",
            "0x763b7f0bde974974d96e2ae1c9bee1bea8841acebf7c188477b198c93022f797",
            "0x9e518c8ced080b6d25836b506a5424ff98ca1933637e7586dd9464c48930880a",
            "0x08467c33ab74e9a379d63cbb1a03097c7cde7f85a166e60804c855cfd8bdcb96",
            "0x38928c665e5c62509066deaffcc94d497928b26bfef33d570a92b09af3a6cbbd",
            "0x2c616b1f2aa52a5f481d8aa5ebe0991f1f03d5c676f1b92cd03496ce753a5ae2",
            "0x3a4cf1999fe714e2be26f12a05270d85bb2033ee787727b94e5a7a3494e45f59",
            "0x8b3fc42aa0de7d0a181829229bc6ec8a5dd6c5d096945c0a2d149dd48a38e94a",
            "0xf1a3521cb1c73ae3bf5af18e25fdff023adabeea83503f73ca8721ce6ea27bfa",
            "0xff3265ddf367f97b50f95e4295bd101914fced55677315dee6c7618e31c721b6",
            "0xe6cc4470987f866cbddfe8e47a069a803fbda1b71055c49e96e78bdbe0cf1462",
            "0xccb8d52db4861b571240d71a58ba6cf8ea8e06567b82d68d517d383753cd8c65",
            "0x7c620a3c26299632c513f3940aae5dc971d1bedc93f669482e760cf4a86e25ee",
            "0xc2b265b37be476a291c87f10913960fe7ac790796248fb07e39fa40502e9fc03",
            "0x78083d9907ab4136e7df0cc266e4a6cddc4cf9e62948d5ab6bf81821ed26f45e",
            "0xf3776413512018e401b49b4661ecfd3f6daabe4aa52b3ae158ef8f10be424ca1",
            "0x53bc3267ef9f8f5a2d7be33f111391cbee7f13390de9bd531f5f216eef13582d",
            "0x6fc125dda0b34acd12f72fc5980fa5250ed1cfa985e60f5535123e7bfe82baca",
            "0xf9ace1b33ed117617cdae76a79a8fa758a8f3817c3aaf245a94953f565001d8a",
            "0xb186f79d1d6218ce61715f579ae2bde0582dede16d0ef9cf1cd85735f05445ea",
            "0x75e69b143d0fb26e4113c2dd0c2f702b2e917b5c23d81aaf587243525ef56e5a",
            "0xe6595bcb2ae614d890d38d153057826c3ad08063332276fa1b16e5f13b06e7a2",
            "0xd473fc760fb6cd8c81b7fe26e1bb6114d95957be22a713e1aac2cc63c2a3f0a3",
            "0x132d23074d8442c60337018bba749e0479f49b3d99a449934031289de6bd4587",
            "0xcead5cec4d5a30b28af721d8efbf77f05261daf76f60bc36298dbdc2793af703",
            "0x8b5b553313660e25a9a357c050576122e6d697314b1044f19f076df0d33f9823",
            "0xd73e844cd930c7463023fcc2eab8e40de90a5476f1c69d9466f506ec0a1c6953",
            "0x70bf1aed5af719155b036b0d761b86610e22855f60279982d1ca83c2c1493861",
            "0x5c2f23360e5247942d0b5150745cb4d8692de92e0fcb3cdfedff0341ff1f3a8e",
            "0x1c2eaceb326006f77142e3ffacc660d17b5b1ccf0ef2d22026149b9973d03752",
            "0x27f087175f96f9169e5e5320dffc920bab0181958df8385a143ac1ce9b7703a5",
            "0x672608a35f4fa4bb65955138521a887a892b0cd35d09f0359d00fdfa5cf427fd",
            "0x3b8942ca076f4e4e3e6222b577da88d888c79768d337bef14de6d75ba2540d11",
            "0x7e1614b107c5a7adc7478198b2d99d3dee48e443f1f475524479aee0a4c9e402",
            "0x5f9c5284a47ed5a6f6e672d48fea29966b3d91d63487ab47bc8f5514f231e687",
            "0x3715bb37c438c4e95fab950f573d184770faf8019018d2b47d6220003f0b35d0",
            "0x33137040d80df84243b63833eea5b34a505a2ca8fb1a34318b74cecf5f4aa7c8",
            "0x470940a47746125aae7513cb22bdac628865ee3df34e99bd0ecd48ff23b47f41",
            "0x875c9fda2e0ccffde973385ee72d106f1fea12fda8d250f55a85007e13422e40",
            "0xd3a08793b023ff2eb5c3e1d9b90254172a796095972d8dc2714cc094f6fc6c19",
            "0x135366e9141a1b871e73941f00c2e321b4ab51c99d58b95f1b201f30c3f7d0d2",
            "0xc93ec0af7511a39dfe389fb37d21144914c99ddc8d259e47146e8b45d288e8f8",
            "0x6ba2a677ff759be8e76f42e1b5d009b5a39f186fa417f00679105059b4cc725c",
            "0x8657b391f8575ab4f7323a5e24e3ca53df61cb433cf88cbef40000c05badedc7",
            "0x6e14d76d37b4dab55b5e49276b207b0e4f117ef8103728f8dadc487996e30c34",
            "0xac4489a73246f8f81503e11254003158893785ae4a603eedddec8b23945d3630",
            "0x50b5e07019621c041d061df0dc447674d719391862238c25181fd45f4bea441c",
            "0x424431243694085158cdcf5ed1666b88421fb3c7fde538acf36f8ea8316d827b",
            "0xf1d5e8256194f29e7da773ea8ef9e60ba7c5ceb7fb9ab9966d2c7b53d4c347ff",
            "0x25f85c5fcda53d733bf0dafe552984b0e17e5202fe9225a9a1bf94b50575e5d8",
            "0xe2499f7bbc8acdc3f273ac29f7757071844b739d2a84ab19440a9b1a3cbe901d",
            "0x25525be1316671638e2b6146f3e3259be8dee11cf8a24cb64b0feb2ad7f1ebf9",
            "0x0518268fb4b06a1285997efb841615a74d113571332ac7c935d2a303ca1d6f23",
            "0x1510c9bf4678ec3e67d05c908ba6d2762c4a815476638cc1d281d65a7dab6745"
        ].into_iter().map(|s| s.to_string()).collect(),
        transactions_root: Some("0xdee0b25a965ff236e4d2e89f56de233759d71ad3e3e150ceb4cf5bb1f0ecf5c0".to_string()),
        uncles: vec![],
    }
}

fn test_client(
    runtime: MockRuntime,
    min_attached_cycles: u128,
    max_num_retries: u32,
) -> EvmRpcClient<MockRuntime, MockLogger> {
    EvmRpcClient::builder(runtime, printable_logger())
        .with_min_attached_cycles(min_attached_cycles)
        .with_max_num_retries(max_num_retries)
        .build()
}

fn printable_logger() -> MockLogger {
    let mut logger = MockLogger::new();
    logger
        .expect_append()
        .withf(|entry| {
            println!(
                "{} {}:{} {}",
                entry.timestamp, entry.file, entry.line, entry.message
            );
            true
        })
        .return_const(());
    logger
}

mod mock {
    use crate::Runtime;
    use async_trait::async_trait;
    use candid::utils::ArgumentEncoder;
    use candid::{CandidType, Principal};
    use ic_canister_log::{LogEntry, Sink};
    use ic_cdk::api::call::RejectionCode;
    use mockall::mock;
    use serde::de::DeserializeOwned;

    mock! {
        pub Runtime{}

         #[async_trait]
        impl Runtime for Runtime {
            async fn call<In, Out>(
                &self,
                id: Principal,
                method: &str,
                args: In,
                cycles: u128,
            ) -> Result<Out, (RejectionCode, String)>
            where
                In: ArgumentEncoder + Send + 'static,
                Out: CandidType + DeserializeOwned + 'static;
        }
    }

    mock! {
        pub Logger{}

        impl Sink for Logger {
            fn append(&self, entry: LogEntry);
        }
    }
}
