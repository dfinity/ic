import EvmRpc "canister:evm_rpc";
import EvmRpcStaging "canister:evm_rpc_staging";

import Buffer "mo:base/Buffer";
import Cycles "mo:base/ExperimentalCycles";
import Debug "mo:base/Debug";
import Nat32 "mo:base/Nat32";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Evm "mo:evm";

shared ({ caller = installer }) persistent actor class Main() {
    type TestCategory = { #staging; #production };

    // (`subnet name`, `nodes in subnet`, `expected cycles for JSON-RPC call`)
    type SubnetTarget = (Text, Nat32, Nat);
    transient let fiduciarySubnet : SubnetTarget = ("fiduciary", 34, 400_299_200);

    transient let testTargets = [
        // (`canister module`, `canister type`, `subnet`)
        (EvmRpc, #production, fiduciarySubnet),
        (EvmRpcStaging, #staging, fiduciarySubnet),
    ];

    // (`RPC service`, `method`)
    transient let ignoredTests = [
        (#EthMainnet(#BlockPi), ?"eth_sendRawTransaction"), // "Private transaction replacement (same nonce) with gas price change lower than 10% is not allowed within 30 sec from the previous transaction."
        (#EthMainnet(#Llama), ?"eth_sendRawTransaction"), // Non-standard error message
        (#ArbitrumOne(#Ankr), null), // Need API key
        (#BaseMainnet(#Ankr), null), // Need API key
        (#EthMainnet(#Ankr), null), // Need API key
        (#OptimismMainnet(#Ankr), null), // Need API key
    ];

    func runTests(caller : Principal, category : TestCategory) : async () {
        assert caller == installer;

        let errors = Buffer.Buffer<Text>(0);
        var relevantTestCount = 0;
        let pending : Buffer.Buffer<async ()> = Buffer.Buffer(100);
        label targets for ((canister, testCategory, (subnetName, nodesInSubnet, expectedCycles)) in testTargets.vals()) {
            if (testCategory != category) {
                continue targets;
            };
            relevantTestCount += 1;

            let canisterType = debug_show category # " " # subnetName;
            Debug.print("Testing " # canisterType # " canister...");

            func addError(error : Text) {
                let message = "[" # canisterType # "] " # error;
                Debug.print(message);
                errors.add(message);
            };

            let mainnet = Evm.Rpc(
                #Canister canister,
                #EthMainnet(#PublicNode),
            );

            let service : EvmRpc.RpcService = #Custom {
                url = "https://ethereum-rpc.publicnode.com";
                headers = null;
            };
            let json = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_gasPrice\",\"params\":null,\"id\":1}";
            let maxResponseBytes : Nat64 = 1000;

            // Nodes in subnet
            let actualNodesInSubnet = await canister.getNodesInSubnet();
            if (actualNodesInSubnet != nodesInSubnet) {
                addError("Unexpected number of nodes in subnet (received " # debug_show actualNodesInSubnet # ", expected " # debug_show nodesInSubnet # ")");
            };

            // `requestCost()`
            let cyclesResult = await canister.requestCost(service, json, maxResponseBytes);
            let cycles = switch cyclesResult {
                case (#Ok cycles) { cycles };
                case (#Err err) {
                    Debug.trap("Unexpected error for `requestCost`: " # debug_show err);
                };
            };

            if (cycles != expectedCycles) {
                addError("Unexpected number of cycles: " # debug_show cycles # " (expected " # debug_show expectedCycles # ")");
            };

            // `request()` without cycles
            let resultWithoutCycles = await canister.request(service, json, maxResponseBytes);
            assert switch resultWithoutCycles {
                case (#Err(#ProviderError(#TooFewCycles { expected }))) expected == cycles;
                case _ false;
            };

            // `request()` with cycles
            let result = await mainnet.request("eth_gasPrice", #Array([]), 1000);
            label validate {
                switch result {
                    case (#ok(#Object fields)) {
                        for ((key, val) in fields.vals()) {
                            switch (key, val) {
                                case ("result", #String val) {
                                    assert Text.startsWith(val, #text "0x");
                                    break validate;
                                };
                                case _ {};
                            };
                        };
                    };
                    case _ {};
                };
                addError(debug_show result);
            };

            // `request()` without sufficient cycles
            let resultWithoutEnoughCycles = await canister.request(service, json, maxResponseBytes);
            Cycles.add<system>(cycles - 1);
            assert switch resultWithoutEnoughCycles {
                case (#Err(#ProviderError(#TooFewCycles { expected }))) expected == cycles;
                case _ false;
            };

            // Candid-RPC methods
            type RpcResult<T> = { #Ok : T; #Err : canister.RpcError };
            type MultiRpcResult<T> = {
                #Consistent : RpcResult<T>;
                #Inconsistent : [(canister.RpcService, RpcResult<T>)];
            };

            func assertOk<T>(networkName : Text, method : Text, result : MultiRpcResult<T>) {
                switch result {
                    case (#Consistent(#Ok _)) {};
                    case (#Consistent(#Err err)) {
                        addError("Received consistent error for " # networkName # " " # method # ": " # debug_show err);
                    };
                    case (#Inconsistent(results)) {
                        for ((service, result) in results.vals()) {
                            switch result {
                                case (#Ok(_)) {};
                                case (#Err(err)) {
                                    for ((ignoredService, ignoredMethod) in ignoredTests.vals()) {
                                        if (ignoredService == service and (ignoredMethod == null or ignoredMethod == ?method)) {
                                            Debug.print("Ignoring error from " # canisterType # " " # debug_show ignoredService # " " # (switch ignoredMethod {
                                                case null "*";
                                                case (?method) method;
                                            }));
                                            return;
                                        };
                                    };
                                    addError("Received error in inconsistent results for " # debug_show service # " " # method # ": " # debug_show err);
                                };
                            };
                        };
                    };
                };
            };

            // All RPC services suitable for E2E testing
            let mainnetServices = [#Ankr, #BlockPi, #PublicNode, #Llama];
            let l2Services = [#Ankr, #BlockPi, #PublicNode, #Llama];
            let allServices : [(Text, EvmRpc.RpcServices)] = [
                (
                    "Ethereum",
                    #EthMainnet(?mainnetServices),
                ),
                (
                    "Arbitrum",
                    #ArbitrumOne(?l2Services),
                ),
                (
                    "Base",
                    #BaseMainnet(?l2Services),
                ),
                (
                    "Optimism",
                    #OptimismMainnet(?l2Services),
                ),
            ];

            // Any unused cycles will be refunded
            let candidRpcCycles = 200_000_000_000;

            func testCandidRpc(networkName : Text, services : EvmRpc.RpcServices) : async () {
                switch (await canister.eth_getBlockByNumber(services, null, #Latest)) {
                    case (#Consistent(#Err(#ProviderError(#TooFewCycles _)))) {};
                    case result {
                        let expected = switch result {
                            case (#Inconsistent(results)) {
                                var expected = true;
                                for (result in results.vals()) {
                                    switch result {
                                        case (_service, #Err(#ProviderError(#TooFewCycles _))) {};
                                        case _ {
                                            expected := false;
                                        };
                                    };
                                };
                                expected;
                            };
                            case _ { false };
                        };
                        if (not expected) {
                            addError("Received unexpected `eth_getBlockByNumber` result for " # networkName # ": " # debug_show result);
                        };
                    };
                };

                Cycles.add<system>(candidRpcCycles);
                assertOk(
                    networkName,
                    "eth_getLogs",
                    await canister.eth_getLogs(
                        services,
                        null,
                        {
                            addresses = ["0xB9B002e70AdF0F544Cd0F6b80BF12d4925B0695F"];
                            fromBlock = ? #Number 19520540;
                            toBlock = ? #Number 19520940;
                            topics = ?[
                                ["0x4d69d0bd4287b7f66c548f90154dc81bc98f65a1b362775df5ae171a2ccd262b"],
                                [
                                    "0x000000000000000000000000352413d00d2963dfc58bc2d6c57caca1e714d428",
                                    "0x000000000000000000000000b6bc16189ec3d33041c893b44511c594b1736b8a",
                                ],
                            ];
                        },
                    ),
                );
                Cycles.add<system>(candidRpcCycles);
                assertOk(
                    networkName,
                    "eth_getBlockByNumber",
                    await canister.eth_getBlockByNumber(services, null, #Latest),
                );
                Cycles.add<system>(candidRpcCycles);
                assertOk(
                    networkName,
                    "eth_getTransactionReceipt",
                    await canister.eth_getTransactionReceipt(services, null, "0xdd5d4b18923d7aae953c7996d791118102e889bea37b48a651157a4890e4746f"),
                );
                Cycles.add<system>(candidRpcCycles);
                assertOk(
                    networkName,
                    "eth_getTransactionCount",
                    await canister.eth_getTransactionCount(
                        services,
                        null,
                        {
                            address = "0x1789F79e95324A47c5Fd6693071188e82E9a3558";
                            block = #Latest;
                        },
                    ),
                );
                Cycles.add<system>(candidRpcCycles);
                assertOk(
                    networkName,
                    "eth_feeHistory",
                    await canister.eth_feeHistory(
                        services,
                        null,
                        {
                            blockCount = 3;
                            newestBlock = #Latest;
                            rewardPercentiles = null;
                        },
                    ),
                );
                switch services {
                    case (#EthMainnet(_)) {
                        Cycles.add<system>(candidRpcCycles);
                        assertOk(
                            networkName,
                            "eth_sendRawTransaction",
                            await canister.eth_sendRawTransaction(
                                services,
                                null,
                                "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
                            ),
                        );
                    };
                    case _ {
                        // Skip sending transaction for non-Ethereum chains due to chain ID mismatch
                    };
                };
            };

            for ((name, services) in allServices.vals()) {
                pending.add(testCandidRpc(name, services));
            };
        };

        for (awaitable in pending.vals()) {
            await awaitable;
        };

        if (relevantTestCount == 0) {
            Debug.trap("No tests found for category: " # debug_show category);
        };

        if (errors.size() > 0) {
            var message = "Errors:";
            for (error in errors.vals()) {
                message #= "\n* " # error;
            };
            Debug.trap(message);
        };
    };

    public shared ({ caller }) func test() : async () {
        await runTests(caller, #staging);
    };

    public shared ({ caller }) func testProduction() : async () {
        await runTests(caller, #production);
    };
};
