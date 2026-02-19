import Debug "mo:base/Debug";
import Cycles "mo:base/ExperimentalCycles";
import Nat64 "mo:base/Nat64";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import JSON "mo:json.mo";

import EvmRpc "declarations/evm_rpc";

module {
    type HttpHeader = {
        name : Text;
        value : Text;
    };

    public type RpcService = EvmRpc.RpcService;
    public type RpcError = EvmRpc.RpcError;
    public type JsonRpcError = EvmRpc.JsonRpcError;
    public type ProviderError = EvmRpc.ProviderError;
    public type HttpOutcallError = EvmRpc.HttpOutcallError;
    public type ValidationError = EvmRpc.ValidationError;

    public type Error = ProviderError or HttpOutcallError or ValidationError or {
        #JsonRpcError : JsonRpcError;
    };

    public type RpcResult<T> = {
        #ok : T;
        #err : Error;
    };

    public type RpcActor = actor {
        request : shared (RpcService, Text, Nat64) -> async {
            #Ok : Text;
            #Err : RpcError;
        };
    };

    public type Provider = {
        #Canister : RpcActor;
        #Principal : Principal;
    };

    func unwrapError(rpcError : RpcError) : Error {
        switch rpcError {
            case (#ProviderError e) { e };
            case (#HttpOutcallError e) { e };
            case (#JsonRpcError e) { #JsonRpcError e };
            case (#ValidationError e) { e };
        };
    };

    public class Rpc(provider : Provider, service : RpcService) = this {

        public var defaultCycles = 1_000_000_000;

        let actor_ = switch provider {
            case (#Canister a) { a };
            case (#Principal p) { actor (Principal.toText(p)) : RpcActor };
        };

        var nextId : Nat = 0;
        public func request(method : Text, params : JSON.JSON, maxResponseBytes : Nat64) : async RpcResult<JSON.JSON> {
            nextId += 1;
            // prettier-ignore
            let payload = JSON.show(#Object([
                ("id", #Number(nextId)),
                ("jsonrpc", #String("2.0")),
                ("method", #String(method)),
                ("params", params),
            ]));
            switch (await requestPlain(payload, maxResponseBytes)) {
                case (#ok text) {
                    switch (JSON.parse(text)) {
                        case (?json) { #ok json };
                        case null {
                            #err(
                                #InvalidHttpJsonRpcResponse {
                                    status = 0;
                                    body = text;
                                    parsingError = ?("error while parsing JSON response");
                                }
                            );
                        };
                    };
                };
                case (#err err) { #err err };
            };
        };

        public func requestPlain(payload : Text, maxResponseBytes : Nat64) : async RpcResult<Text> {
            func requestPlain_(payload : Text, maxResponseBytes : Nat64, cycles : Nat) : async RpcResult<Text> {
                Cycles.add<system>(cycles);
                switch (await actor_.request(service, payload, maxResponseBytes)) {
                    case (#Ok ok) { #ok ok };
                    case (#Err err) { #err(unwrapError(err)) };
                };
            };
            switch (await requestPlain_(payload, maxResponseBytes, defaultCycles)) {
                case (#err(#TooFewCycles { expected })) {
                    debug {
                        Debug.print("Retrying with " # (debug_show expected) # " cycles");
                    };
                    await requestPlain_(payload, maxResponseBytes, expected);
                };
                case r r;
            };
        };
    };
};
