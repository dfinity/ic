import IcVetkeys "mo:ic-vetkeys";
import Types "mo:ic-vetkeys/Types";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import Result "mo:base/Result";
import Array "mo:base/Array";

actor class (keyName : Text) {
    var keyManager = IcVetkeys.KeyManager.KeyManager<Types.AccessRights>({ curve = #bls12_381_g2; name = keyName }, "key manager", Types.accessRightsOperations());
    /// In this canister, we use the `ByteBuf` type to represent blobs. The reason is that we want to be consistent with the Rust canister implementation.
    /// Unfortunately, the `Blob` type cannot be serialized/deserialized in the current Rust implementation efficiently without nesting it in another type.
    public type ByteBuf = { inner : Blob };

    /// The result type compatible with Rust's `Result`.
    public type Result<Ok, Err> = {
        #Ok : Ok;
        #Err : Err;
    };

    public query (msg) func get_accessible_shared_key_ids() : async [(Principal, ByteBuf)] {
        Array.map<(Principal, Blob), (Principal, ByteBuf)>(
            keyManager.getAccessibleSharedKeyIds(msg.caller),
            func((principal, blob) : (Principal, Blob)) {
                (principal, { inner = blob });
            },
        );
    };

    public query (msg) func get_shared_user_access_for_key(
        key_owner : Principal,
        key_name : ByteBuf,
    ) : async Result<[(Principal, Types.AccessRights)], Text> {
        convertResult(keyManager.getSharedUserAccessForKey(msg.caller, (key_owner, key_name.inner)));
    };

    public shared func get_vetkey_verification_key() : async ByteBuf {
        let inner = await keyManager.getVetkeyVerificationKey();
        { inner };
    };

    public shared (msg) func get_encrypted_vetkey(
        key_owner : Principal,
        key_name : ByteBuf,
        transport_key : ByteBuf,
    ) : async Result<ByteBuf, Text> {
        let vetkeyBytebuf = await keyManager.getEncryptedVetkey(msg.caller, (key_owner, key_name.inner), transport_key.inner);
        switch (vetkeyBytebuf) {
            case (#err(e)) { #Err(e) };
            case (#ok(inner)) { #Ok({ inner }) };
        };
    };

    public query (msg) func get_user_rights(
        key_owner : Principal,
        key_name : ByteBuf,
        user : Principal,
    ) : async Result<?Types.AccessRights, Text> {
        convertResult(keyManager.getUserRights(msg.caller, (key_owner, key_name.inner), user));
    };

    public shared (msg) func set_user_rights(
        key_owner : Principal,
        key_name : ByteBuf,
        user : Principal,
        access_rights : Types.AccessRights,
    ) : async Result<?Types.AccessRights, Text> {
        convertResult(keyManager.setUserRights(msg.caller, (key_owner, key_name.inner), user, access_rights));
    };

    public shared (msg) func remove_user(
        key_owner : Principal,
        key_name : ByteBuf,
        user : Principal,
    ) : async Result<?Types.AccessRights, Text> {
        convertResult(keyManager.removeUserRights(msg.caller, (key_owner, key_name.inner), user));
    };

    /// Convert to the result type compatible with Rust's `Result`
    private func convertResult<Ok, Err>(result : Result.Result<Ok, Err>) : Result<Ok, Err> {
        switch (result) {
            case (#err(e)) { #Err(e) };
            case (#ok(o)) { #Ok(o) };
        };
    };
};
