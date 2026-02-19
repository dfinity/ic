/// The **KeyManager** backend is a support library for **vetKeys**.
///
/// **vetKeys** is a feature of the Internet Computer (ICP) that enables the derivation of **encrypted cryptographic keys**. This library simplifies the process of key retrieval, encryption, and controlled sharing, ensuring secure and efficient key management for canisters and users.
///
/// For an introduction to **vetKeys**, refer to the [vetKeys Overview](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/introduction).
///
/// ## Core Features
///
/// The **KeyManager** support library provides the following core functionalities:
///
/// - **Request an Encrypted Key:** Users can derive any number of **encrypted cryptographic keys**, secured using a user-provided **public transport key**. Each vetKey is associated with a unique **key id**.
/// - **Manage vetKey Sharing:** A user can **share their vetKeys** with other users while controlling access rights.
/// - **Access Control Management:** Users can define and enforce **fine-grained permissions** (read, write, manage) for each vetKey.
/// - **Uses Stable Storage:** The library persists key access information using **OrderedMap**, ensuring reliability across canister upgrades.
///
/// ## KeyManager Architecture
///
/// The **KeyManager** consists of two primary components:
///
/// 1. **Access Control Map** (`accessControl`): Maps `(Caller, KeyId)` to `T`, defining permissions for each user.
/// 2. **Shared Keys Map** (`sharedKeys`): Tracks which users have access to shared vetKeys.
///
/// ## Example Use Case
///
/// 1. **User A** requests a vetKey from KeyManager.
/// 2. KeyManager verifies permissions and derives an **encrypted cryptographic key**.
/// 3. **User A** securely shares access with **User B** using `setUserRights`.
/// 4. **User B** retrieves the key securely via `getEncryptedVetkey`.
///
/// ## Security Considerations
///
/// - vetKeys are derived **on demand** and constructed from encrypted vetKey shares.
/// - Only authorized users can access shared vetKeys.
/// - Stable storage ensures vetKeys persist across canister upgrades.
/// - Access control logic ensures only authorized users retrieve vetKeys or modify access rights.
///
/// ## Summary
/// `KeyManager` simplifies the usage of **vetKeys** on the ICP, providing a secure and efficient mechanism for **cryptographic key derivation, sharing, and management**.

import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import Debug "mo:base/Debug";
import OrderedMap "mo:base/OrderedMap";
import Result "mo:base/Result";
import Types "../Types";
import Text "mo:base/Text";
import Nat8 "mo:base/Nat8";
import ManagementCanister "../ManagementCanister";

module {
    /// The public verification key used to verify the authenticity of derived vetKeys.
    public type VetKeyVerificationKey = Blob;

    /// An encrypted cryptographic key derived using vetKD.
    public type VetKey = Blob;

    /// The owner of a vetKey, represented as a Principal.
    public type Owner = Principal;

    /// The caller requesting access to a vetKey, represented as a Principal.
    public type Caller = Principal;

    /// The name of a vetKey, used as part of the key identifier.
    public type KeyName = Blob;

    /// A unique identifier for a vetKey, consisting of the owner and key name.
    public type KeyId = (Owner, KeyName);

    /// The public transport key used to encrypt vetKeys for secure transmission.
    public type TransportKey = Blob;

    func compareKeyIds(a : KeyId, b : KeyId) : { #less; #greater; #equal } {
        let ownersCompare = Principal.compare(a.0, b.0);
        if (ownersCompare == #equal) {
            Blob.compare(a.1, b.1);
        } else {
            ownersCompare;
        };
    };

    func accessControlMapOps() : OrderedMap.Operations<Caller> {
        OrderedMap.Make<Caller>(Principal.compare);
    };

    func sharedKeysMapOps() : OrderedMap.Operations<KeyId> {
        OrderedMap.Make<KeyId>(compareKeyIds);
    };

    public type KeyManagerState<T> = {
        var accessControl : OrderedMap.Map<Principal, [(KeyId, T)]>;
        var sharedKeys : OrderedMap.Map<KeyId, [Principal]>;
        var vetKdKeyId : ManagementCanister.VetKdKeyid;
        domainSeparator : Text;
    };

    public func newKeyManagerState<T>(vetKdKeyId : ManagementCanister.VetKdKeyid, domainSeparator : Text) : KeyManagerState<T> {
        {
            var accessControl = accessControlMapOps().empty();
            var sharedKeys = sharedKeysMapOps().empty();
            var vetKdKeyId = vetKdKeyId;
            domainSeparator;
        };
    };

    /// See the module documentation for more information.
    public class KeyManager<T>(keyManagerState : KeyManagerState<T>, accessRightsOperations : Types.AccessControlOperations<T>) {
        let domainSeparatorBytes = Text.encodeUtf8(keyManagerState.domainSeparator);

        /// Retrieves all vetKey IDs shared with the given caller.
        /// This method returns a list of all vetKeys that the caller has access to.
        public func getAccessibleSharedKeyIds(caller : Caller) : [KeyId] {
            switch (accessControlMapOps().get(keyManagerState.accessControl, caller)) {
                case (null) { [] };
                case (?entries) {
                    Array.map<(KeyId, T), KeyId>(entries, func((keyId, _)) = keyId);
                };
            };
        };

        /// Retrieves a list of users with whom a given vetKey has been shared, along with their access rights.
        /// The caller must have appropriate permissions to view this information.
        public func getSharedUserAccessForKey(caller : Caller, keyId : KeyId) : Result.Result<[(Caller, T)], Text> {
            let canRead = ensureUserCanRead(caller, keyId);
            switch (canRead) {
                case (#err(msg)) { return #err(msg) };
                case (_) {};
            };

            let users = switch (sharedKeysMapOps().get(keyManagerState.sharedKeys, keyId)) {
                case (null) { return #ok([]) };
                case (?users) users;
            };

            let results = Buffer.Buffer<(Caller, T)>(0);
            for (user in users.vals()) {
                switch (getUserRights(caller, keyId, user)) {
                    case (#err(msg)) { return #err(msg) };
                    case (#ok(optRights)) {
                        switch (optRights) {
                            case (null) {
                                Debug.trap("bug: missing access rights");
                            };
                            case (?rights) {
                                results.add((user, rights));
                            };
                        };
                    };
                };
            };
            #ok(Buffer.toArray(results));
        };

        /// Retrieves the vetKD verification key for this canister.
        /// This key is used to verify the authenticity of derived vetKeys.
        public func getVetkeyVerificationKey() : async VetKeyVerificationKey {
            await ManagementCanister.vetKdPublicKey(null, domainSeparatorBytes, keyManagerState.vetKdKeyId);
        };

        /// Retrieves an encrypted vetKey for caller and key id.
        /// The vetKey is secured using the provided transport key and can only be accessed by authorized users.
        /// Returns an error if the caller is not authorized to access the vetKey.
        public func getEncryptedVetkey(caller : Caller, keyId : KeyId, transportKey : TransportKey) : async Result.Result<VetKey, Text> {
            switch (ensureUserCanRead(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    let principalBytes = Blob.toArray(Principal.toBlob(keyId.0));
                    let input = Array.flatten<Nat8>([
                        [Nat8.fromNat(Array.size<Nat8>(principalBytes))],
                        principalBytes,
                        Blob.toArray(keyId.1),
                    ]);

                    #ok(await ManagementCanister.vetKdDeriveKey(Blob.fromArray(input), domainSeparatorBytes, keyManagerState.vetKdKeyId, transportKey));
                };
            };
        };

        /// Retrieves the access rights a given user has to a specific vetKey.
        /// The caller must have appropriate permissions to view this information.
        public func getUserRights(caller : Caller, keyId : KeyId, user : Principal) : Result.Result<?T, Text> {
            switch (ensureUserCanGetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    #ok(
                        do ? {
                            if (Principal.equal(user, keyId.0)) {
                                accessRightsOperations.ownerRights();
                            } else {
                                let entries = accessControlMapOps().get(keyManagerState.accessControl, user)!;
                                let (k, rights) = Array.find<(KeyId, T)>(
                                    entries,
                                    func((k, rights)) = compareKeyIds(k, keyId) == #equal,
                                )!;
                                rights;
                            };
                        }
                    );
                };
            };
        };

        /// Grants or modifies access rights for a user to a given vetKey.
        /// Only the vetKey owner or a user with management rights can perform this action.
        /// The vetKey owner cannot change their own rights.
        public func setUserRights(caller : Caller, keyId : KeyId, user : Principal, accessRights : T) : Result.Result<?T, Text> {
            switch (ensureUserCanSetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    if (Principal.equal(caller, keyId.0) and Principal.equal(caller, user)) {
                        return #err("cannot change key owner's user rights");
                    };

                    // Update sharedKeys
                    let currentUsers = switch (sharedKeysMapOps().get(keyManagerState.sharedKeys, keyId)) {
                        case (null) { [] };
                        case (?users) { users };
                    };

                    let newUsers = switch (Array.indexOf<Principal>(user, currentUsers, Principal.equal)) {
                        case (?_) currentUsers;
                        case (null) Array.append<Principal>(currentUsers, [user]);
                    };

                    keyManagerState.sharedKeys := sharedKeysMapOps().put(keyManagerState.sharedKeys, keyId, newUsers);

                    // Update accessControl
                    let currentEntries = switch (accessControlMapOps().get(keyManagerState.accessControl, user)) {
                        case (null) { [] };
                        case (?entries) { entries };
                    };

                    var oldRights : ?T = null;
                    let newEntries = switch (
                        Array.indexOf<(KeyId, T)>(
                            (keyId, accessRightsOperations.ownerRights()),
                            currentEntries,
                            func(a, b) = compareKeyIds(a.0, b.0) == #equal,
                        )
                    ) {
                        case (?index) {
                            let mutCurrentEntries = Array.thaw<(KeyId, T)>(currentEntries);
                            oldRights := ?mutCurrentEntries[index].1;
                            mutCurrentEntries[index] := (keyId, accessRights);
                            Array.freeze(mutCurrentEntries);
                        };
                        case (null) {
                            Array.append<(KeyId, T)>(currentEntries, [(keyId, accessRights)]);
                        };
                    };
                    keyManagerState.accessControl := accessControlMapOps().put(keyManagerState.accessControl, user, newEntries);
                    #ok(oldRights);
                };
            };
        };

        /// Revokes a user's access to a shared vetKey.
        /// The vetKey owner cannot remove their own access.
        /// Only the vetKey owner or a user with management rights can perform this action.
        public func removeUserRights(caller : Caller, keyId : KeyId, user : Principal) : Result.Result<?T, Text> {
            switch (ensureUserCanSetUserRights(caller, keyId)) {
                case (#err(msg)) { #err(msg) };
                case (#ok(_)) {
                    if (Principal.equal(caller, user) and Principal.equal(caller, keyId.0)) {
                        return #err("cannot remove key owner");
                    };

                    // Update sharedKeys
                    let currentUsers = switch (sharedKeysMapOps().get(keyManagerState.sharedKeys, keyId)) {
                        case (null) { [] };
                        case (?users) { users };
                    };
                    let newUsers = Array.filter<Caller>(currentUsers, func(u) = not Principal.equal(u, user));
                    keyManagerState.sharedKeys := sharedKeysMapOps().put(keyManagerState.sharedKeys, keyId, newUsers);

                    // Update accessControl
                    let currentEntries = switch (accessControlMapOps().get(keyManagerState.accessControl, user)) {
                        case (null) { [] };
                        case (?entries) { entries };
                    };
                    let (newEntries, oldRights) = Array.foldRight<(KeyId, T), ([(KeyId, T)], ?T)>(
                        currentEntries,
                        ([], null),
                        func((k, r), (entries, rights)) {
                            if (compareKeyIds(k, keyId) == #equal) {
                                (entries, ?r);
                            } else {
                                (Array.append<(KeyId, T)>(entries, [(k, r)]), rights);
                            };
                        },
                    );
                    keyManagerState.accessControl := accessControlMapOps().put(keyManagerState.accessControl, user, newEntries);
                    #ok(oldRights);
                };
            };
        };

        /// Ensures that a user has read access to a vetKey before proceeding.
        /// Returns an error if the user is not authorized.
        public func ensureUserCanRead(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(keyManagerState.accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canRead(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        /// Ensures that a user has write access to a vetKey before proceeding.
        /// Returns an error if the user is not authorized.
        public func ensureUserCanWrite(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(keyManagerState.accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canWrite(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        /// Ensures that a user has permission to view user rights for a vetKey.
        /// Returns an error if the user is not authorized.
        private func ensureUserCanGetUserRights(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(keyManagerState.accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canGetUserRights(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };

        /// Ensures that a user has management access to a vetKey before proceeding.
        /// Returns an error if the user is not authorized.
        private func ensureUserCanSetUserRights(user : Principal, keyId : KeyId) : Result.Result<T, Text> {
            if (Principal.equal(user, keyId.0)) {
                return #ok(accessRightsOperations.ownerRights());
            };

            switch (accessControlMapOps().get(keyManagerState.accessControl, user)) {
                case (null) { #err("unauthorized") };
                case (?entries) {
                    for ((k, rights) in entries.vals()) {
                        if (compareKeyIds(k, keyId) == #equal) {
                            if (accessRightsOperations.canSetUserRights(rights)) {
                                return #ok(rights);
                            } else {
                                return #err("unauthorized");
                            };
                        };
                    };
                    #err("unauthorized");
                };
            };
        };
    };
};
