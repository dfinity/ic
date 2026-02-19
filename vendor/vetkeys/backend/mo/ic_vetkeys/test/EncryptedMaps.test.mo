import VetKey "../src";
import { EncryptedMaps } "../src";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Blob "mo:base/Blob";
import { test } "mo:test";

type EncryptedMaps = VetKey.EncryptedMaps.EncryptedMaps<VetKey.AccessRights>;
func newEncryptedMaps() : EncryptedMaps {
    let encryptedMapsState = EncryptedMaps.newEncryptedMapsState<VetKey.AccessRights>({ curve = #bls12_381_g2; name = "dfx_test_key" }, "encrypted maps");
    EncryptedMaps.EncryptedMaps<VetKey.AccessRights>(encryptedMapsState, VetKey.accessRightsOperations());
};

let p1 = Principal.fromText("2vxsx-fae");
let p2 = Principal.fromText("aaaaa-aa");
let mapName = Text.encodeUtf8("some map");
let mapKey = Text.encodeUtf8("some key");
let mapValue = Text.encodeUtf8("some value");

test(
    "can remove map values",
    func() {
        let encryptedMaps = newEncryptedMaps();
        let result = encryptedMaps.removeMapValues(p1, (p1, mapName));
        switch (result) {
            case (#ok(keys)) {
                assert keys == [];
            };
            case (#err(e)) {
                Debug.trap("Failed to remove map values: " # e);
            };
        };
    },
);

test(
    "unauthorized delete map values fails",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Insert a value first
        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, mapValue)) {
            case (#err(e)) { Debug.trap("Failed to insert value: " # e) };
            case (#ok(_)) {};
        };

        // Try to remove with unauthorized user
        let result = encryptedMaps.removeMapValues(p2, (p1, mapName));
        assert result == #err("unauthorized");
    },
);

test(
    "can add user to map",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Check initial state
        switch (encryptedMaps.getUserRights(p1, (p1, mapName), p2)) {
            case (#ok(null)) {};
            case (unexpected) {
                Debug.trap("Unexpected initial state: " # debug_show (unexpected));
            };
        };

        // Set user rights
        switch (encryptedMaps.setUserRights(p1, (p1, mapName), p2, #ReadWriteManage)) {
            case (#ok(null)) {};
            case (unexpected) {
                Debug.trap("Failed to set user rights: " # debug_show (unexpected));
            };
        };

        // Verify rights were set
        switch (encryptedMaps.getUserRights(p1, (p1, mapName), p2)) {
            case (#ok(?#ReadWriteManage)) {};
            case (unexpected) {
                Debug.trap("Failed to verify user rights: " # debug_show (unexpected));
            };
        };
    },
);

test(
    "unauthorized cannot invoke operations",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Try various operations with unauthorized user
        assert encryptedMaps.getUserRights(p2, (p1, mapName), p2) == #err("unauthorized");
        assert encryptedMaps.getEncryptedValue(p2, (p1, mapName), mapKey) == #err("unauthorized");
        assert encryptedMaps.getEncryptedValuesForMap(p2, (p1, mapName)) == #err("unauthorized");
        assert encryptedMaps.removeMapValues(p2, (p1, mapName)) == #err("unauthorized");
        assert encryptedMaps.removeUser(p2, (p1, mapName), p2) == #err("unauthorized");
        assert encryptedMaps.setUserRights(p2, (p1, mapName), p2, #Read) == #err("unauthorized");

        assert encryptedMaps.insertEncryptedValue(p2, (p1, mapName), mapKey, mapValue) == #err("unauthorized");

        // Give read access and verify still can't write
        switch (encryptedMaps.setUserRights(p1, (p1, mapName), p2, #Read)) {
            case (#ok(_)) {};
            case (#err(e)) { Debug.trap("Failed to set read access: " # e) };
        };

        assert encryptedMaps.insertEncryptedValue(p2, (p1, mapName), mapKey, mapValue) == #err("unauthorized");

        assert encryptedMaps.setUserRights(p2, (p1, mapName), p2, #Read) == #err("unauthorized");
    },
);

test(
    "can remove user from map",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Add user first
        switch (encryptedMaps.setUserRights(p1, (p1, mapName), p2, #ReadWriteManage)) {
            case (#ok(null)) {};
            case (unexpected) {
                Debug.trap("Failed to add user: " # debug_show (unexpected));
            };
        };

        // Remove user
        switch (encryptedMaps.removeUser(p1, (p1, mapName), p2)) {
            case (#ok(?#ReadWriteManage)) {};
            case (unexpected) {
                Debug.trap("Failed to remove user: " # debug_show (unexpected));
            };
        };
    },
);

test(
    "can add a key to map",
    func() {
        let encryptedMaps = newEncryptedMaps();

        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, mapValue)) {
            case (#ok(null)) {};
            case (unexpected) {
                Debug.trap("Failed to add key: " # debug_show (unexpected));
            };
        };
    },
);

test(
    "can remove a key from map",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Add key first
        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, mapValue)) {
            case (#ok(_)) {};
            case (#err(e)) { Debug.trap("Failed to add key: " # e) };
        };

        // Remove key
        switch (encryptedMaps.removeEncryptedValue(p1, (p1, mapName), mapKey)) {
            case (#ok(?_)) {};
            case (unexpected) {
                Debug.trap("Failed to remove key: " # debug_show (unexpected));
            };
        };
    },
);

test(
    "can access map values",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Add a key-value pair
        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, mapValue)) {
            case (#ok(_)) {};
            case (#err(e)) { Debug.trap("Failed to add key-value pair: " # e) };
        };

        for (accessRights in [#Read, #ReadWrite, #ReadWriteManage].vals()) {
            // Give read access to p2
            switch (encryptedMaps.setUserRights(p1, (p1, mapName), p2, accessRights)) {
                case (#ok(_)) {};
                case (#err(e)) { Debug.trap("Failed to set read access: " # e) };
            };

            // Verify p2 can read
            switch (encryptedMaps.getEncryptedValue(p2, (p1, mapName), mapKey)) {
                case (#ok(?_)) {};
                case (unexpected) {
                    Debug.trap("Failed to read value: " # debug_show (unexpected));
                };
            };
        };
    },
);

test(
    "can modify a key value in map",
    func() {
        let encryptedMaps = newEncryptedMaps();
        let newValue = Text.encodeUtf8("new value");

        // Add initial value
        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, mapValue)) {
            case (#ok(_)) {};
            case (#err(e)) { Debug.trap("Failed to add initial value: " # e) };
        };

        // Modify value
        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, newValue)) {
            case (#ok(?_)) {};
            case (unexpected) {
                Debug.trap("Failed to modify value: " # debug_show (unexpected));
            };
        };

        switch (encryptedMaps.getEncryptedValue(p1, (p1, mapName), mapKey)) {
            case (#ok(?returnedNewValue)) {
                assert returnedNewValue == newValue;
            };
            case (unexpected) {
                Debug.trap("Failed to get value: " # debug_show (unexpected));
            };
        };
    },
);

test(
    "can get owned map names",
    func() {
        let encryptedMaps = newEncryptedMaps();

        // Initially no maps
        assert encryptedMaps.getOwnedNonEmptyMapNames(p1) == [];

        // Add a key-value pair
        switch (encryptedMaps.insertEncryptedValue(p1, (p1, mapName), mapKey, mapValue)) {
            case (#ok(_)) {};
            case (#err(e)) { Debug.trap("Failed to add key-value pair: " # e) };
        };

        // Verify map appears in owned maps
        let ownedMaps = encryptedMaps.getOwnedNonEmptyMapNames(p1);
        assert ownedMaps.size() == 1;
        assert Blob.equal(ownedMaps[0], mapName);
    },
);
