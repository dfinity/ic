import VetKey "../src";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import { test } "mo:test";

let accessRightsOperations = VetKey.accessRightsOperations();
let p1 = Principal.fromText("2vxsx-fae");
let p2 = Principal.fromText("aaaaa-aa");
let keyName = Text.encodeUtf8("some key");

func newKeyManager() : VetKey.KeyManager.KeyManager<VetKey.AccessRights> {
    let keyManagerState = VetKey.KeyManager.newKeyManagerState<VetKey.AccessRights>({ curve = #bls12_381_g2; name = "dfx_test_key" }, "key manager");
    VetKey.KeyManager.KeyManager<VetKey.AccessRights>(keyManagerState, accessRightsOperations);
};

test(
    "accessRightsOperations",
    func() {
        assert accessRightsOperations.canRead(#Read);
        assert not accessRightsOperations.canWrite(#Read);
        assert not accessRightsOperations.canSetUserRights(#Read);
        assert not accessRightsOperations.canGetUserRights(#Read);

        assert accessRightsOperations.canRead(#ReadWrite);
        assert accessRightsOperations.canWrite(#ReadWrite);
        assert not accessRightsOperations.canSetUserRights(#ReadWrite);
        assert not accessRightsOperations.canGetUserRights(#ReadWrite);

        assert accessRightsOperations.canRead(#ReadWriteManage);
        assert accessRightsOperations.canWrite(#ReadWriteManage);
        assert accessRightsOperations.canSetUserRights(#ReadWriteManage);
        assert accessRightsOperations.canGetUserRights(#ReadWriteManage);
    },
);

test(
    "can set and get user rights",
    func() {

        let keyManager = newKeyManager();

        switch (keyManager.getUserRights(p2, (p2, keyName), p2)) {
            case (#ok(?accessRights)) {
                assert accessRights == #ReadWriteManage;
            };
            case (unexpected) {
                Debug.trap("owner should have access rights " # debug_show (unexpected));
            };
        };

        switch (keyManager.getUserRights(p2, (p1, keyName), p2)) {
            case (#err e) {
                assert e == "unauthorized";
            };
            case (unexpected) {
                Debug.trap("user should not have access rights " # debug_show (unexpected));
            };
        };

        switch (keyManager.getUserRights(p1, (p1, keyName), p2)) {
            case (#ok null) {};
            case (#ok arg) {
                Debug.trap("already some access rights" # debug_show (arg));
            };
            case (#err e) {
                Debug.trap("should set user rights: " # e);
            };
        };

        switch (keyManager.setUserRights(p1, (p1, keyName), p2, #Read)) {
            case (#ok null) {};
            case (#ok arg) {
                Debug.trap("already some access rights" # debug_show (arg));
            };
            case (#err e) {
                Debug.trap("should set user rights: " # e);
            };
        };

        switch (keyManager.getUserRights(p2, (p1, keyName), p2)) {
            case (#err e) {
                assert e == "unauthorized";
            };
            case (unexpected) {
                Debug.trap("user should not have access rights with only read rights " # debug_show (unexpected));
            };
        };

        switch (keyManager.getUserRights(p1, (p1, keyName), p2)) {
            case (#ok(?arg)) { assert arg == #Read };
            case (#ok(null)) { Debug.trap("got null user rights in getter") };
            case (#err e) {
                Debug.trap("should get #read user rights: " # e);
            };
        };

        switch (keyManager.setUserRights(p1, (p1, keyName), p2, #ReadWriteManage)) {
            case (#ok null) { Debug.trap("got null user rights in setter") };
            case (#ok arg) {
                assert arg == ?#Read;
            };
            case (#err e) {
                Debug.trap("should set user rights: " # e);
            };
        };

        switch (keyManager.getUserRights(p2, (p1, keyName), p2)) {
            case (#ok(?arg)) {
                assert arg == #ReadWriteManage;
            };
            case (#ok arg) {
                Debug.trap("wrong access rights " # debug_show (arg));
            };
            case (#err e) {
                Debug.trap("user should get user rights: " # e);
            };
        };
    },
);

test(
    "can remove user rights",
    func() {
        let keyManager = newKeyManager();

        for (remover in [p1, p2].vals()) {
            switch (keyManager.setUserRights(p1, (p1, keyName), p2, #ReadWriteManage)) {
                case (#ok null) {};
                case (unexpected) {
                    Debug.trap("unexpected result in setting user rights: " # debug_show (unexpected));
                };
            };

            switch (keyManager.removeUserRights(remover, (p1, keyName), p2)) {
                case (#ok arg) {
                    assert arg == ?#ReadWriteManage;
                };
                case (unexpected) {
                    Debug.trap("unexpected result in removing user rights: " # debug_show (unexpected));
                };
            };

            switch (keyManager.getUserRights(p2, (p1, keyName), p2)) {
                case (#err e) {
                    assert e == "unauthorized";
                };
                case (unexpected) {
                    Debug.trap("user should not have access rights after removing user rights: " # debug_show (unexpected));
                };
            };

            switch (keyManager.getUserRights(p1, (p1, keyName), p2)) {
                case (#ok(null)) {};
                case (unexpected) {
                    Debug.trap("should not have access rights after removing user rights: " # debug_show (unexpected));
                };
            };
        };
    },
);

test(
    "get accessible shared key ids",
    func() {
        let keyManager = newKeyManager();
        assert keyManager.getAccessibleSharedKeyIds(p1) == [];
        assert keyManager.getAccessibleSharedKeyIds(p2) == [];

        do {
            let result = keyManager.setUserRights(p1, (p1, keyName), p2, #ReadWriteManage);
            assert result == #ok(null);
            assert keyManager.getAccessibleSharedKeyIds(p1) == [];
            assert keyManager.getAccessibleSharedKeyIds(p2) == [(p1, keyName)];
        };

        do {
            let result = keyManager.setUserRights(p2, (p2, keyName), p1, #ReadWriteManage);
            assert result == #ok(null);
            assert keyManager.getAccessibleSharedKeyIds(p1) == [(p2, keyName)];
            assert keyManager.getAccessibleSharedKeyIds(p2) == [(p1, keyName)];
        };

        let otherKey = Text.encodeUtf8("other key");

        do {
            let result = keyManager.setUserRights(p1, (p1, otherKey), p2, #ReadWriteManage);
            assert result == #ok(null);
            assert keyManager.getAccessibleSharedKeyIds(p1) == [(p2, keyName)];
            assert keyManager.getAccessibleSharedKeyIds(p2) == [(p1, keyName), (p1, otherKey)];
        };

        do {
            let result = keyManager.removeUserRights(p1, (p1, otherKey), p2);
            assert result == #ok(?#ReadWriteManage);
            assert keyManager.getAccessibleSharedKeyIds(p1) == [(p2, keyName)];
            assert keyManager.getAccessibleSharedKeyIds(p2) == [(p1, keyName)];
        };

        do {
            let result = keyManager.removeUserRights(p1, (p1, keyName), p2);
            assert result == #ok(?#ReadWriteManage);
            assert keyManager.getAccessibleSharedKeyIds(p1) == [(p2, keyName)];
            assert keyManager.getAccessibleSharedKeyIds(p2) == [];
        };

        do {
            let result = keyManager.removeUserRights(p2, (p2, keyName), p1);
            assert result == #ok(?#ReadWriteManage);
            assert keyManager.getAccessibleSharedKeyIds(p1) == [];
            assert keyManager.getAccessibleSharedKeyIds(p2) == [];
        };
    },
);

test(
    "get shared user access for a key",
    func() {
        let keyManager = newKeyManager();

        assert keyManager.getSharedUserAccessForKey(p1, (p1, keyName)) == #ok([]);

        do {
            let result = keyManager.setUserRights(p1, (p1, keyName), p2, #ReadWriteManage);
            assert result == #ok(null);
            for (user in [p1, p2].vals()) {
                assert keyManager.getSharedUserAccessForKey(p1, (p1, keyName)) == #ok([(p2, #ReadWriteManage)]);
            };
        };

        let p3 = Principal.fromText("nfxu4-cn7qt-x7r3c-5dhnk-dcrct-gmgoz-67gcg-5glvc-2krhv-gcmsr-qqe");

        do {
            let result = keyManager.setUserRights(p1, (p1, keyName), p3, #ReadWriteManage);
            assert result == #ok(null);
            for (user in [p1, p2, p3].vals()) {
                assert keyManager.getSharedUserAccessForKey(p1, (p1, keyName)) == #ok([(p2, #ReadWriteManage), (p3, #ReadWriteManage)]);
            };
        };

        do {
            let result = keyManager.removeUserRights(p1, (p1, keyName), p3);
            assert result == #ok(?#ReadWriteManage);
            for (user in [p1, p2].vals()) {
                assert keyManager.getSharedUserAccessForKey(p1, (p1, keyName)) == #ok([(p2, #ReadWriteManage)]);
            };
        };

        do {
            let result = keyManager.removeUserRights(p1, (p1, keyName), p2);
            assert result == #ok(?#ReadWriteManage);
            assert keyManager.getSharedUserAccessForKey(p1, (p1, keyName)) == #ok([]);
        };
    },
);
