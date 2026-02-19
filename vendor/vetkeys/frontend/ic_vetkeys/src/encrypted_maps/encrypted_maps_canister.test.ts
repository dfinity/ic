import { HttpAgent } from "@dfinity/agent";
import { DefaultEncryptedMapsClient } from "./encrypted_maps_canister";
import { expect, test } from "vitest";
import fetch from "isomorphic-fetch";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import { EncryptedMaps } from "./index";
import { randomBytes } from "node:crypto";

function randomId(): Ed25519KeyIdentity {
    return Ed25519KeyIdentity.generate(randomBytes(32));
}

function ids(): [Ed25519KeyIdentity, Ed25519KeyIdentity] {
    return [randomId(), randomId()];
}

async function newEncryptedMaps(
    id: Ed25519KeyIdentity,
): Promise<EncryptedMaps> {
    const host = "http://localhost:4943";
    const agent = await HttpAgent.create({
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        fetch,
        host,
        identity: id,
        shouldFetchRootKey: true,
    });
    const canisterId =
        process.env.CANISTER_ID_IC_VETKEYS_ENCRYPTED_MAPS_CANISTER;
    return new EncryptedMaps(new DefaultEncryptedMapsClient(agent, canisterId));
}

test("getAccessibleSharedMapNames", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const names = await encryptedMaps.getAccessibleSharedMapNames();
    expect(names.length === 0).toBeTruthy();
});

test("can get vetkey", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const owner = id.getPrincipal();
    const vetkey = await encryptedMaps.getDerivedKeyMaterial(
        owner,
        new TextEncoder().encode("some key"),
    );
    const secondVetkey = await encryptedMaps.getDerivedKeyMaterial(
        owner,
        new TextEncoder().encode("some key"),
    );
    expect(
        isEqualArrayThrowing(
            await secondVetkey.decryptMessage(
                await vetkey.encryptMessage("message", "domain", ""),
                "domain",
                "",
            ),
            new TextEncoder().encode("message"),
        ),
    ).to.equal(true);
});

test("vetkey encryption roundtrip", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const owner = id.getPrincipal();
    const plaintext = Uint8Array.from([1, 2, 3, 4]);

    const encryptionResult = await encryptedMaps.encryptFor(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
        plaintext,
    );
    const decryptedCiphertext = await encryptedMaps.decryptFor(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
        encryptionResult,
    );
    expect(isEqualArrayThrowing(plaintext, decryptedCiphertext)).to.equal(true);
});

test("cannot get unauthorized vetkey", async () => {
    const [id0, id1] = ids();
    const encryptedMaps = await newEncryptedMaps(id0);
    await expect(
        encryptedMaps.getDerivedKeyMaterial(
            id1.getPrincipal(),
            new TextEncoder().encode("some key"),
        ),
    ).rejects.toThrow(Error("unauthorized"));
});

test("can share a key", async () => {
    const [id0, id1] = ids();
    const owner = id0.getPrincipal();
    const user = id1.getPrincipal();
    const encryptedMapsOwner = await newEncryptedMaps(id0);
    const encryptedMapsUser = await newEncryptedMaps(id1);

    const rights = { ReadWrite: null };
    expect(
        await encryptedMapsOwner.setUserRights(
            owner,
            new TextEncoder().encode("some key"),
            user,
            rights,
        ),
    ).toBeUndefined();
    await expect(
        encryptedMapsUser.getDerivedKeyMaterial(
            owner,
            new TextEncoder().encode("some key"),
        ),
    ).resolves.toBeDefined();
});

test("set value should work", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const owner = id.getPrincipal();
    const plaintext = new TextEncoder().encode("Hello, world!");
    const mapKey = new TextEncoder().encode("some key");
    const mapName = new TextEncoder().encode("some map");

    await encryptedMaps.setValue(owner, mapName, mapKey, plaintext);

    const expectedEncryptionResult = await encryptedMaps.encryptFor(
        owner,
        mapName,
        mapKey,
        plaintext,
    );

    const getValueResult =
        await encryptedMaps.canisterClient.get_encrypted_value(
            owner,
            { inner: mapName },
            { inner: mapKey },
        );
    if ("Err" in getValueResult) {
        throw new Error(getValueResult.Err);
    }
    if (getValueResult.Ok.length === 0) {
        throw new Error("empty result");
    }

    expect(expectedEncryptionResult.length).to.equal(
        8 + 12 + 16 + plaintext.length,
    );
    expect(getValueResult.Ok[0].inner.length).to.equal(
        8 + 12 + 16 + plaintext.length,
    );

    const tryDecryptFromCheck = await encryptedMaps.decryptFor(
        owner,
        mapName,
        mapKey,
        Uint8Array.from(expectedEncryptionResult),
    );
    expect(isEqualArrayThrowing(tryDecryptFromCheck, plaintext)).to.equal(true);

    const tryDecryptFromCanister = await encryptedMaps.decryptFor(
        owner,
        mapName,
        mapKey,
        Uint8Array.from(getValueResult.Ok[0].inner),
    );
    expect(isEqualArrayThrowing(tryDecryptFromCanister, plaintext)).to.equal(
        true,
    );
});

test("get value should work", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const owner = id.getPrincipal();

    const value = new TextEncoder().encode("Hello, world!");

    const setValueResult = await encryptedMaps.setValue(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
        value,
    );

    expect(setValueResult).toBeFalsy();

    const getValueResult = await encryptedMaps.getValue(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
    );

    expect(isEqualArrayThrowing(value, getValueResult)).to.equal(true);
});

test("get-set roundtrip should be consistent", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const owner = id.getPrincipal();
    const data = new TextEncoder().encode("Hello, world!");

    await encryptedMaps.setValue(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
        data,
    );
    const result = await encryptedMaps.getValue(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
    );
    expect(isEqualArrayThrowing(data, result)).toBeTruthy();
});

test("can get user rights", async () => {
    const [id0, id1] = ids();
    const owner = id0.getPrincipal();
    const user = id1.getPrincipal();
    const encryptedMapsOwner = await newEncryptedMaps(id0);
    const encryptedMapsUser = await newEncryptedMaps(id1);
    const rights = { ReadWriteManage: null };

    await encryptedMapsOwner.setValue(
        owner,
        new TextEncoder().encode("some map"),
        new TextEncoder().encode("some key"),
        new TextEncoder().encode("Hello, world!"),
    );
    const initialUserRights = await encryptedMapsOwner.getUserRights(
        owner,
        new TextEncoder().encode("some key"),
        owner,
    );
    expect(initialUserRights).to.deep.equal({ ReadWriteManage: null });

    expect(
        await encryptedMapsOwner.getUserRights(
            owner,
            new TextEncoder().encode("some key"),
            user,
        ),
    ).toBeUndefined();
    const setUserRightsResult = await encryptedMapsOwner.setUserRights(
        owner,
        new TextEncoder().encode("some key"),
        user,
        rights,
    );
    expect(setUserRightsResult).toBeUndefined();
    expect(
        await encryptedMapsUser.getUserRights(
            owner,
            new TextEncoder().encode("some key"),
            user,
        ),
    ).to.deep.equal(rights);
});

test("get map values should work", async () => {
    const id = randomId();
    const encryptedMaps = await newEncryptedMaps(id);
    const owner = id.getPrincipal();
    const key1 = new TextEncoder().encode("some key 1");
    const key2 = new TextEncoder().encode("some key 2");
    const key3 = new TextEncoder().encode("some key 3");
    const data1 = new TextEncoder().encode("Hello, world 1!");
    const data2 = new TextEncoder().encode("Hello, world 2!");
    const data3 = new TextEncoder().encode("Hello, world 3!");
    const mapName = new TextEncoder().encode("some map");

    await encryptedMaps.setValue(owner, mapName, key1, data1);
    await encryptedMaps.setValue(owner, mapName, key2, data2);
    await encryptedMaps.setValue(owner, mapName, key3, data3);
    const result = await encryptedMaps.getValuesForMap(owner, mapName);
    expect(result.length).to.equal(3);

    const expectedMapValues: Array<[Uint8Array, Uint8Array]> = [
        [key1, data1],
        [key2, data2],
        [key3, data3],
    ];
    expect(
        isEqual2dArrayIfSortedThrowing(result, expectedMapValues),
    ).to.toBeTruthy();
});

test("get all accessible values should work", async () => {
    const [id0, id1] = ids();
    const encryptedMapsOwner = await newEncryptedMaps(id0);
    const encryptedMapsSharesWithOwner = await newEncryptedMaps(id1);
    const owner = id0.getPrincipal();
    const sharesWithOwner = id1.getPrincipal();
    const mapName1 = new TextEncoder().encode("some map 1");
    const mapName2 = new TextEncoder().encode("some map 2");
    const key1 = new TextEncoder().encode("some key 1");
    const key2 = new TextEncoder().encode("some key 2");
    const key3 = new TextEncoder().encode("some key 3");
    const key4 = new TextEncoder().encode("some key 4");
    const data1 = new TextEncoder().encode("Hello, world 1!");
    const data2 = new TextEncoder().encode("Hello, world 2!");
    const data3 = new TextEncoder().encode("Hello, world 3!");
    const data4 = new TextEncoder().encode("Hello, world 4!");

    await encryptedMapsOwner.setValue(owner, mapName1, key1, data1);
    await encryptedMapsOwner.setValue(owner, mapName1, key2, data2);
    await encryptedMapsSharesWithOwner.setValue(
        sharesWithOwner,
        mapName2,
        key3,
        data3,
    );
    await encryptedMapsSharesWithOwner.setValue(
        sharesWithOwner,
        mapName2,
        key4,
        data4,
    );

    await encryptedMapsSharesWithOwner.setUserRights(
        sharesWithOwner,
        mapName2,
        owner,
        { Read: null },
    );

    const retrievedValues = await encryptedMapsOwner.getAllAccessibleValues();

    // 2 maps
    expect(retrievedValues.length).to.equal(2);
    // 2 keys in the first map
    expect(retrievedValues[0][1].length).to.equal(2);
    // 2 keys in the second map
    expect(retrievedValues[1][1].length).to.equal(2);

    for (const [[ownerPrincipal, mapName], values] of retrievedValues) {
        if (
            ownerPrincipal.compareTo(owner) === "eq" &&
            isEqualArray(mapName, mapName1)
        ) {
            const expectedValues: Array<[Uint8Array, Uint8Array]> = [
                [key1, data1],
                [key2, data2],
            ];
            expect(
                isEqual2dArrayIfSortedThrowing(values, expectedValues),
            ).to.toBeTruthy();
        } else if (
            ownerPrincipal.compareTo(sharesWithOwner) === "eq" &&
            isEqualArray(mapName, mapName2)
        ) {
            const expectedValues: Array<[Uint8Array, Uint8Array]> = [
                [key3, data3],
                [key4, data4],
            ];
            expect(
                isEqual2dArrayIfSortedThrowing(values, expectedValues),
            ).to.toBeTruthy();
        } else {
            throw new Error(
                "Unexpected map owner and name: " +
                    ownerPrincipal.toText() +
                    " " +
                    mapName.toString() +
                    ". Expected were owner=" +
                    owner.toText() +
                    ", map=" +
                    mapName1.toString() +
                    " and non-owner=" +
                    sharesWithOwner.toText() +
                    ", map=" +
                    mapName2.toString(),
            );
        }
    }
});

function isEqualArrayThrowing(a: Uint8Array, b: Uint8Array) {
    if (!isEqualArray(a, b)) {
        throw Error(
            "Arrays not equal\n\na: " + a.toString() + "\n\nb: " + b.toString(),
        );
    }
    return true;
}

function isEqualArray(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length != b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

function isEqual2dArrayIfSortedThrowing(
    a: Array<[Uint8Array, Uint8Array]>,
    b: Array<[Uint8Array, Uint8Array]>,
): boolean {
    if (a.length != b.length)
        throw Error(
            "Arrays not equal length\n\na: " +
                JSON.stringify(a) +
                "\n\nb: " +
                JSON.stringify(b),
        );

    for (const [keyA, valueA] of a) {
        const isFound = b.find(([keyB, valueB]) => {
            return isEqualArray(keyA, keyB) && isEqualArray(valueA, valueB);
        });
        if (!isFound) {
            throw Error(
                "Arrays not equal\n\na: " +
                    JSON.stringify(a) +
                    "\n\nb: " +
                    JSON.stringify(b),
            );
        }
    }

    return true;
}
