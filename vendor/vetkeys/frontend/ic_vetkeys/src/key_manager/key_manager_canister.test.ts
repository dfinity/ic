import { HttpAgent } from "@dfinity/agent";
import { Ed25519KeyIdentity } from "@dfinity/identity";
import fetch from "isomorphic-fetch";
import { expect, test } from "vitest";
import { KeyManager } from "./index";
import { DefaultKeyManagerClient } from "./key_manager_canister";
import { randomBytes } from "node:crypto";

function randomId(): Ed25519KeyIdentity {
    return Ed25519KeyIdentity.generate(randomBytes(32));
}

function ids(): [Ed25519KeyIdentity, Ed25519KeyIdentity] {
    return [randomId(), randomId()];
}

async function newKeyManager(id: Ed25519KeyIdentity): Promise<KeyManager> {
    const host = "http://127.0.0.1:4943";
    const agent = await HttpAgent.create({
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        fetch,
        host,
        identity: id,
        shouldFetchRootKey: true,
    }).catch((err) => {
        throw err;
    });
    const canisterId = process.env.CANISTER_ID_IC_VETKEYS_MANAGER_CANISTER;
    return new KeyManager(new DefaultKeyManagerClient(agent, canisterId));
}

test("empty getAccessibleSharedKeyIds", async () => {
    const id = randomId();
    const keyManager = await newKeyManager(id).catch((err) => {
        throw err;
    });
    const ids = await keyManager.getAccessibleSharedKeyIds();
    expect(ids.length === 0).to.equal(true);
});

test("can get vetkey", async () => {
    const id = randomId();
    const keyManager = await newKeyManager(id).catch((err) => {
        throw err;
    });
    const owner = id.getPrincipal();
    const vetkey = await keyManager
        .getVetkey(owner, new TextEncoder().encode("some key"))
        .catch((err) => {
            throw err;
        });
    // no trivial key output
    expect(isEqualArray(vetkey, new Uint8Array(16))).to.equal(false);

    const secondVetkey = await keyManager
        .getVetkey(owner, new TextEncoder().encode("some key"))
        .catch((err) => {
            throw err;
        });
    expect(isEqualArray(vetkey, secondVetkey)).to.equal(true);
});

test("cannot get unauthorized vetkey", async () => {
    const [id0, id1] = ids();
    const keyManager = await newKeyManager(id0).catch((err) => {
        throw err;
    });
    await expect(
        keyManager.getVetkey(
            id1.getPrincipal(),
            new TextEncoder().encode("some key"),
        ),
    ).rejects.toThrow("unauthorized");
});

test("can share a key", async () => {
    const [id0, id1] = ids();
    const owner = id0.getPrincipal();
    const user = id1.getPrincipal();
    const keyManagerOwner = await newKeyManager(id0).catch((err) => {
        throw err;
    });
    const keyManagerUser = await newKeyManager(id1).catch((err) => {
        throw err;
    });
    const vetkeyOwner = await keyManagerOwner.getVetkey(
        owner,
        new TextEncoder().encode("some key"),
    );

    const rights = { ReadWrite: null };
    expect(
        await keyManagerOwner.setUserRights(
            owner,
            new TextEncoder().encode("some key"),
            user,
            rights,
        ),
    ).toBeUndefined();

    const vetkeyUser = await keyManagerUser.getVetkey(
        owner,
        new TextEncoder().encode("some key"),
    );

    expect(isEqualArray(vetkeyOwner, vetkeyUser)).to.equal(true);
});

test("sharing rights are consistent", async () => {
    const [id0, id1] = ids();
    const owner = id0.getPrincipal();
    const user = id1.getPrincipal();
    const keyManagerOwner = await newKeyManager(id0).catch((err) => {
        throw err;
    });
    const keyManagerUser = await newKeyManager(id1).catch((err) => {
        throw err;
    });
    const rights = { ReadWriteManage: null };

    expect(
        await keyManagerOwner.setUserRights(
            owner,
            new TextEncoder().encode("some key"),
            user,
            rights,
        ),
    ).toBeUndefined();
    expect(
        await keyManagerUser.getUserRights(
            owner,
            new TextEncoder().encode("some key"),
            user,
        ),
    ).to.deep.equal(rights);
});

function isEqualArray(a: Uint8Array, b: Uint8Array) {
    if (a.length != b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
    return true;
}
