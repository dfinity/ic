import {
    DerivedPublicKey,
    EncryptedVetKey,
    IbeIdentity,
    IbeCiphertext,
    MasterPublicKey,
    MasterPublicKeyId,
    PocketIcMasterPublicKeyId,
    IbeSeed,
    TransportSecretKey,
    VetKey,
    VrfOutput,
    augmentedHashToG1,
    deriveSymmetricKey,
    hashToScalar,
    isValidTransportPublicKey,
    verifyBlsSignature,
} from "./utils";
import { expect, test } from "vitest";
import { bls12_381 } from "@noble/curves/bls12-381";

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return [...new Uint8Array(bytes)]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

function assertEqual(a, b) {
    expect(a).toStrictEqual(b);
}

test("creating random TransportSecretKey", () => {
    const key = TransportSecretKey.random();

    const pk = key.publicKeyBytes();
    assertEqual(pk.length, 48);
});

test("isValidTransportPublicKey", () => {
    assertEqual(isValidTransportPublicKey(hexToBytes("50505050")), false);
    assertEqual(
        isValidTransportPublicKey(
            hexToBytes(
                "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            ),
        ),
        true,
    );
    assertEqual(
        isValidTransportPublicKey(
            hexToBytes(
                "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        true,
    );
});

test("parsing DerivedPublicKey", () => {
    expect(() => {
        const invalid = new Uint8Array([1, 2, 3]);
        return DerivedPublicKey.deserialize(invalid);
    }).toThrow();

    const valid = hexToBytes(
        "972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f",
    );
    const key = DerivedPublicKey.deserialize(valid);
    assertEqual(valid, key.publicKeyBytes());
});

test("MasterPublicKey derivation using test key", () => {
    const masterKey = MasterPublicKey.productionKey(
        MasterPublicKeyId.TEST_KEY_1,
    );

    const canisterId = hexToBytes("0000000000c0a0d00101");

    const canisterKey = masterKey.deriveCanisterKey(canisterId);

    assertEqual(
        bytesToHex(canisterKey.publicKeyBytes()),
        "8b961f06d392367e84136088971c4808b434e5d6b928b60fa6177f811db9930e4f2a911ef517db40f7e7897588ae0e2316500dbef3abf08ad7f63940af0cf816c2c1c234943c9bb6f4d53da121dceed093d118d0bd5552740da315eac3b59b0f",
    );

    const derivedKey = canisterKey.deriveSubKey(
        new TextEncoder().encode("context-string"),
    );

    assertEqual(
        bytesToHex(derivedKey.publicKeyBytes()),
        "958a2700438db39cf848f99c80d4d1c0f42b5e6783c35abffe5acda4fdb09548a025fdf85aad8980fcf6e20c1082596310c2612a3f3034c56445ddfc32a0c3cd34a7d0fea8df06a2996c54e21e3f8361a6e633d706ff58e979858fe436c7edf3",
    );
});

test("MasterPublicKey derivation using prod key", () => {
    const masterKey = MasterPublicKey.productionKey();

    const canisterId = hexToBytes("0000000000c0a0d00101");

    const canisterKey = masterKey.deriveCanisterKey(canisterId);

    assertEqual(
        bytesToHex(canisterKey.publicKeyBytes()),
        "a4df5fb733dc53ba0b3f8dab3f7538b2f345052072f69a5749d630d9c2b2b1c4b00af09fa1d993e1ce533996961575ad027e058e2a279ab05271c115ef27d750b6b233f12bc9f1973b203e338d43b6a7617be58d5c7195dfb809d756413bc006",
    );

    const derivedKey = canisterKey.deriveSubKey(
        new TextEncoder().encode("context-string"),
    );

    assertEqual(
        bytesToHex(derivedKey.publicKeyBytes()),
        "aa45fccb82432315e39fedb1b1f150d2e895fb1f7399cc593b826ac151b519f0966b92aef49a89efe60570ef325f0f7e1974ac3519d2e127a52c013e246aedbff2158bdd0bb9f26c763c88c0b8ec796f401d057eab276d0a34384a8a97b1937f",
    );
});

test("MasterPublicKey derivation using PocketIC key_1", () => {
    const canisterId = hexToBytes("ffffffffff9000030101");

    const masterKey = MasterPublicKey.pocketicKey(
        PocketIcMasterPublicKeyId.KEY_1,
    );
    const canisterKey = masterKey.deriveCanisterKey(canisterId);

    const derivedKey = canisterKey.deriveSubKey(
        new TextEncoder().encode("Test Derivation For PocketIC VetKD key_1"),
    );

    assertEqual(
        bytesToHex(derivedKey.publicKeyBytes()),
        "899a951f6ec2f9a96759c554a6cb01fb1cb20b2f2f96a2d2c869221c04d3349c3be8d49c3257312aed031f430f15f7ef0f4d43adf11251015d70dd91ac07df50fb70818ece721a1d6a314204acddde55542902f5d0d95e2406a5ab1fad18349d",
    );
});

test("MasterPublicKey derivation using PocketIC test_key_1", () => {
    const canisterId = hexToBytes("ffffffffff9000030101");

    const masterKey = MasterPublicKey.pocketicKey(
        PocketIcMasterPublicKeyId.TEST_KEY_1,
    );
    const canisterKey = masterKey.deriveCanisterKey(canisterId);

    const derivedKey = canisterKey.deriveSubKey(
        new TextEncoder().encode(
            "Test Derivation For PocketIC VetKD test_key_1",
        ),
    );

    assertEqual(
        bytesToHex(derivedKey.publicKeyBytes()),
        "a60993fc46593728bd9b0a4ffb1fb9a662dd89b29c99fde36e403c311c8992e6eeb097b31174dd43f74e73fe10c190271193a4345490f64a41ce778a2f6e7c16804919e843ac72ff65bab959c53fa839c9fb3cb263e41498d17fb82704fe18bc",
    );
});

test("MasterPublicKey derivation using PocketIC dfx_test_key", () => {
    const canisterId = hexToBytes("ffffffffff9000030101");

    const masterKey = MasterPublicKey.pocketicKey(
        PocketIcMasterPublicKeyId.DFX_TEST_KEY,
    );
    const canisterKey = masterKey.deriveCanisterKey(canisterId);

    const derivedKey = canisterKey.deriveSubKey(
        new TextEncoder().encode(
            "Test Derivation For PocketIC VetKD dfx_test_key",
        ),
    );

    assertEqual(
        bytesToHex(derivedKey.publicKeyBytes()),
        "800424bea66b95b715f86a9bed06b1f60df98206a57235c3e0f2da4d485dc1c93c56eef54155d559ef45c757fb0444920620b932652f1d683fdbc57db98b5aeb8ba664a5e040cbdf4d685e4e236a7193d1bd5b0927204fab05fff4f61f26b358",
    );
});

test("DerivedPublicKey subderivation", () => {
    const canisterKey = DerivedPublicKey.deserialize(
        hexToBytes(
            "8bf165ea580742abf5fd5123eb848aa116dcf75c3ddb3cd3540c852cf99f0c5394e72dfc2f25dbcb5f9220f251cd04040a508a0bcb8b2543908d6626b46f09d614c924c5deb63a9949338ae4f4ac436bd77f8d0a392fd29de0f392a009fa61f3",
        ),
    );

    const context = new TextEncoder().encode("test-context");

    const derivedKey = canisterKey.deriveSubKey(context);

    assertEqual(
        bytesToHex(derivedKey.publicKeyBytes()),
        "80b4f1e11766d32bed0ea4e8b05e82bf84519de4a63eca0213d9e3603a946ea2968150882d1e9508701f34048fcec80919b4f493a2a254fc13dc956f1d82c6b8e641f962e1c0342c95eb58e168327d5e51e9337627ac9f1aa93d2e3058a1ff09",
    );
});

test("augmented hash to G1", () => {
    const pk = DerivedPublicKey.deserialize(
        hexToBytes(
            "80e38f040fae321c75cf8faf8c6e9500c92b7cac022ca3eb48fb01c8e91d8c2bc806c2665ed28a0a8c87a4bff717dd3c0c4eb57ad635bc582f89c171b8478f2fe1b806c3faeed7133b13141aaf4a65aa0c5d7902dc80102e91e6f73fe56fa34f",
        ),
    );
    const msg = hexToBytes("25138dfc69267bd861d8ad9f05b9");

    const expected =
        "8e946e53188c951301b895c228c48cdeebf008d0fbc5b0aa8bff07a30926fb166485137dc372983433032673f74c24e6";

    const calculated = augmentedHashToG1(pk, msg);

    assertEqual(bytesToHex(calculated.toRawBytes(true)), expected);
});

test("BLS signature verification", () => {
    const pk = DerivedPublicKey.deserialize(
        hexToBytes(
            "972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f",
        ),
    );

    const msg = new TextEncoder().encode("message");
    const wrongMsg = new TextEncoder().encode("this is some other message");

    const signatureHex =
        "987db5406ce297e729c8564a106dc896943b00216a095fe9c5d32a16a330c02eb80e6f468ede83cde5462b5145b58f65";

    // Test verification works passing a binary string
    const signatureBytes = hexToBytes(signatureHex);
    assertEqual(verifyBlsSignature(pk, msg, signatureBytes), true);
    assertEqual(verifyBlsSignature(pk, wrongMsg, signatureBytes), false);

    // Test verification works passing a point objecet
    const signaturePoint = bls12_381.G1.ProjectivePoint.fromHex(signatureHex);
    assertEqual(verifyBlsSignature(pk, msg, signaturePoint), true);
    assertEqual(verifyBlsSignature(pk, wrongMsg, signaturePoint), false);
});

test("protocol flow with precomputed data", () => {
    const tsk = TransportSecretKey.deserialize(
        hexToBytes(
            "167b736e44a1c134bd46ca834220c75c186768612568ac264a01554c46633e76",
        ),
    );

    const tpk = tsk.publicKeyBytes();

    assertEqual(
        bytesToHex(tpk),
        "911969d56f42875d37a92d7eaa5d43293eff9f9a20ba4c60523e70a695eaeadeb721659b52a49d74e67841ad19033a12",
    );

    const identity = hexToBytes("6d657373616765");

    const dpk = DerivedPublicKey.deserialize(
        hexToBytes(
            "972c4c6cc184b56121a1d27ef1ca3a2334d1a51be93573bd18e168f78f8fe15ce44fb029ffe8e9c3ee6bea2660f4f35e0774a35a80d6236c050fd8f831475b5e145116d3e83d26c533545f64b08464e4bcc755f990a381efa89804212d4eef5f",
        ),
    );

    const ek = EncryptedVetKey.deserialize(
        hexToBytes(
            "b1a13757eaae15a3c8884fc1a3453f8a29b88984418e65f1bd21042ce1d6809b2f8a49f7326c1327f2a3921e8ff1d6c3adde2a801f1f88de98ccb40c62e366a279e7aec5875a0ce2f2a9f3e109d9cb193f0197eadb2c5f5568ee4d6a87e115910662e01e604087246be8b081fc6b8a06b4b0100ed1935d8c8d18d9f70d61718c5dba23a641487e72b3b25884eeede8feb3c71599bfbcebe60d29408795c85b4bdf19588c034d898e7fc513be8dbd04cac702a1672f5625f5833d063b05df7503",
        ),
    );

    const message = hexToBytes("f00f11");
    const seed = IbeSeed.fromBytes(new Uint8Array(32));
    const ibe = IbeCiphertext.encrypt(
        dpk,
        IbeIdentity.fromBytes(identity),
        message,
        seed,
    );

    assertEqual(
        bytesToHex(ibe.serialize()),
        "4943204942450001a9937528bda5826cf5c7da77a5f5e46719a9748f4ea0aa491c8fba92081e5d55457ab36ec4f6335954c6d87987d0b28301bd8da166493bb537c842d20396da5a68cc9e9672fadedf1e311e0057fc906dfd37d1077ca027954c45336405e66e5e4b346b0f24bfd358a09de701654c1e0791741e4826396588440eee021df9b2399f7f98",
    );

    const ibeRec = IbeCiphertext.deserialize(ibe.serialize());

    const vetkd = ek.decryptAndVerify(tsk, dpk, identity);

    assertEqual(
        bytesToHex(vetkd.signatureBytes()),
        "987db5406ce297e729c8564a106dc896943b00216a095fe9c5d32a16a330c02eb80e6f468ede83cde5462b5145b58f65",
    );

    const rec = ibeRec.decrypt(vetkd);
    assertEqual(bytesToHex(rec), "f00f11");

    const symKey = vetkd.deriveSymmetricKey(
        "QUUX-V01-CS02-with-expander-SHA256-128",
        32,
    );
    assertEqual(
        bytesToHex(symKey),
        "ed2984e1a5eca6d49294e96db7f31b9f47fb3ae5f48383926f16811ffb9fd991",
    );
});

test("hash to scalar", () => {
    const dst = "QUUX-V01-CS02-with-BLS12381SCALAR_XMD:SHA-256_SSWU_RO_";

    assertEqual(
        hashToScalar(hexToBytes(""), dst).toString(16),
        "3b3fdf74b194c0a0f683d67a312a4e72d663d74b8478dc7b56be41e0ce11caa1",
    );
    assertEqual(
        hashToScalar(hexToBytes("616263"), dst).toString(16),
        "47e7a8839695a3df27f202cf71e295a8554b47cef75c1e316b1865317720e188",
    );
});

test("hkdf using webcrypto", async () => {
    const vetkey = VetKey.deserialize(
        hexToBytes(
            "ad19676dd92f116db11f326ff0822f295d87cc00cf65d9f132b5a618bb7381e5b0c3cb814f15e4a0f015359dcfa8a1da",
        ),
    );

    const domainSep = "ic-test-domain-sep";

    const key1 = vetkey.deriveSymmetricKey(domainSep, 32);
    assertEqual(
        "3b7bd854033cdc119865ba3019dc1e35010fdaf90f8ff5c9cfe9d1d557dddb29",
        bytesToHex(key1),
    );

    const wckey = (await vetkey.asDerivedKeyMaterial()).getCryptoKey();

    const algorithm = {
        name: "HKDF",
        salt: new Uint8Array(),
        info: new TextEncoder().encode(domainSep),
        hash: "SHA-256",
        length: 32 * 8,
    };
    const derivedAlgo = {
        name: "HMAC",
        hash: "SHA-256",
        length: 32 * 8,
    };
    const derived = await globalThis.crypto.subtle.deriveKey(
        algorithm,
        wckey,
        derivedAlgo,
        true,
        ["sign"],
    );

    const derivedBytes = new Uint8Array(
        await globalThis.crypto.subtle.exportKey("raw", derived),
    );
    assertEqual(
        bytesToHex(derivedBytes),
        "3b7bd854033cdc119865ba3019dc1e35010fdaf90f8ff5c9cfe9d1d557dddb29",
    );
});

test("AES-GCM encryption", async () => {
    const vetkey = VetKey.deserialize(
        hexToBytes(
            "ad19676dd92f116db11f326ff0822f295d87cc00cf65d9f132b5a618bb7381e5b0c3cb814f15e4a0f015359dcfa8a1da",
        ),
    );

    const testMessage = "stay calm, this is only a test";
    const testMessageBytes = new TextEncoder().encode(testMessage);
    const domainSep = "ic-test-domain-sep";
    const associatedData = "some additional authenticated data";

    const keyMaterial = await vetkey.asDerivedKeyMaterial();

    // Test string encryption path, then decryption

    const msg1 = await keyMaterial.encryptMessage(
        testMessage,
        domainSep,
        associatedData,
    );
    assertEqual(
        await keyMaterial.decryptMessage(msg1, domainSep, associatedData),
        testMessageBytes,
    );

    // Test Uint8Array encryption path, then decryption
    const msg2 = await keyMaterial.encryptMessage(
        testMessageBytes,
        domainSep,
        associatedData,
    );
    assertEqual(
        await keyMaterial.decryptMessage(msg2, domainSep, associatedData),
        testMessageBytes,
    );

    // Test decryption of old format (headerless) ciphertext
    const msgOldFormat = hexToBytes(
        "476f440e30bb95fff1420ce41ba6a07e03c3fcc0a751cfb23e64a8dcb0fc2b1eb74e2d4768f5c4dccbf2526609156664046ad27a6e78bd93bb8b",
    );
    assertEqual(
        await keyMaterial.decryptMessage(msgOldFormat, domainSep, ""),
        testMessageBytes,
    );

    // Test decryption of known ciphertext encrypted with the derived key
    const msg3 = hexToBytes(
        "49432047434d76325dc1b0f5f8deec973adda66ce7cb9dc06118c738fae12027c5bae5b86e69ffd633ddfc0ea66c4df37b6e7e298d9f80170ec3d51c4238be9a63bd",
    );
    assertEqual(
        await keyMaterial.decryptMessage(msg3, domainSep, associatedData),
        testMessageBytes,
    );

    // Test decryption of various mutated or truncated ciphertexts: all should fail

    // Test sequentially flipping each bit of the ciphertext
    for (let trial = 0; trial < msg3.length * 8; trial++) {
        const modMsg = new Uint8Array(msg3);

        const flip = 0x80 >> trial % 8;
        const byteToFlip = Math.floor(trial / 8);
        modMsg[byteToFlip] ^= flip;

        const expectedError =
            trial < 8 * 8
                ? "Unknown header for AES-GCM encrypted ciphertext"
                : "Decryption failed";

        await expect(async () => {
            return await keyMaterial.decryptMessage(
                modMsg,
                domainSep,
                associatedData,
            );
        }).rejects.toThrow(expectedError);
    }

    // Test sequentially flipping each bit of the associated data
    for (let trial = 0; trial < associatedData.length * 8; trial++) {
        const modAad = new TextEncoder().encode(associatedData);

        const flip = 0x80 >> trial % 8;
        const byteToFlip = Math.floor(trial / 8);
        modAad[byteToFlip] ^= flip;

        const expectedError = "Decryption failed";

        await expect(async () => {
            return await keyMaterial.decryptMessage(msg3, domainSep, modAad);
        }).rejects.toThrow(expectedError);
    }

    // Test truncating
    for (let trial = 0; trial < msg3.length - 1; trial++) {
        const modMsg = msg3.slice(0, trial);

        const expectedError =
            modMsg.length < 8 + 12 + 16
                ? "Invalid ciphertext, too short"
                : "Decryption failed";

        await expect(async () => {
            return await keyMaterial.decryptMessage(
                modMsg,
                domainSep,
                associatedData,
            );
        }).rejects.toThrow(expectedError);
    }

    // Test appending random bytes
    for (let trial = 1; trial < 32; trial++) {
        const extraBytes = globalThis.crypto.getRandomValues(
            new Uint8Array(trial),
        );
        const modMsg = new Uint8Array([...msg3, ...extraBytes]);

        await expect(async () => {
            return await keyMaterial.decryptMessage(
                modMsg,
                domainSep,
                associatedData,
            );
        }).rejects.toThrow("Decryption failed");
    }
});

test("VRF with production key output", () => {
    const vrfBytes = hexToBytes(
        "82c018756fc09660f19f9f4473820c8f047b9709e9371ae705175cb510efbfc610f0f61fb5ca8bba59e998249d466a818a62a9f32cb3dacc11941ea27256ac5b0ca710f8803d111f04b798677d9c54e127e63000c906a85bcb08c422fc81229d07a2554e7882308c6f1c3ecd07c3d72a465f741e4357144afe042c1e6d7f838ecc3f40c5e681e2b55032cfd689ebd17976726620696e707574",
    );
    const vrf = VrfOutput.deserialize(vrfBytes);

    assertEqual(vrf.serialize(), vrfBytes);

    const masterKey = MasterPublicKey.productionKey(MasterPublicKeyId.KEY_1);

    const canisterId = hexToBytes("0000000000c0a0d00101");
    const canisterKey = masterKey.deriveCanisterKey(canisterId);
    const vrfContext = "vrf context";
    const vrfInput = "vrf input";

    const vrfKey = canisterKey.deriveSubKey(
        new TextEncoder().encode(vrfContext),
    );

    assertEqual(
        bytesToHex(vrf.publicKey().publicKeyBytes()),
        bytesToHex(vrfKey.publicKeyBytes()),
    );
    assertEqual(vrf.input(), new TextEncoder().encode(vrfInput));
    assertEqual(
        bytesToHex(vrf.output()),
        "a484fc1e8a2b0dca99beb6f4409370f5c6932a931e47a7625c3bfe9e1f9af37f",
    );
});

test("IBE ciphertext size utils", () => {
    for (let ptextLen: number = 0; ptextLen != 1024; ++ptextLen) {
        const ctextLen = IbeCiphertext.ciphertextSize(ptextLen);
        const recPtextLen = IbeCiphertext.plaintextSize(ctextLen);
        assertEqual(ptextLen, recPtextLen);
    }
});

test("hkdf test vectors", () => {
    // HKDF test vectors from wycheproof
    const testVectors = [
        [
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ],
        [
            "24aeff2645e3e0f5494a9a102778c43a",
            "",
            "d4cca5e416c3d9eb58bd562e922691daff76aa4d",
        ],
        [
            "a23632e18ec76b59b1c87008da3f8a7e",
            "",
            "976d1590926ac35e28d7f1a29fe98a1f787703a71cee3cb2c10acb9cc1b56c0f21b55d5de37755a79b12",
        ],
        [
            "a4748031a14d3e6aafe42aa20c568f5f",
            "",
            "03f5db41f4484ec9468648c9f2a7f73ec18386008691b0555a7eec165e2f8cc72a6e74fffafbfb1ead00a89ff80ba00a266a70fcac07364110c6f5707f5096aa",
        ],
        [
            "06eb26f8ccf28580c8f28d5b4dc47a49",
            "d5f081e81e8cf9ded199f3ae43c80a2dfe3d9cf2",
            "ae538577a14df1ab170ec01a9ceceabcebdd584f",
        ],
        [
            "c181696a19ab1a32eb6e81b2925d8990",
            "d8c8de92fe5422c9825996354db1821ba43a81ac",
            "151ee737f049d18cdeb3010a0fbb606461875b22ac76487874498808248cf607e1cf7f3fc52b3a28ac64",
        ],
        [
            "55fb6dcc7802354e55a45a6e41858c05",
            "dcd590e418b259c64fb9e139b3a1280d5de8400b",
            "6ca91e1a6c0eb286d6fea277e9936f2486104c4c5d473a92872009f04aa545a61d03d83e14aa0965ba355551b93073ef91382c88afad091c62f6f65188f789e3",
        ],
        [
            "d04f44faa4542b34f958d8a863801f2c",
            "ff6b5b655cbf2421a66d2f28408395a2ce57264f76bd60befd51cbfd9474faa47a97a9aa0f0e4338635633023cb36da12a3051f1f369355b687304e74c5218b315",
            "aa235b487116b1c1e2f68c9a557b396a318ea2aa29c0e6a122645918ba693598e40e5b7c73c92f832530db888d4c53fbf73aff67d129a24263134335c9757da6ff7f386c77f830d1bac3409fb3b834be",
        ],
        [
            "fa4f94e9cdbf725c1ee98decddbe42ec06196116",
            "",
            "f32a552257d372b16c5d8c46e6c07dc9c33be9bc",
        ],
        [
            "094db4e2eaae8fc9dca0d9bc14b29387fd476921",
            "",
            "41ae65892c3359f808e906bbc91c701f7e067b548e685bc02d5badad2799221bf313964f8307670d76a8",
        ],
        [
            "bfbe4f1edace02b2a3afcaada5f319103996dec9",
            "",
            "93c737cdce4fe225839614393bc5ff6fd14390dc436ad6f9e13a7714e8b8b2d66cb690fd9a213c0e297ac96fda5d27e002cfc344964b86e78ff23c260cbcc82e",
        ],
        [
            "71220f185f4f2d436fa88b61f7ddf4a10948385e",
            "f392a656590cdd585a06ad4892d2381ad0616a99",
            "db44f61cc3538799665902ea761be6fea0c51e75",
        ],
        [
            "3a0c2c84ea46c152104d794261413412bad2e846",
            "1cf4f37e0cab71a252100a2925a8703231292a7e",
            "1d4f606b55c6f6fc25d06eadcc86732afeaa281f7cc7acb3efb40eacfb4880d46daef24091045cb16baa",
        ],
        [
            "59b7fce05176a56f9b086b2e9e526b4491d05d27",
            "d0e410792d888f355baaae8e17288e982032c231",
            "df10c40dae8f62e212775e5f19f9769f17ac32abe46aae106a5baa9af3d9c2305376ec0a6f86492219a7d448b518ed08fb6fd6eeb3f964949e164bf8caef03d3",
        ],
        [
            "8e9dfcf668a8b7e22c8d403c35af78324dafeadf",
            "b4d6ce377ee98d0e1614e3865354cda02dfeb92010ffbade5d1f7e4329f166995a67415d56221128b04de3e8c49437b9e322986b5fe1256c7f8c81021b99ea96ae",
            "01ed7302f611c098f57fe9ec9b8654974bd707981c2b647753cd586cbdd0d7ea1dbc5c76262fdcbe0c355a965a4287eb86e4c97e60bf0e6be0dc898c997b0e73b2888265e8115073bdc5040365736d73",
        ],
        [
            "7ef7d4f8c11d940471cf9a3048d66b3b3a3d9db9fed5f81419fe75dd50116f4e",
            "",
            "a370de1c822b8eb00645c18e32ad6a1f4bb17c9b",
        ],
        [
            "1b6c7d5da045bf8bd4ac3083e8de2b90904bc7f7830bef876e355b74466cef91",
            "",
            "50dd5b5adbe96aa216f93c4cbb7d568d5141b3ef7214be885984629b93f07814870db846c3efc8c7db7f",
        ],
        [
            "b9da242c02bfe79364aedd7a323692191092edb2094f112675c2609a387c3b21",
            "",
            "384c0ded57bf066d6665d88355aff9eab8cbd78c1c71af7b8334cde6536f21223aeddd5a84d278d5d73f5b536973575dd2993a4a857289c3b59861643c464c2c",
        ],
        [
            "23624191960916aad7039c8e9dc2ec4e04ac61a233a02ec6045021598123f0cd",
            "60dd0d1381a014491b34f0af15e4bebb8f64cbd5",
            "2f94214e5171e40cd7bb601c2fc7fca42c77f227",
        ],
        [
            "ad75f83c7fef898ab33a429af351c10caaf39ef27b161a6806d34f1f4f8be229",
            "69546d578a213b7f2af101c8ef532339324d43ea",
            "b60b7fb09271c6ac0c48d6ccfbc535115075e0060633e5adb502bd964bac2fd120a53be8bfbc9fedc27b",
        ],
        [
            "cb55dbea8b91ae1ce0a07b23b1508c2a930560b8fe7255fcc3e37835803661fe",
            "b57d6aaedf30bd8e25867059761a02c5d0478f2e",
            "d22014f4f0475223eb87d4d462f29f04a33fe93349fe62ff9d4dce9360e5e22bc0a42746abbf44c22bf472c1f6aa608f3c90c088daae7015fb2f9e5aafa2c9a2",
        ],
        [
            "d2ee6859f3e52e456f4b0e19252f3ba453102fb4de685b9823a652acb2f87039",
            "086e8dc0aa05538926dc74e89857232aa7d1fdc3f6ca29dddaba48dd682bcf1cfe08700e2a5a7102d01e57a93bca2668dee95339d5db6b6a2e7e5fa66667b8d5b8",
            "9270c8f7b8c979c7f537ff820b08ab3b757266a00679070380bba554e30e843710551cf5ae38d6d692749a425b85b4c2fa674ab37e3936feb6089afd60c80d5f2cba1ff9257519a40d2e181ce920d370",
        ],
        [
            "3ee1fc0d8fac49d494c4a1b8cf6bf290a4a2c19a27c3ab1914d0d21c841577e0",
            "4dc991623624fadef207587e42776cf3e0fdf4e5",
            "f41f703259063d401de67cea9192038ddddc71ede5cdb383aad71894c1a39e8c",
        ],
    ];

    for (const tv of testVectors) {
        const input = hexToBytes(tv[0]);
        const dst = hexToBytes(tv[1]);
        const expected = tv[2];

        const outputLen = Math.trunc(expected.length / 2);

        const kdf = deriveSymmetricKey(input, dst, outputLen);
        assertEqual(bytesToHex(kdf), expected);
    }
});
