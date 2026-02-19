import { bls12_381 } from "@noble/curves/bls12-381";
import { ProjPointType } from "@noble/curves/abstract/weierstrass";
import { Fp, Fp2, Fp12 } from "@noble/curves/abstract/tower";
import { hash_to_field, Opts } from "@noble/curves/abstract/hash-to-curve";
import { shake256 } from "@noble/hashes/sha3";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import type { Principal } from "@dfinity/principal";

export type G1Point = ProjPointType<Fp>;
export type G2Point = ProjPointType<Fp2>;

const G1_BYTES = 48;
const G2_BYTES = 96;

/**
 * Transport Secret Key
 *
 * Applications using VetKD create an ephemeral transport secret key and send
 * the public key to the IC as part of their VetKD request. The returned VetKey
 * is encrypted, and can only be decrypted using the transport secret key.
 */
export class TransportSecretKey {
    readonly #sk: Uint8Array;
    readonly #pk: G1Point;

    /**
     * Create a random transport secret key
     */
    static random() {
        return new TransportSecretKey(bls12_381.utils.randomPrivateKey());
    }

    /**
     * Deserialize TransportSecretKey from a bytestring
     *
     * The passed value would typically be a string previously returned
     * by calling serialize on a randomly-created TransportSecretKey.
     */
    static deserialize(sk: Uint8Array) {
        if (sk.length !== 32) {
            throw new Error("Invalid size for transport secret key");
        }

        return new TransportSecretKey(sk);
    }

    /**
     * Return the encoding of the transport public key; this value is
     * sent to the IC
     */
    publicKeyBytes(): Uint8Array {
        return this.#pk.toRawBytes(true);
    }

    /**
     * Return the transport secret key value
     *
     * Applications would not normally need to call this
     */
    serialize(): Uint8Array {
        return this.#sk;
    }

    /**
     * @internal constructor
     */
    private constructor(sk: Uint8Array) {
        this.#sk = sk;
        const pk = bls12_381.G1.ProjectivePoint.fromPrivateKey(this.#sk);
        this.#pk = pk;
    }
}

/**
 * Check if a transport public key is valid
 *
 * This tests if the passed byte array is of the expected size and encodes
 * a valid group element.
 */
export function isValidTransportPublicKey(tpk: Uint8Array): boolean {
    // We only accept compressed format for transport public keys
    if (tpk.length != 48) {
        return false;
    }

    try {
        bls12_381.G1.ProjectivePoint.fromHex(tpk);
        return true;
    } catch {
        return false;
    }
}

/**
 * Prefix a bytestring with its length
 */
function prefixWithLen(input: Uint8Array): Uint8Array {
    let length = input.length;

    const result = new Uint8Array(8 + length);

    for (let i = 7; i >= 0; i--) {
        result[i] = length & 0xff;
        length >>>= 8;
    }

    result.set(input, 8);

    return result;
}

/**
 * Enumeration identifying possible master public keys
 */
export enum MasterPublicKeyId {
    /** The production key generated in June 2025 */
    KEY_1 = "key_1",
    /** The test key generated in May 2025 */
    TEST_KEY_1 = "test_key_1",
}

/**
 * Enumeration identifying possible PocketIC test keys
 */
export enum PocketIcMasterPublicKeyId {
    KEY_1 = "key_1",
    TEST_KEY_1 = "test_key_1",
    DFX_TEST_KEY = "dfx_test_key",
}

/**
 * @internal helper to perform hex decoding
 */
function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

/**
 * VetKD master key
 *
 * The VetKD subnet contains a small number of master keys, from which canister
 * keys are derived. In turn, many keys can be derived from the canister keys
 * using a context string.
 */
export class MasterPublicKey {
    readonly #pk: G2Point;

    /**
     * Read a MasterPublicKey from the bytestring encoding
     *
     * Normally the bytes provided here will have been returned by
     * the `vetkd_public_key` management canister interface.
     */
    static deserialize(bytes: Uint8Array): MasterPublicKey {
        return new MasterPublicKey(bls12_381.G2.ProjectivePoint.fromHex(bytes));
    }

    /**
     * Derive a canister master key from the subnet master key
     *
     * To create the derived public key in VetKD, a two step derivation is performed. The first step
     * creates a key that is specific to the canister that is making VetKD requests to the
     * management canister, sometimes called canister master key.
     *
     * This function can be used to compute canister master keys knowing just the subnet master key
     * plus the canister identity. This avoids having to interact with the IC for performing this
     * computation.
     */
    deriveCanisterKey(canisterId: Uint8Array): DerivedPublicKey {
        const dst = "ic-vetkd-bls12-381-g2-canister-id";
        const pkbytes = this.publicKeyBytes();
        const randomOracleInput = new Uint8Array([
            ...prefixWithLen(pkbytes),
            ...prefixWithLen(canisterId),
        ]);
        const offset = hashToScalar(randomOracleInput, dst);
        const g2offset = bls12_381.G2.ProjectivePoint.BASE.multiply(offset);
        return new DerivedPublicKey(this.#pk.add(g2offset));
    }

    /**
     * Return the bytestring encoding of the master public key
     */
    publicKeyBytes(): Uint8Array {
        return this.#pk.toRawBytes(true);
    }

    /**
     * Return the hardcoded master public key used on IC
     *
     * This allows performing public key derivation offline
     */
    static productionKey(
        keyId: MasterPublicKeyId = MasterPublicKeyId.KEY_1,
    ): MasterPublicKey {
        if (keyId == MasterPublicKeyId.KEY_1) {
            return MasterPublicKey.deserialize(
                hexToBytes(
                    "a9caf9ae8af0c7c7272f8a122133e2e0c7c0899b75e502bda9e109ca8193ded3ef042ed96db1125e1bdaad77d8cc60d917e122fe2501c45b96274f43705edf0cfd455bc66c3c060faa2fcd15486e76351edf91fecb993797273bbc8beaa47404",
                ),
            );
        } else if (keyId == MasterPublicKeyId.TEST_KEY_1) {
            return MasterPublicKey.deserialize(
                hexToBytes(
                    "ad86e8ff845912f022a0838a502d763fdea547c9948f8cb20ea7738dd52c1c38dcb4c6ca9ac29f9ac690fc5ad7681cb41922b8dffbd65d94bff141f5fb5b6624eccc03bf850f222052df888cf9b1e47203556d7522271cbb879b2ef4b8c2bfb1",
                ),
            );
        } else {
            throw new Error(
                "Unknown MasterPublicKeyId value for productionKey",
            );
        }
    }

    /**
     * Return the hardcoded master public key used in PocketIC
     *
     * This allows performing public key derivation offline
     */
    static pocketicKey(
        keyId: PocketIcMasterPublicKeyId = PocketIcMasterPublicKeyId.KEY_1,
    ): MasterPublicKey {
        if (keyId == PocketIcMasterPublicKeyId.KEY_1) {
            return MasterPublicKey.deserialize(
                hexToBytes(
                    "8c800b5cff00463d26e8167369168827f1e48f4d8d60f71dd6a295580f65275b5f5f8e6a792c876b2c72492136530d0710a27522ee63977a76216c3cef9e70bfcb45b88736fc62142e7e0737848ce06cbb1f45a4a6a349b142ae5cf7853561e0",
                ),
            );
        } else if (keyId == PocketIcMasterPublicKeyId.TEST_KEY_1) {
            return MasterPublicKey.deserialize(
                hexToBytes(
                    "9069b82c7aae418cef27678291e7f2cb1a008a500eceba7199bffca12421b07c158987c6a22618af3d1958738b2835691028801f7663d311799733286c557c8979184bb62cb559a4d582fca7d2e48b860f08ed6641aef66a059ec891889a6218",
                ),
            );
        } else if (keyId == PocketIcMasterPublicKeyId.DFX_TEST_KEY) {
            return MasterPublicKey.deserialize(
                hexToBytes(
                    "b181c14cf9d04ba45d782c0067a44b0aaa9fc2acf94f1a875f0dae801af4f80339a7e6bf8b09fcf993824c8df3080b3f1409b688ca08cbd44d2cb28db9899f4aa3b5f06b9174240448e10be2f01f9f80079ea5431ce2d11d1c8d1c775333315f",
                ),
            );
        } else {
            throw new Error(
                "Unknown PocketIcMasterPublicKeyId value for pocketicKey",
            );
        }
    }

    /**
     * @internal constructor
     */
    private constructor(pk: G2Point) {
        this.#pk = pk;
    }
}

/**
 * VetKD derived public key
 *
 * An unencrypted VetKey is a BLS signature generated with a canister-specific
 * key. This type represents such keys.
 */
export class DerivedPublicKey {
    readonly #pk: G2Point;

    /**
     * Read a DerivedPublicKey from the bytestring encoding
     *
     * Normally the bytes provided here will have been returned by
     * the `vetkd_public_key` management canister interface.
     */
    static deserialize(bytes: Uint8Array): DerivedPublicKey {
        return new DerivedPublicKey(
            bls12_381.G2.ProjectivePoint.fromHex(bytes),
        );
    }

    /**
     * Perform second-stage derivation of a public key
     *
     * To create the derived public key in VetKD, a two step derivation is performed. The first step
     * creates a key that is specific to the canister that is making VetKD requests to the
     * management canister, sometimes called canister master key. The second step incorporates the
     * "derivation context" value provided to the `vetkd_public_key` management canister interface.
     *
     * If `vetkd_public_key` is invoked with an empty derivation context, it simply returns the
     * canister master key. Then the second derivation step can be done offline, using this
     * function. This is useful if you wish to derive multiple keys without having to interact with
     * the IC each time.
     *
     * If `context` is empty, then this simply returns the underlying key. This matches the behavior
     * of `vetkd_public_key`
     */
    deriveSubKey(context: Uint8Array): DerivedPublicKey {
        if (context.length === 0) {
            return this;
        } else {
            const dst = "ic-vetkd-bls12-381-g2-context";
            const pkbytes = this.publicKeyBytes();
            const randomOracleInput = new Uint8Array([
                ...prefixWithLen(pkbytes),
                ...prefixWithLen(context),
            ]);
            const offset = hashToScalar(randomOracleInput, dst);
            const g2offset = bls12_381.G2.ProjectivePoint.BASE.multiply(offset);
            return new DerivedPublicKey(this.getPoint().add(g2offset));
        }
    }

    /**
     * Return the bytestring encoding of the derived public key
     *
     * Applications would not normally need to call this, unless they
     * are using VetKD for creating a random beacon, in which case
     * these bytes are used by anyone verifying the beacon.
     */
    publicKeyBytes(): Uint8Array {
        return this.#pk.toRawBytes(true);
    }

    /**
     * @internal getter returning the point element of the derived public key
     *
     * Applications would not normally need to call this
     */
    getPoint(): G2Point {
        return this.#pk;
    }

    /**
     * @internal constructor
     *
     * This is public for typing reasons but there should be no need
     * for an application to call this.
     */
    constructor(pk: G2Point) {
        this.#pk = pk;
    }
}

/**
 * Hash an input to a scalar in the BLS12-381 group
 *
 * This is useful if you want to derive a BLS12-381 secret key from some other
 * input data, but this is not a common operation.
 */
export function hashToScalar(input: Uint8Array, domainSep: string): bigint {
    const params = {
        p: bls12_381.params.r,
        m: 1,
        DST: domainSep,
    };

    const options = Object.assign(
        {},
        // @ts-expect-error (https://github.com/paulmillr/noble-curves/issues/179)
        bls12_381.G2.CURVE.htfDefaults,
        params,
    ) as Opts;

    const scalars = hash_to_field(input, 1, options);

    return scalars[0][0];
}

/**
 * @internal helper for data encoding
 */
function asBytes(input: Uint8Array | string): Uint8Array {
    if (typeof input === "string") {
        return new TextEncoder().encode(input);
    } else {
        return input;
    }
}

/**
 * @internal helper for data encoding
 */
function withPrefix(prefix: string, input: Uint8Array | string): Uint8Array {
    const prefixBytes = new TextEncoder().encode(prefix);
    const inputBytes = asBytes(input);

    const result = new Uint8Array(prefixBytes.length + inputBytes.length);
    result.set(prefixBytes, 0);
    result.set(inputBytes, prefixBytes.length);
    return result;
}

/**
 * Derive a symmetric key from the provided input using HKDF-SHA256.
 *
 * The `input` parameter should be a sufficiently long random input generated
 * in a secure way. 256 bits (32 bytes) or longer is preferable.
 *
 * The `domainSep` parameter should be a string unique to your application and
 * also your usage of the resulting key. For example say your application
 * "my-app" is deriving two keys, one for usage "foo" and the other for
 * "bar". You might use as domain separators "my-app-foo" and "my-app-bar".
 *
 * The returned Uint8Array will be `outputLength` bytes long.
 */
export function deriveSymmetricKey(
    input: Uint8Array,
    domainSep: Uint8Array | string,
    outputLength: number,
): Uint8Array {
    const empty = new Uint8Array();
    return hkdf(sha256, input, empty, domainSep, outputLength);
}

/**
 * @internal hash a derived public key plus a message into the BLS12-381 G1 group
 *
 * This is not normally needed by applications using VetKD.
 */
export function augmentedHashToG1(
    pk: DerivedPublicKey,
    message: Uint8Array,
): G1Point {
    const domainSep = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";
    const pkbytes = pk.publicKeyBytes();
    const input = new Uint8Array([...pkbytes, ...message]);
    const pt = bls12_381.G1.ProjectivePoint.fromAffine(
        bls12_381.G1.hashToCurve(input, {
            DST: domainSep,
        }).toAffine(),
    );

    return pt;
}

/**
 * Verify a BLS signature
 *
 * A VetKey is in the end a valid BLS signature; this function checks that a
 * provided BLS signature is the valid one for the provided public key and
 * message.
 *
 * Specifically this verifies "augmented" BLS signature, which includes the
 * public key of the signer as an input to the hash. This addition ensures that
 * messages signed by different public keys are distinct.
 *
 * See section 3.2 of the IETF draft `draft-irtf-cfrg-bls-signature` for details.
 *
 * When a VetKey struct is created (using EncryptedVetKey.decryptAndVerify) the signature
 * is already verified, so using this function is only necessary when
 * using a vetKey as a VRF or for threshold BLS signatures, with the bytes obtained
 * from VetKey.signatureBytes.
 */
export function verifyBlsSignature(
    pk: DerivedPublicKey,
    message: Uint8Array,
    signature: G1Point | Uint8Array,
): boolean {
    const publicKeyBytes = pk.publicKeyBytes();

    // We sign the concatenation of the public key and the message
    const publicKeyAndMessage = new Uint8Array([...publicKeyBytes, ...message]);

    // The standard domain separator defined in section 4.2.2 of draft-irtf-cfrg-bls-signature
    const domainSep = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";

    const options = Object.assign(
        {},
        // @ts-expect-error (https://github.com/paulmillr/noble-curves/issues/179)
        bls12_381.G1.CURVE.htfDefaults,
        {
            DST: domainSep,
        },
    ) as Opts;

    return bls12_381.verifyShortSignature(
        signature,
        publicKeyAndMessage,
        pk.getPoint(),
        options,
    );
}

/**
 * A VetKey (verifiably encrypted threshold key)
 *
 * This is the end product of executing the VetKD protocol.
 *
 * Internally a VetKey is a valid BLS signature for the bytestring
 * `input` which provided when calling the `vetkd_derive_encrypted_key`
 * management canister interface.
 *
 * For certain usages, such as a beacon, the VetKey is actually used directly.
 * However the more common usage of VetKD protocol is for distribution of
 * encryption keys (eg AES keys to encrypt content).
 */
export class VetKey {
    readonly #pt: G1Point;
    readonly #bytes: Uint8Array;

    /**
     * Return the VetKey bytes, aka the BLS signature
     *
     * Use the raw bytes only if your design makes use of the fact that VetKeys
     * are BLS signatures (eg for random beacon or threshold BLS signature
     * generation). If you are using VetKD for key distribution, instead use
     * deriveSymmetricKey or asHkdfCryptoKey
     */
    signatureBytes(): Uint8Array {
        return this.#bytes;
    }

    /**
     * Return the serialization of the VetKey
     *
     * This is the byte encoding of the unencrypted VetKey.
     */
    serialize(): Uint8Array {
        return this.#bytes;
    }

    /**
     * Derive a symmetric key of the requested length from the VetKey
     *
     * As an alternative to this function consider using asDerivedKeyMaterial,
     * which uses the WebCrypto API and prevents export of the underlying key.
     *
     * The `domainSep` parameter should be a string unique to your application and
     * also your usage of the resulting key. For example say your application
     * "my-app" is deriving two keys, one for usage "foo" and the other for
     * "bar". You might use as domain separators "my-app-foo" and "my-app-bar".
     *
     * The returned Uint8Array will be `outputLength` bytes long.
     */
    deriveSymmetricKey(
        domainSep: Uint8Array | string,
        outputLength: number,
    ): Uint8Array {
        return deriveSymmetricKey(this.#bytes, domainSep, outputLength);
    }

    /**
     * Return a DerivedKeyMaterial type which is suitable for further key derivation
     */
    async asDerivedKeyMaterial(): Promise<DerivedKeyMaterial> {
        return DerivedKeyMaterial.setup(this.#bytes);
    }

    /**
     * Deserialize a VetKey from the 48 byte encoding of the BLS signature
     *
     * This deserializes the same value as returned by serialize (or signatureBytes)
     */
    static deserialize(bytes: Uint8Array): VetKey {
        return new VetKey(bls12_381.G1.ProjectivePoint.fromHex(bytes));
    }

    /**
     * @internal getter returning the point object of the VetKey
     *
     * Applications would not usually need to call this
     */
    getPoint(): G1Point {
        return this.#pt;
    }

    /**
     * @internal constructor
     *
     * This is public for typing reasons but there is no reason for an application
     * to call this constructor.
     */
    constructor(pt: G1Point) {
        this.#pt = pt;
        this.#bytes = pt.toRawBytes(true);
    }
}

// The size of the nonce used for encryption by DerivedKeyMaterial
const DERIVED_KEY_MATERIAL_NONCE_LENGTH = 12;

const DERIVED_KEY_MATERIAL_VERSION = 2;

const DERIVED_KEY_MATERIAL_HEADER = "IC GCMv2";
const DERIVED_KEY_MATERIAL_HEADER_BYTES = new TextEncoder().encode(
    DERIVED_KEY_MATERIAL_HEADER,
);
const DERIVED_KEY_MATERIAL_HEADER_LEN = 8;

/*
 * Derived Key Material
 *
 * This type wraps a {@link CryptoKey} whose value is derived from a {@link VetKey}
 *
 * The {@link CryptoKey} is not exportable but it is possible to use the value
 * for further derivation of keys using HKDF.
 *
 * As a convenience it is also possible to directly encrypt messages
 * (using AES in GCM mode) using a key which is first derived using HKDF.
 */
export class DerivedKeyMaterial {
    readonly #hkdf: CryptoKey;
    readonly #raw: CryptoKey;

    /**
     * @internal constructor
     */
    private constructor(hkdf: CryptoKey, raw: CryptoKey) {
        this.#hkdf = hkdf;
        this.#raw = raw;
    }

    static async fromCryptoKey(raw: CryptoKey): Promise<DerivedKeyMaterial> {
        /**
         * For whatever reason it's not possible in WebCrypto to use HKDF to derive a
         * new HKDF key. So instead we have to derive a new key and then import it.
         *
         * We cannot directly use deriveBits because earlier versions of this library
         * created keys using only the deriveKey permission, and not deriveBits. So
         * instead we derive a new WebCrypto key (nominally AES), then export it, then
         * finally import that exported value as an HKDF key.
         */

        const derivationParams = {
            name: "HKDF",
            hash: "SHA-256",
            info: new TextEncoder().encode(
                "ic-vetkd-bls12-381-g2-derived-key-material",
            ),
            salt: new Uint8Array(),
        };

        const gcmParams = {
            name: "AES-GCM",
            length: 32 * 8,
        };

        const derivedKey = await crypto.subtle.deriveKey(
            derivationParams,
            raw,
            gcmParams,
            true, // exportable
            ["encrypt"],
        );

        const derivedKeyBytes = await crypto.subtle.exportKey(
            "raw",
            derivedKey,
        );

        /*
         * Note that the earlier versions of this library imported keys using
         * only deriveKey and not deriveBits permissions. Since such keys might
         * be persisted in a browser nearly indefinitely, any use of deriveBits
         * must be done with the understanding that the call might fail
         */

        const derived = await crypto.subtle.importKey(
            "raw",
            derivedKeyBytes,
            { name: "HKDF" },
            false,
            ["deriveKey", "deriveBits"],
        );

        return new DerivedKeyMaterial(derived, raw);
    }

    /**
     * @internal constructor
     */
    static async setup(vetkey: Uint8Array) {
        const exportable = false;

        /*
         * Note that the earlier versions of this library imported keys using
         * only deriveKey and not deriveBits permissions. Since such keys might
         * be persisted in a browser nearly indefinitely, any use of deriveBits
         * must be done with the understanding that the call might fail
         */
        const raw = await globalThis.crypto.subtle.importKey(
            "raw",
            vetkey,
            "HKDF",
            exportable,
            ["deriveKey", "deriveBits"],
        );

        return DerivedKeyMaterial.fromCryptoKey(raw);
    }

    /**
     * Return the CryptoKey
     */
    getCryptoKey(): CryptoKey {
        return this.#raw;
    }

    /**
     * Return a WebCrypto CryptoKey handle suitable for AES-GCM encryption/decryption
     *
     * The key is derived using HKDF with the provided domain separator
     *
     * The CryptoKey is not exportable
     */
    private async deriveAesGcmCryptoKey(
        domainSep: Uint8Array | string,
        version: number,
    ): Promise<CryptoKey> {
        const algorithm = {
            name: "HKDF",
            hash: "SHA-256",
            length: 32 * 8,
            info: withPrefix(
                "ic-vetkd-bls12-381-g2-aes-gcm-v" + version.toString() + "-",
                domainSep,
            ),
            salt: new Uint8Array(),
        };

        const gcmParams = {
            name: "AES-GCM",
            length: 32 * 8,
        };

        const exportable = false;

        return globalThis.crypto.subtle.deriveKey(
            algorithm,
            this.#hkdf,
            gcmParams,
            exportable,
            ["encrypt", "decrypt"],
        );
    }

    /**
     * Encrypt the provided message using AES-GCM and a key derived using HKDF
     *
     * The GCM key is derived using HKDF with the provided domain separator
     */
    async encryptMessage(
        message: Uint8Array | string,
        domainSep: Uint8Array | string,
        associatedData: Uint8Array | string,
    ): Promise<Uint8Array> {
        const gcmKey = await this.deriveAesGcmCryptoKey(
            domainSep,
            DERIVED_KEY_MATERIAL_VERSION,
        );

        // The nonce must never be reused with a given key
        const nonce = globalThis.crypto.getRandomValues(
            new Uint8Array(DERIVED_KEY_MATERIAL_NONCE_LENGTH),
        );

        const aad = withPrefix(DERIVED_KEY_MATERIAL_HEADER, associatedData);

        const ciphertext = new Uint8Array(
            await globalThis.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: nonce, additionalData: aad },
                gcmKey,
                asBytes(message),
            ),
        );

        // Concatenate the nonce to the beginning of the ciphertext
        return new Uint8Array([
            ...DERIVED_KEY_MATERIAL_HEADER_BYTES,
            ...nonce,
            ...ciphertext,
        ]);
    }

    /**
     * Decrypt the provided ciphertext using AES-GCM and a key derived using HKDF
     *
     * The GCM key is derived using HKDF with the provided domain separator
     */
    async decryptMessage(
        message: Uint8Array,
        domainSep: Uint8Array | string,
        associatedData: Uint8Array | string,
    ): Promise<Uint8Array> {
        const GCM_TAG_LENGTH = 16;

        const minLen =
            DERIVED_KEY_MATERIAL_HEADER_LEN +
            DERIVED_KEY_MATERIAL_NONCE_LENGTH +
            GCM_TAG_LENGTH;
        if (message.length < minLen) {
            throw new Error(
                "Invalid ciphertext, too short to possibly be valid",
            );
        }

        const header = message.slice(0, DERIVED_KEY_MATERIAL_HEADER_LEN); // first 8 bytes are the header

        // If multiple versions are ever supported in the future, and we
        // must retain backward compatability, then this would need to be
        // extended to check for multiple different headers and process
        // the ciphertext accordingly.
        if (!isEqual(header, DERIVED_KEY_MATERIAL_HEADER_BYTES)) {
            if (associatedData.length == 0) {
                // Possibly the old "headerless" format which did not support associated data

                const nonce = message.slice(
                    0,
                    DERIVED_KEY_MATERIAL_NONCE_LENGTH,
                ); // first 12 bytes are the nonce
                const ciphertext = message.slice(
                    DERIVED_KEY_MATERIAL_NONCE_LENGTH,
                ); // remainder GCM ciphertext

                const algorithm = {
                    name: "HKDF",
                    hash: "SHA-256",
                    length: 32 * 8,
                    info: asBytes(domainSep),
                    salt: new Uint8Array(),
                };

                const gcmParams = {
                    name: "AES-GCM",
                    length: 32 * 8,
                };

                const gcmKey = await globalThis.crypto.subtle.deriveKey(
                    algorithm,
                    this.#raw,
                    gcmParams,
                    false,
                    ["decrypt"],
                );

                try {
                    const ptext = await globalThis.crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: nonce },
                        gcmKey,
                        ciphertext,
                    );
                    return new Uint8Array(ptext);
                } catch {
                    throw new Error("Decryption failed");
                }
            } else {
                throw new Error(
                    "Unknown header for AES-GCM encrypted ciphertext",
                );
            }
        }

        const aad = withPrefix(DERIVED_KEY_MATERIAL_HEADER, associatedData);

        const nonce = message.slice(
            DERIVED_KEY_MATERIAL_HEADER_LEN,
            DERIVED_KEY_MATERIAL_HEADER_LEN + DERIVED_KEY_MATERIAL_NONCE_LENGTH,
        ); // next 12 bytes are the nonce
        const ciphertext = message.slice(
            DERIVED_KEY_MATERIAL_HEADER_LEN + DERIVED_KEY_MATERIAL_NONCE_LENGTH,
        ); // remainder GCM ciphertext
        const gcmKey = await this.deriveAesGcmCryptoKey(
            domainSep,
            DERIVED_KEY_MATERIAL_VERSION,
        );

        try {
            const ptext = await globalThis.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: nonce, additionalData: aad },
                gcmKey,
                ciphertext,
            );
            return new Uint8Array(ptext);
        } catch {
            throw new Error("Decryption failed");
        }
    }
}

export class EncryptedVetKey {
    readonly #c1: G1Point;
    readonly #c2: G2Point;
    readonly #c3: G1Point;

    /**
     * Parse an encrypted key returned by the `vetkd_derive_encrypted_key`
     * managment canister interface
     */
    static deserialize(bytes: Uint8Array): EncryptedVetKey {
        if (bytes.length !== G1_BYTES + G2_BYTES + G1_BYTES) {
            throw new Error("Invalid EncryptedVetKey serialization");
        }

        const c1 = bls12_381.G1.ProjectivePoint.fromHex(
            bytes.subarray(0, G1_BYTES),
        );
        const c2 = bls12_381.G2.ProjectivePoint.fromHex(
            bytes.subarray(G1_BYTES, G1_BYTES + G2_BYTES),
        );
        const c3 = bls12_381.G1.ProjectivePoint.fromHex(
            bytes.subarray(G1_BYTES + G2_BYTES),
        );
        return new EncryptedVetKey(c1, c2, c3);
    }

    /**
     * Decrypt the encrypted key returning a VetKey
     */
    decryptAndVerify(
        tsk: TransportSecretKey,
        dpk: DerivedPublicKey,
        input: Uint8Array,
    ): VetKey {
        // Check that c1 and c2 have the same discrete logarithm, ie that e(c1, g2) == e(g1, c2)

        const g1 = bls12_381.G1.ProjectivePoint.BASE;
        const negG2 = bls12_381.G2.ProjectivePoint.BASE.negate();
        const oneGt = bls12_381.fields.Fp12.ONE;

        const c1c2 = bls12_381.pairingBatch([
            { g1: this.#c1, g2: negG2 },
            { g1: g1, g2: this.#c2 },
        ]);

        if (!bls12_381.fields.Fp12.eql(c1c2, oneGt)) {
            throw new Error("Invalid VetKey");
        }

        // Compute the purported vetKey k
        const k = this.#c3.subtract(
            this.#c1.multiply(
                bls12_381.G1.normPrivateKeyToScalar(tsk.serialize()),
            ),
        );

        // Verify that k is a valid BLS signature
        if (verifyBlsSignature(dpk, input, k)) {
            return new VetKey(k);
        } else {
            throw new Error("Invalid VetKey");
        }
    }

    /**
     * @internal constructor
     */
    private constructor(c1: G1Point, c2: G2Point, c3: G1Point) {
        this.#c1 = c1;
        this.#c2 = c2;
        this.#c3 = c3;
    }
}

/* IBE (Identity Based Encryption) helper functions, not exported */

enum IbeDomainSeparators {
    HashToMask = "ic-vetkd-bls12-381-ibe-hash-to-mask",
    MaskSeed = "ic-vetkd-bls12-381-ibe-mask-seed",
    // Note that the messge length is appended to this
    MaskMsg = "ic-vetkd-bls12-381-ibe-mask-msg-",
}

// "IC IBE" (ASCII) plus 0x00 0x01 for future extensions/ciphersuites
const IBE_HEADER_BYTES = new Uint8Array([
    0x49, 0x43, 0x20, 0x49, 0x42, 0x45, 0x00, 0x01,
]);
const IBE_HEADER_LEN = 8;

function hashToMask(
    header: Uint8Array,
    seed: Uint8Array,
    msg: Uint8Array,
): bigint {
    /*
      It would have been better to instead use the SHA-256 of the message instead of the
      message directly, since that would avoid having to allocate an extra buffer of
      length proportional to the message. If in the future any change is made to the
      IBE scheme, consider also changing this.
    */

    const randomOracleInput = new Uint8Array([...header, ...seed, ...msg]);
    return hashToScalar(randomOracleInput, IbeDomainSeparators.HashToMask);
}

function xorBuf(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.length !== b.length) {
        throw new Error("xorBuf arguments should have the same length");
    }
    const c = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        c[i] = a[i] ^ b[i];
    }
    return c;
}

function maskSeed(seed: Uint8Array, t: Uint8Array): Uint8Array {
    if (t.length !== 576) {
        throw new Error("Unexpected size for Gt element");
    }
    const mask = deriveSymmetricKey(
        t,
        IbeDomainSeparators.MaskSeed,
        seed.length,
    );
    return xorBuf(mask, seed);
}

function maskMsg(msg: Uint8Array, seed: Uint8Array): Uint8Array {
    /*
    Zero prefix the length up to 20 digits, which is sufficient to be fixed
    length for any 64-bit length. This ensures all of the MaskMsg domain
    separators are of equal length. With how we use the domain separators, this
    padding isn't required - we only need uniquness - but having variable
    length domain separators is generally not considered a good practice and is
    easily avoidable here.
    */
    const domainSep = IbeDomainSeparators.MaskMsg.concat(
        msg.length.toString().padStart(20, "0"),
    );
    const xofSeed = deriveSymmetricKey(seed, domainSep, 32);

    const mask = shake256(xofSeed, { dkLen: msg.length });

    return xorBuf(msg, mask);
}

function serializeGtElem(gt: Fp12): Uint8Array {
    // noble-curves formats the Gt element bytes in reverse order
    const enc = bls12_381.fields.Fp12.toBytes(gt);

    const bytes = new Uint8Array(576);

    const shuffle = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

    for (let i = 0; i < 12; ++i) {
        for (let j = 0; j < 48; ++j) {
            bytes[48 * i + j] = enc[48 * shuffle[i] + j];
        }
    }

    return bytes;
}

function isEqual(x: Uint8Array, y: Uint8Array): boolean {
    if (x.length !== y.length) {
        return false;
    }

    let diff = 0;
    for (let i = 0; i < x.length; ++i) {
        diff |= x[i] ^ y[i];
    }
    return diff == 0;
}

/**
 * An identity used for identity based encryption
 *
 * As far as the IBE encryption scheme goes this is simply an opauqe bytestring
 * We provide a type to make code using the IBE a bit easier to understand
 */
export class IbeIdentity {
    readonly #identity: Uint8Array;

    private constructor(identity: Uint8Array) {
        this.#identity = identity;
    }

    /**
     * Create an identity from a byte string
     */
    static fromBytes(bytes: Uint8Array) {
        return new IbeIdentity(bytes);
    }

    /**
     * Create an identity from a string
     */
    static fromString(bytes: string) {
        return IbeIdentity.fromBytes(new TextEncoder().encode(bytes));
    }

    /**
     * Create an identity from a Principal
     */
    static fromPrincipal(principal: Principal) {
        return IbeIdentity.fromBytes(principal.toUint8Array());
    }

    /**
     * @internal getter returning the encoded
     */
    getBytes(): Uint8Array {
        return this.#identity;
    }
}

const IBE_SEED_BYTES = 32;

/**
 * A random seed, used for identity based encryption
 */
export class IbeSeed {
    readonly #seed: Uint8Array;

    private constructor(seed: Uint8Array) {
        // This should never happen as our callers ensure this
        if (seed.length !== IBE_SEED_BYTES) {
            throw new Error("IBE seed must be exactly IBE_SEED_BYTES long");
        }

        this.#seed = seed;
    }

    /**
     * Create a seed for IBE encryption from a byte string
     *
     * This input should be randomly chosen by a secure random number generator.
     * If the seed is not securely generated the IBE scheme will be insecure.
     *
     * At least 128 bits (16 bytes) must be provided.
     *
     * If the input is exactly 256 bits it is used directly. Otherwise the input
     * is hashed with HKDF to produce a 256 bit seed.
     */
    static fromBytes(bytes: Uint8Array) {
        if (bytes.length < 16) {
            throw new Error(
                "Insufficient input material for IbeSeed derivation",
            );
        } else if (bytes.length == IBE_SEED_BYTES) {
            return new IbeSeed(bytes);
        } else {
            return new IbeSeed(
                deriveSymmetricKey(
                    bytes,
                    "ic-vetkd-bls12-381-ibe-hash-seed",
                    IBE_SEED_BYTES,
                ),
            );
        }
    }

    /**
     * Create a random seed for IBE encryption
     */
    static random() {
        return new IbeSeed(
            globalThis.crypto.getRandomValues(new Uint8Array(IBE_SEED_BYTES)),
        );
    }

    /**
     * @internal getter returning the seed bytes
     */
    getBytes(): Uint8Array {
        return this.#seed;
    }
}

/**
 * Total overhead for an IBE ciphertext
 */
const IBE_OVERHEAD = IBE_HEADER_LEN + IBE_SEED_BYTES + G2_BYTES;

/**
 * IBE (Identity Based Encryption)
 */
export class IbeCiphertext {
    readonly #header: Uint8Array;
    readonly #c1: G2Point;
    readonly #c2: Uint8Array;
    readonly #c3: Uint8Array;

    /**
     * Helper function for determining the size of an IBE ciphertext in bytes.
     */
    static ciphertextSize(plaintextSize: number): number {
        if (plaintextSize < 0) {
            throw new Error(
                "IbeCiphertext.ciphertextSize argument cannot be negative",
            );
        }

        return plaintextSize + IBE_OVERHEAD;
    }

    /**
     * Helper function for determining the size of an IBE plaintext in bytes.
     */
    static plaintextSize(ciphertextSize: number): number {
        if (ciphertextSize < IBE_OVERHEAD) {
            throw new Error(
                "IbeCiphertext.plaintextSize given ciphertext size is too small to be valid",
            );
        }

        return ciphertextSize - IBE_OVERHEAD;
    }

    /**
     * Serialize the IBE ciphertext to a bytestring
     */
    serialize(): Uint8Array {
        const c1bytes = this.#c1.toRawBytes(true);
        return new Uint8Array([
            ...this.#header,
            ...c1bytes,
            ...this.#c2,
            ...this.#c3,
        ]);
    }

    /**
     * Deserialize an IBE ciphertext
     */
    static deserialize(bytes: Uint8Array): IbeCiphertext {
        if (bytes.length < IBE_HEADER_LEN + G2_BYTES + IBE_SEED_BYTES) {
            throw new Error("Invalid IBE ciphertext");
        }

        const header = bytes.subarray(0, IBE_HEADER_LEN);
        const c1 = bls12_381.G2.ProjectivePoint.fromHex(
            bytes.subarray(IBE_HEADER_LEN, IBE_HEADER_LEN + G2_BYTES),
        );
        const c2 = bytes.subarray(
            IBE_HEADER_LEN + G2_BYTES,
            IBE_HEADER_LEN + G2_BYTES + IBE_SEED_BYTES,
        );
        const c3 = bytes.subarray(IBE_HEADER_LEN + G2_BYTES + IBE_SEED_BYTES);

        if (!isEqual(header, IBE_HEADER_BYTES)) {
            throw new Error("Unexpected header for IBE ciphertext");
        }

        return new IbeCiphertext(header, c1, c2, c3);
    }

    /**
     * Encrypt a message using IBE, returning the ciphertext
     *
     * Any user who is able to retrieve the VetKey for the specified derived public key and
     * identity will be able to decrypt this message.
     *
     * There is no fixed upper bound on the size of the message that can be encrypted using
     * this scheme. However, internally during the encryption process several heap allocations
     * are performed which are approximately the same length as the message itself, so
     * encrypting or decrypting very large messages may result in memory allocation errors.
     *
     * If you anticipate using IBE to encrypt very large messages, consider using IBE just to
     * encrypt a symmetric key, and then using a standard cipher such as AES-GCM to encrypt the
     * data.
     *
     * The seed parameter must be a randomly generated value that was generated just for this
     * one message. Using it for a second message, or for any other purpose, compromises the
     * security of the IBE scheme.
     */
    static encrypt(
        dpk: DerivedPublicKey,
        identity: IbeIdentity,
        msg: Uint8Array,
        seed: IbeSeed,
    ): IbeCiphertext {
        const header = IBE_HEADER_BYTES;
        const t = hashToMask(header, seed.getBytes(), msg);
        const pt = augmentedHashToG1(dpk, identity.getBytes());
        const tsig = bls12_381.fields.Fp12.pow(
            bls12_381.pairing(pt, dpk.getPoint()),
            t,
        );

        const c1 = bls12_381.G2.ProjectivePoint.BASE.multiply(t);
        const c2 = maskSeed(seed.getBytes(), serializeGtElem(tsig));
        const c3 = maskMsg(msg, seed.getBytes());

        return new IbeCiphertext(header, c1, c2, c3);
    }

    /**
     * Decrypt an IBE ciphertext, returning the message
     *
     * There is no fixed upper bound on the size of the message that can be encrypted using
     * this scheme. However, internally during the encryption process several heap allocations
     * are performed which are approximately the same length as the message itself, so
     * encrypting or decrypting very large messages may result in memory allocation errors.
     */
    decrypt(vetkd: VetKey): Uint8Array {
        const seed = maskSeed(
            this.#c2,
            serializeGtElem(bls12_381.pairing(vetkd.getPoint(), this.#c1)),
        );

        const msg = maskMsg(this.#c3, seed);

        const t = hashToMask(this.#header, seed, msg);

        const valid = isEqual(
            bls12_381.G2.ProjectivePoint.BASE.multiply(t).toRawBytes(true),
            this.#c1.toRawBytes(true),
        );

        if (valid) {
            return msg;
        } else {
            throw new Error("Decryption failed");
        }
    }

    /**
     * Private constructor
     */
    private constructor(
        header: Uint8Array,
        c1: G2Point,
        c2: Uint8Array,
        c3: Uint8Array,
    ) {
        this.#header = header;
        this.#c1 = c1;
        this.#c2 = c2;
        this.#c3 = c3;
    }
}

/// The size of the VRF output
const VRF_OUTPUT_BYTES = 32;

/**
 * VRF (Verifiable Random Function) Output
 *
 * VetKD can be used to construct a VRF, which is a public key version of a
 * keyed hash. Like a standard keyed hash, it takes an input string and produces
 * a output string which is indistinguishable from random. The difference
 * between a VRF and a normal keyed hash is that a VRF can only be computed
 * by someone with access to the VRF secret key, while the VRF output can be verified
 * by any party with access to the public key.
 *
 * For some general background on VRFs consult [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html)
 */
export class VrfOutput {
    readonly #proof: VetKey;
    readonly #dpk: DerivedPublicKey;
    readonly #input: Uint8Array;
    readonly #output: Uint8Array;

    private static computeVrfHash(
        proof: VetKey,
        dpk: DerivedPublicKey,
        input: Uint8Array,
    ): Uint8Array {
        const hkdfInput = new Uint8Array([
            ...prefixWithLen(proof.serialize()),
            ...prefixWithLen(dpk.publicKeyBytes()),
            ...prefixWithLen(input),
        ]);

        return deriveSymmetricKey(
            hkdfInput,
            "ic-vetkd-bls12-381-g2-vrf",
            VRF_OUTPUT_BYTES,
        );
    }

    /**
     * Serialize a VrfOutput to a byte string
     */
    serialize(): Uint8Array {
        return new Uint8Array([
            ...this.#proof.serialize(),
            ...this.#dpk.publicKeyBytes(),
            ...this.#input,
        ]);
    }

    /**
     * Deserialize and verify a VrfOutput
     *
     * Note this verifies the VrfOutput with respect to the derived public key
     * and VRF input which are included in the struct. It is the responsibility
     * of the application to examine the return value of `publicKey` and `input`
     * and ensure these values make sense in the context where this VRF is being
     * used.
     */
    static deserialize(bytes: Uint8Array): VrfOutput {
        if (bytes.length < G1_BYTES + G2_BYTES) {
            throw new Error(
                "VrfOutput.deserialize input too short to possibly be valid",
            );
        }

        const proof = VetKey.deserialize(bytes.slice(0, G1_BYTES));
        const dpk = DerivedPublicKey.deserialize(
            bytes.slice(G1_BYTES, G1_BYTES + G2_BYTES),
        );
        const input = bytes.slice(G1_BYTES + G2_BYTES); // remainder is the VRF input string

        if (!verifyBlsSignature(dpk, input, proof.getPoint())) {
            throw new Error("VrfOutput.deserialize proof is invalid");
        }

        return new VrfOutput(proof, dpk, input);
    }

    /**
     * Return the public key under which this VRF output was derived
     */
    publicKey(): DerivedPublicKey {
        return this.#dpk;
    }

    /**
     * Return the input that was used to create this VRF output
     */
    input(): Uint8Array {
        return this.#input;
    }

    /**
     * Return the VRF output
     *
     * This is a random-looking value which was provably generated by some party with
     * access to the VRF secret key.
     */
    output(): Uint8Array {
        return this.#output;
    }

    /**
     * Private constructor
     */
    private constructor(
        proof: VetKey,
        dpk: DerivedPublicKey,
        input: Uint8Array,
    ) {
        this.#proof = proof;
        this.#dpk = dpk;
        this.#input = input;
        this.#output = VrfOutput.computeVrfHash(proof, dpk, input);
    }
}
