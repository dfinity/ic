/**
 * @module @dfinity/vetkeys
 *
 * @description Provides frontend utilities for the low-level use of Verifiably Encrypted Threshold Keys (VetKeys) on the Internet Computer (IC) such as decryption of encrypted VetKeys, identity based encryption (IBE), and symmetric key derivation from a VetKey.
 *
 * ## Usage Example: IBE
 *
 * This example demonstrates the complete flow from key generation to message encryption and decryption:
 *
 * ```ts
 * import {
 *   TransportSecretKey,
 *   DerivedPublicKey,
 *   EncryptedKey,
 *   VetKey,
 *   IbeCiphertext,
 *   IbeIdentity,
 *   IbeSeed,
 * } from "ic_vetkd_sdk_utils";
 *
 * // 1. Generate a Transport Secret Key for decrypting VetKD-derived keys
 * const tsk = TransportSecretKey.random();
 *
 * // 2. Load a Derived Public Key (obtained from the IC)
 * const dpkBytes = new Uint8Array([...]); // Replace with actual bytes from IC
 * const dpk = DerivedPublicKey.deserialize(dpkBytes);
 *
 * // 3. Perform second-stage key derivation with a specific input, e.g., other user's principal as bytes
 * const input = new Uint8Array([1, 2, 3]); // Your application-specific input
 * const derivedKey = dpk.deriveKey(input);
 * console.log("Derived Public Key:", derivedKey.publicKeyBytes());
 *
 * // 4. Decrypt a VetKey using the transport secret key
 * const encKeyBytes = new Uint8Array([...]); // Replace with encrypted key from IC
 * const encryptedKey = new EncryptedKey(encKeyBytes);
 * const vetKey = encryptedKey.decryptAndVerify(tsk, dpk, input);
 * console.log('Decrypted VetKey:', vetKey.signatureBytes());
 *
 * // 5. Use Identity-Based Encryption to encrypt and decrypt a message
 * const message = new TextEncoder().encode("Secret message");
 *
 * // 6. Encrypt the message
 * const ciphertext = IbeCiphertext.encrypt(
 *   dpk,
 *   IbeIdentity.fromBytes(input),
 *   message,
 *   IbeSeed.random()
 * );
 * const serializedCiphertext = ciphertext.serialize();
 *
 * // 7. Decrypt the message
 * const deserializedCiphertext = IbeCiphertext.deserialize(serializedCiphertext);
 * const decryptedMessage = deserializedCiphertext.decrypt(vetKey);
 * console.log("Decrypted Message:", new TextDecoder().decode(decryptedMessage));
 * ```
 *
 * ## Security Considerations
 *
 * - **Keep Transport Secret Keys Private:** Never expose the transport secret key as it is required for decrypting VetKeys.
 * - **Unique Domain Separators:** Use unique domain separators for symmetric key derivation to prevent cross-context attacks.
 * - **Authenticated Encryption:** Always verify ciphertext integrity when decrypting to prevent unauthorized modifications.
 * - **Secure Key Storage:** If storing symmetric keys, ensure they are exposed only in authorized environments such as user's browser page.
 */

export * from "./utils/utils";
