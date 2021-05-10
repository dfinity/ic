//! Various data for testing.

// Ed25519 test vector "TEST 1" from https://tools.ietf.org/html/rfc8032#section-7.1
pub const ED25519_SK_1_RFC8032_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const ED25519_PK_1_RFC8032_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
pub const ED25519_MSG_1_RFC8032_HEX: &str = "";
pub const ED25519_SIG_1_RFC8032_HEX: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// Ed25519 test vectors with DER-encoded public keys.
// Generated using ic-webauthn-cli,
// and some other tools for post-processing.
pub const ED25519_PK_1_HEX: &str =
    "B3997656BA51FF6DA37B61D8D549EC80717266ECF48FB5DA52B654412634844C";
pub const ED25519_PK_1_DER_HEX: &str =
    "302A300506032B6570032100B3997656BA51FF6DA37B61D8D549EC80717266ECF48FB5DA52B654412634844C";
pub const ED25519_MSG_1_HEX: &str = "";
pub const ED25519_SIG_1_HEX: &str = "90EBBB4F6FE3462E6EEEF01BAD59EC0D4C483750291EB8E1E9B225558BC9940F85D6D4902C453C0B6D7EF5DCB3C0EEA1AC5B2287E2D5E0FF12A50F405B861309";

pub const ED25519_PK_2_HEX: &str =
    "A5AFB5FEB6DFB6DDF5DD6563856FFF5484F5FE304391D9ED06697861F220C610";
pub const ED25519_PK_2_DER_HEX: &str =
    "302A300506032B6570032100A5AFB5FEB6DFB6DDF5DD6563856FFF5484F5FE304391D9ED06697861F220C610";
pub const ED25519_MSG_2_HEX: &str = "";
pub const ED25519_SIG_2_HEX: &str = "C2FC88F1AECCD886E8024A348484CD5F36F958FDE2502F4BCC0C45CF8F209DCC7634F5465A9634A851B83558CC6DE012E73F3FACB4D321AB5EEE5775405CEB06";

pub const ED25519_PK_3_HEX: &str =
    "C8413108F121CB794A10804D15F613E40ECC7C78A4EC567040DDF78467C71DFF";
pub const ED25519_PK_3_DER_HEX: &str =
    "302A300506032B6570032100C8413108F121CB794A10804D15F613E40ECC7C78A4EC567040DDF78467C71DFF";
pub const ED25519_MSG_3_HEX: &str = "";
pub const ED25519_SIG_3_HEX: &str = "BA375FF73EF785ED59ACC15166950ED3B7DFF6B8D26B0B6083CB999B0E96FBBA7F94E9E1A38F0BF1A21BE0D3F9EF9406CCA0EB643E45048C6A3493B4AB15A701";

// WebAuthn example COSE-encoded ECDSA-P256 public key
// (see https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples).
pub const WEBAUTHN_ECDSA_P256_PK_COSE_HEX: &str = "a501020326200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";

// ECDSA-P256 public keys in COSE-format and signatures in DER-format,
// generated using JS according to WebAuthn spec.
pub const ECDSA_P256_PK_1_COSE_HEX: &str = "a5010203262001215820ad2f0169b23f64500df8ecacb4c3e8b6a1ad72c3133f2e9ccbe74629a2a7cf1d22582035c748923ce1c59361295d06f813ec3e12f65a04ebf0df54265975145aa972cf";
pub const ECDSA_P256_PK_1_COSE_DER_WRAPPED_HEX: &str = "305E300C060A2B0601040183B8430101034E00a5010203262001215820ad2f0169b23f64500df8ecacb4c3e8b6a1ad72c3133f2e9ccbe74629a2a7cf1d22582035c748923ce1c59361295d06f813ec3e12f65a04ebf0df54265975145aa972cf";
pub const ECDSA_P256_SIG_1_DER_HEX: &str = "304502200c8b35c7585701e3f57400745a3088b936ad46f907ca1db88066c47e60397932022100c3738c97c833a3d33536f21ca8093a305f6120b3056dc4790a4505a6aa5f1fd0";
pub const WEBAUTHN_MSG_1_HEX: &str = "9bc7b89a00c2aa9105a648bf57d85b5b3c669fd1e4b9ebafcdf525b35ea5a64501000000559d865b1f13e4d37794660207547d3706e5049f190c380d50d3060baf32a7452e";

pub const ECDSA_P256_PK_2_COSE_HEX: &str = "a50102032620012158200f42629866a318de25f29c549ebdfcf7e9a58a26782edf39b55fc58b98ec423a225820d4922a9c0aa842c28516711a698b7fabef663bf2fe433baec3d743721a522a56";
pub const ECDSA_P256_PK_2_COSE_DER_WRAPPED_HEX: &str = "305E300C060A2B0601040183B8430101034E00a50102032620012158200f42629866a318de25f29c549ebdfcf7e9a58a26782edf39b55fc58b98ec423a225820d4922a9c0aa842c28516711a698b7fabef663bf2fe433baec3d743721a522a56";
pub const ECDSA_P256_SIG_2_DER_HEX: &str = "3045022100e4e74ecff065dfbcc00cd1a7ea17f3d9cb907d80c114a761373148acd0ce71ee02205335bfb3c1c40059a54f94e4c6ab90e6b89ddd05f83f1e74d4d026ee30fd74a8";
pub const WEBAUTHN_MSG_2_HEX: &str = "9bc7b89a00c2aa9105a648bf57d85b5b3c669fd1e4b9ebafcdf525b35ea5a645055f622a2713513422fa8b8c360a962b0f64e7aa1b0b6b0bbd5f6e26775a285fcdf716577a";

// A DER-wrapped COSE ECDSA-P256 public key.
// (from https://sdk.dfinity.org/docs/interface-spec/index.html#signatures)
pub const ECDSA_P256_PK_3_COSE_DER_WRAPPED_HEX: &str = "305E300C060A2B0601040183B8430101034E00A50102032620012158207FFD83632072FD1BFEAF3FBAA43146E0EF95C3F55E3994A41BBF2B5174D771DA22582032497EED0A7F6F000928765B8318162CFD80A94E525A6A368C2363063D04E6ED";

// ECDSA_PK_DER_HEX was generated via the following commands:
//   openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
//   openssl ec -in private.ec.key -pubout -outform DER -out ecpubkey.der
//   hexdump -ve '1/1 "%.2x"' ecpubkey.der
pub const ECDSA_P256_PK_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004485c32997ce7c6d38ca82c821185c689d424fac7c9695bb97786c4248aab6428949bcd163e2bcf3eeeac4f200b38fbd053f82c4e1776dc9c6dc8db9b7c35e06f";

/// ECDSA-P256 public keys and signatures generated by browsers using Web
/// Crypto API, with the following JavasScript code (note that the signatures
/// are on empty messages):
/// ``` javascript
/// var enc = new TextEncoder();
/// window.crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"},
///     true, ["sign", "verify"]).then(function(key) {
///   window.crypto.subtle.exportKey("spki", key.publicKey).then(function(keydata) {
///      // e.g. console.log(buf2hex(new Uint8Array(keydata)));
///   });
///   window.crypto.subtle.sign({name: "ECDSA", namedCurve: "P-256",
///       hash: {name: "SHA-256"}}, key.privateKey,
///       enc.encode("")).then(function(signature) {
///     // e.g. console.log(buf2hex(new Uint8Array(signature)));
///   });
/// });
/// ```
/// where
/// ``` javascript
/// function buf2hex(buffer) { // buffer is an ArrayBuffer
///    return Array.prototype.map.call(new Uint8Array(buffer),
///       x => ('00' + x.toString(16)).slice(-2)).join('');
/// }
/// ```
pub const SAFARI_ECDSA_P256_PK_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004e9ef0251bf1a18088f013ce452d46c1e6d46858af909b26ee4edfbf94767da910fbbde09a884f3890c06b5375020ff496cf07b41da66c132039c0859db702681";
pub const CHROME_ECDSA_P256_PK_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004b2cd11f3cb911d7a5e0e0a78c137585318107f8bb55e9fdcfa2b46953b16ce8d55fc6d6c32d2dc07f0da32e3aaa959af42ebfd6eb8afade0ec05f54183481ea1";
pub const FIREFOX_ECDSA_P256_PK_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004ba6b9ffe7690db2752806390996f6ade25d7831a49413fb1ef8a961175a4f38b293da921735c3c7dacdd29ddf29a967191c7c20ec45af418e0b53d8beef11663";

pub const SAFARI_ECDSA_P256_SIG_RAW_HEX: &str = "2da3d334c8816feb71b16539db8b1831dc7bd7fcd1eda34bab00592d4f6e22bbcaeb11d6e80235dfebebfd0061af551b67ff1eadab772bb48b77a58088ae8c00";
pub const CHROME_ECDSA_P256_SIG_RAW_HEX: &str = "8f3e656b4d775a91c57d5342e6d9517550da820a34f880860d6498fb2e60295ec7eb4f3d0f493d687d68e62465b2ad91385dbcc881f419ee8fe8c5e5f91ee3ae";
pub const FIREFOX_ECDSA_P256_SIG_RAW_HEX: &str = "265b3ff7bf75dee9b2d5493c4313ab591b6ebad302f2c98e3fab6fd720bc86ebe296cf278a3f1be479b9305158d3509d6a4607ca1ef8afa7e929ff00e872b041";

// Test cases generated as follows:
//
// $ openssl ecparam -name secp256k1 -genkey -noout -out priv.pem
// $ openssl ec -in priv.pem -pubout -outform der -out pub.der
// $ echo -n "" | openssl dgst -sha256 -sign priv.pem > sign.der
// $ xxd -p < sign.der > sign.hex
//
// (plus minor massaging with a text editor).
pub const ECDSA_SECP256K1_PK_DER_HEX: &str = "3056301006072a8648ce3d020106052b8104000a034200047060f720298ffa0f48d9606abdb013bc82f4ff269f9adc3e7226391af3fad8b30fd6a30deb81d5b4f9e142971085d0ae15b8e222d85af1e17438e630d09b7ef4";
pub const ECDSA_SECP256K1_SIG_RAW_HEX: &str = "1a39066abe0da4d68a6a682e941c73b0f112b1f1e1766c2c4514591dd640793196c79e9e0d0e9678d72ba421fac9ddde86214d8fbe51e63f8b48f37471b69fbb";
