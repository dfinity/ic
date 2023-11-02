/// Computes a hash tree leaf hash.
/// See "reconstruct" function on https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate.
pub(crate) fn ic_hashtree_leaf_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = ic_crypto_sha2::Sha256::new();
    // \0x10 is the length of the "ic-hashtree-leaf" byte string.
    //
    // See also: [ic_crypto_tree_hash::hasher::Hasher::for_domain],
    // which we do not use here because we need only a tiny and
    // non-essential piece of the [ic_cypto_tree_hash] library.
    h.write(b"\x10ic-hashtree-leaf");
    h.write(bytes);
    h.finish()
}
