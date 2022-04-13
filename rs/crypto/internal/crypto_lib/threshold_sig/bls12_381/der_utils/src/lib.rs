use simple_asn1::{oid, ASN1Block};

pub const KEY_SIZE: usize = 96;

/// Converts public key bytes into its DER-encoded form.
///
/// See [the Interface Spec](https://sdk.dfinity.org/docs/interface-spec/index.html#_certificate)
/// and [RFC 5480](https://tools.ietf.org/html/rfc5480).
pub fn public_key_to_der(key: &[u8]) -> Result<Vec<u8>, String> {
    simple_asn1::to_der(&ASN1Block::Sequence(
        2,
        vec![
            ASN1Block::Sequence(0, vec![bls_algorithm_id(), bls_curve_id()]),
            ASN1Block::BitString(0, key.len() * 8, key.to_vec()),
        ],
    ))
    .map_err(|e| e.to_string())
}

/// Parses a `PublicKeyBytes` from its DER-encoded form.
///
/// See [the Interface Spec](https://sdk.dfinity.org/docs/interface-spec/index.html#_certificate)
/// and [RFC 5480](https://tools.ietf.org/html/rfc5480).
///
/// # Errors
/// * Returns a string describing the error if the given `bytes` are not valid
///   ASN.1, or include unexpected ASN.1 structures.
pub fn public_key_from_der(bytes: &[u8]) -> Result<[u8; KEY_SIZE], String> {
    use simple_asn1::{
        from_der,
        ASN1Block::{BitString, Sequence},
    };

    let unexpected_struct_err = |s: &ASN1Block| {
        format!(
            "unexpected ASN1 structure: {:?}, wanted: seq(seq(OID, OID), bitstring)",
            s
        )
    };

    let asn1_values =
        from_der(bytes).map_err(|e| format!("failed to deserialize DER blocks: {}", e))?;

    match asn1_values[..] {
        [Sequence(_, ref seq)] => match &seq[..] {
            [Sequence(_, ids), BitString(_, len, key)] => {
                if ids.len() != 2 {
                    return Err(unexpected_struct_err(&asn1_values[0]));
                }

                if *len != KEY_SIZE * 8 {
                    return Err(format!("unexpected key length: {} bits", len));
                }

                if ids[0] == bls_algorithm_id() && ids[1] == bls_curve_id() {
                    let mut key_bytes = [0u8; KEY_SIZE];
                    key_bytes.copy_from_slice(key.as_slice());
                    Ok(key_bytes)
                } else {
                    Err(format!(
                        "unsupported algorithm ({:?}) and/or curve ({:?}) OIDs",
                        ids[0], ids[1],
                    ))
                }
            }
            _ => Err(unexpected_struct_err(&asn1_values[0])),
        },
        _ => Err(format!(
            "expected exactly one ASN1 block, got sequence: {:?}",
            asn1_values
        )),
    }
}

fn bls_algorithm_id() -> ASN1Block {
    ASN1Block::ObjectIdentifier(0, oid!(1, 3, 6, 1, 4, 1, 44668, 5, 3, 1, 2, 1))
}

fn bls_curve_id() -> ASN1Block {
    ASN1Block::ObjectIdentifier(0, oid!(1, 3, 6, 1, 4, 1, 44668, 5, 3, 2, 1))
}
