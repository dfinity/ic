use tecdsa::*;

#[test]
fn mega_smoke_test() -> Result<(), ThresholdSignatureError> {
    let curve = EccCurve::new(EccCurveType::K256);

    let mut rng = Seed::from_bytes([42; 32]).into_rng();

    let a_sk = MEGaPrivateKey::generate(curve, &mut rng)?;
    let b_sk = MEGaPrivateKey::generate(curve, &mut rng)?;

    let a_pk = a_sk.public_key()?;
    let b_pk = b_sk.public_key()?;

    let a_id = b"Alice";
    let b_id = b"Bob";

    let associated_data = b"assoc_data_test";

    let ptext_for_a = curve.random_scalar(&mut rng)?;
    let ptext_for_b = curve.random_scalar(&mut rng)?;

    let seed = Seed::from_rng(&mut rng);

    let ctext = mega_encryption_single(
        seed,
        &[ptext_for_a.clone(), ptext_for_b.clone()],
        &[(a_id.to_vec(), a_pk), (b_id.to_vec(), b_pk)],
        associated_data,
    )?;

    let ptext_a = mega_decryption_single(&ctext, 0, a_id, &a_sk, associated_data)?;

    assert_eq!(
        hex::encode(ptext_a.serialize()),
        hex::encode(ptext_for_a.serialize())
    );

    let ptext_b = mega_decryption_single(&ctext, 1, b_id, &b_sk, associated_data)?;

    assert_eq!(
        hex::encode(ptext_b.serialize()),
        hex::encode(ptext_for_b.serialize())
    );

    Ok(())
}

fn xmd_check(msg: &str, dst: &str, len: usize, want: &str) {
    let x = expand_message_xmd(msg.as_bytes(), dst.as_bytes(), len);
    assert_eq!(hex::encode(x), want);
}

#[test]
fn expand_message_xmd_test() {
    // Check we can handle lengths that are not a perfect multiple of 32.
    let x = expand_message_xmd(b"foo", b"bar", 123);
    assert_eq!(x.len(), 123);

    // Test cases from Appendix K.
    xmd_check(
        "",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        32,
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
    );
    xmd_check(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        32,
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
    );
    xmd_check("", "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", 32,
              "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3");
    xmd_check("abc", "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", 32,
              "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12");
}
