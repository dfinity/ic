use super::*;
use assert_matches::assert_matches;
use ic_crypto_standalone_sig_verifier::ed25519_public_key_to_der;
use ic_crypto_temp_crypto::temp_crypto_component_with_fake_registry;
use ic_crypto_test_utils_root_of_trust::MockRootOfTrustProvider;
use ic_test_utilities_types::ids::{canister_test_id, message_test_id, node_test_id};
use ic_types::{
    messages::{Delegation, SignedDelegation, UserSignature},
    time::UNIX_EPOCH,
};
use std::time::Duration;

#[test]
fn plain_authentication_correct_signature_passes() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    let pubkey_base64 = "SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=";

    // Signed the message ID with the corresponding secret key:
    // LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
    let signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

    let user_signature = UserSignature {
        signature: base64::decode(signature).unwrap(),
        signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap()).unwrap(),
        sender_delegation: None,
    };

    assert!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        )
        .is_ok()
    );

    // Same signature as above with empty delegations specified. Should also pass.
    let user_signature = UserSignature {
        signature: base64::decode(signature).unwrap(),
        signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap()).unwrap(),
        sender_delegation: Some(Vec::new()),
    };

    assert!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        )
        .is_ok()
    );
}

#[test]
fn plain_authentication_incorrect_signature_passes() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    let pubkey_base64 = "SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=";

    // Incorrect signature. Correct signature should be:
    // "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";
    let signature =
        "nWfuICAf29zspOaoGUcn/xIFUtnUiZRsbhxgZywz6OzRTHKoY32sU78uE0z8UFcbInkzwDtw+4PP2JQrnwHtCw==";

    let user_signature = UserSignature {
        signature: base64::decode(signature).unwrap(),
        signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap()).unwrap(),
        sender_delegation: None,
    };

    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Err(InvalidSignature(InvalidBasicSignature(_)))
    );
}

#[test]
fn plain_authentication_with_one_delegation() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    // In this scenario we have two keypairs:
    //
    // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
    // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
    //
    // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
    // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=
    //
    // Keypair 1 delegates to keypair 2.

    let pk1 = ed25519_public_key_to_der(
        base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap(),
    )
    .unwrap();
    let pk2 = ed25519_public_key_to_der(
        base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap(),
    )
    .unwrap();
    let delegation = Delegation::new(pk2, UNIX_EPOCH);

    // Signature of sk1 for the delegation above.
    let delegation_signature = base64::decode(
        "QhNcIhRQalYnRK4WJ3KWIrfqMIC1RAiehoGU/rqDbfzvz4trSBH0THxJY+P7J7dJ63HPXiBa1vYnSfVjbpoCCg==",
    )
    .unwrap();

    // Signature of sk2 of the message id.
    let message_id_signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

    let signed_delegation = SignedDelegation::new(delegation, delegation_signature);

    let user_signature = UserSignature {
        signature: base64::decode(message_id_signature).unwrap(),
        signer_pubkey: pk1,
        sender_delegation: Some(vec![signed_delegation]),
    };

    assert_eq!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Ok(CanisterIdSet::all())
    );

    // Try verifying the signature in the future. It should fail because the
    // delegation would've expired.
    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH + Duration::from_secs(1),
            &MockRootOfTrustProvider::new()
        ),
        Err(RequestValidationError::InvalidDelegationExpiry(_))
    );
}

#[test]
fn plain_authentication_with_one_scoped_delegation() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    // In this scenario we have two keypairs:
    //
    // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
    // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
    //
    // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
    // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=
    //
    // Keypair 1 delegates to keypair 2.

    let pk1 = ed25519_public_key_to_der(
        base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap(),
    )
    .unwrap();
    let pk2 = ed25519_public_key_to_der(
        base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap(),
    )
    .unwrap();
    let delegation = Delegation::new_with_targets(pk2, UNIX_EPOCH, vec![canister_test_id(1)]);

    // Signature of sk1 for the delegation above.
    let delegation_signature = base64::decode(
        "yULx4bstJpKWTcymC3T9kQUVC0fD04pxuHtMSOH2c9NkM5AqplrRmJgeb92p583nuexafMS6SXWfmWszSo14CA==",
    )
    .unwrap();

    // Signature of sk2 of the message id.
    let message_id_signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

    let signed_delegation = SignedDelegation::new(delegation, delegation_signature);

    let user_signature = UserSignature {
        signature: base64::decode(message_id_signature).unwrap(),
        signer_pubkey: pk1,
        sender_delegation: Some(vec![signed_delegation]),
    };

    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Ok(ids) if ids == CanisterIdSet::try_from_iter(vec![canister_test_id(1)]).unwrap()
    );
}

#[test]
fn plain_authentication_with_multiple_delegations() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    // In this scenario we have four keypairs:
    //
    // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
    // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
    //
    // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
    // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=
    //
    // SK3: 0bQjDi/upCIujouLLPQOn2ePrvoVkMgG2SA8R3NQH4U=
    // PK3: 02aktrssfFxcxrf18Fx6nENqaxgVLC+e+x3Y3tunQPs=
    //
    // SK4: tgkM2ZIh4NE23/E6UgDhoUaxT+3FR8PiMxdSsC4yWR4=
    // PK4: b9k9ldofRsdXBrcfHoInQGhhtzbGCVBb9Kpcw2ij2Ck=
    //
    // Each keypair delegates to the one below it.
    let pk1 = ed25519_public_key_to_der(
        base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap(),
    )
    .unwrap();
    let pk2 = ed25519_public_key_to_der(
        base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap(),
    )
    .unwrap();
    let pk3 = ed25519_public_key_to_der(
        base64::decode("02aktrssfFxcxrf18Fx6nENqaxgVLC+e+x3Y3tunQPs=").unwrap(),
    )
    .unwrap();
    let pk4 = ed25519_public_key_to_der(
        base64::decode("b9k9ldofRsdXBrcfHoInQGhhtzbGCVBb9Kpcw2ij2Ck=").unwrap(),
    )
    .unwrap();

    // KP1 delegating to KP2.
    let delegation = Delegation::new_with_targets(
        pk2,
        UNIX_EPOCH + Duration::new(4, 0),
        vec![canister_test_id(1), canister_test_id(2)],
    );

    // Signature of SK1 for `delegation` above.
    let delegation_signature = base64::decode(
        "R1LC9wYXfuWn1BjTJHWF8ANyxyTVqEJzhybvOMxgn9gERpqdQoh+BhsLue3byTp7X1uEtc44QYKLIH1adajHCg==",
    )
    .unwrap();

    // KP2 delegating to KP3.
    let delegation_2 = Delegation::new(pk3, UNIX_EPOCH + Duration::new(2, 0));
    // Signature of SK2 for delegation_2
    let delegation_2_signature = base64::decode(
        "rP1xtpEK9ypS+I4JU5rywZNQjYMa0JsVXR+a2DkmShbXQ08s0PmUh6KaGmP56YJtI1hIz3ZELlYKvw+M/jAcCA==",
    )
    .unwrap();

    // KP3 delegating to KP4.
    let delegation_3 = Delegation::new_with_targets(
        pk4,
        UNIX_EPOCH + Duration::new(3, 0),
        vec![canister_test_id(1)],
    );
    // Signature of SK3 for delegation_3
    let delegation_3_signature = base64::decode(
        "a/hTCL8yOijzFIcHdcE0uvt2dj3WQdTiMLPX+xI8mWC0wRt+CYlMoFTc6JlfBopEJDrDwdEBz1n6/S8R2A/CCQ==",
    )
    .unwrap();

    // Message ID signature by SK4
    let message_id_signature =
        "UwmzxUzil6smPQ9hxab03AdSDUUbM76nx6yYPsMKzP59XlbjPxHJqyk7/n93I8a3oWkkJsxZNcFxMdnVx1L4CA==";

    let signed_delegation = SignedDelegation::new(delegation, delegation_signature);
    let signed_delegation_2 = SignedDelegation::new(delegation_2, delegation_2_signature);
    let signed_delegation_3 = SignedDelegation::new(delegation_3, delegation_3_signature);

    let user_signature = UserSignature {
        signature: base64::decode(message_id_signature).unwrap(),
        signer_pubkey: pk1,
        sender_delegation: Some(vec![
            signed_delegation,
            signed_delegation_2,
            signed_delegation_3,
        ]),
    };

    // Should pass at time 0.
    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Ok(ids) if ids == CanisterIdSet::try_from_iter(vec![canister_test_id(1)]).unwrap()
    );
    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH + Duration::from_secs(2),
            &MockRootOfTrustProvider::new()
        ),
        Ok(_)
    );

    // Should expire after > 2 seconds
    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH + Duration::from_secs(3),
            &MockRootOfTrustProvider::new()
        ),
        Err(RequestValidationError::InvalidDelegationExpiry(_))
    );
}

#[test]
fn plain_authentication_with_malformed_delegation() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    let pubkey_base64 = "SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=";
    let signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

    let user_signature = UserSignature {
        signature: base64::decode(signature).unwrap(),
        signer_pubkey: ed25519_public_key_to_der(base64::decode(pubkey_base64).unwrap()).unwrap(),
        // Add a malformed delegation.
        sender_delegation: Some(vec![SignedDelegation::new(
            Delegation::new(
                vec![1, 2, 3], // malformed key
                UNIX_EPOCH,
            ),
            vec![], // malformed signature
        )]),
    };

    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Err(InvalidDelegation(InvalidBasicSignature(_)))
    );
}

#[test]
fn plain_authentication_with_invalid_delegation() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(1);

    // In this scenario we have two keypairs:
    //
    // SK1: 1nKa/Hbm9veagk6lP331WpynpNokOZnQQ/zKxD4Gg5o=
    // PK1: rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=
    //
    // SK2: LDFkTfdAOC4kGVyOUaf0rZs2W6+hWo2YqSAU59m/agQ=
    // PK2: SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=

    let pk1 = base64::decode("rrkzV33aO4TcH2DMz3ducPaZyIiG/8YbnNjHW+0hRvg=").unwrap();
    let pk2 = base64::decode("SyP7C1lwpbsWjwT7ow5CnbiL5JzbyjzQrdDVQQb18yE=").unwrap();

    // KP1 delegating to KP2.
    let delegation = Delegation::new(pk2, UNIX_EPOCH + Duration::new(4, 0));
    // Faulty delegation signature. The correct one should be:
    // f5uiR36pRe4VL1k2VTwSvZGmViFTUZxZoh/IeYA183DgK1lhDLRpln57+2Ik2Mkqs5H/
    // G8jwx1+FQ/RZFaX1Dw==
    let delegation_signature = base64::decode(
        "HnM9ZfEg1E/+KPFBf6JGMS/TwtbjWVIm9PwG8vxbb74p0NBT98kDwtaT4TU0rSxm7WcWLNf7GnPu4b+0VroNBw==",
    )
    .unwrap();

    // Message ID signature by SK2
    let message_id_signature =
        "MwqQH8l2vCNhRTzYmBA95p7tQWg4S0G4v0zyIiX21H6c6E1oL8xWDuOe67Yh98yt6z8n84D875I2qmvLliWODA==";

    let signed_delegation = SignedDelegation::new(delegation, delegation_signature);

    let user_signature = UserSignature {
        signature: base64::decode(message_id_signature).unwrap(),
        signer_pubkey: pk1,
        sender_delegation: Some(vec![signed_delegation]),
    };

    assert_matches!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Err(InvalidDelegation(InvalidPublicKey(_)))
    );
}

#[test]
fn validate_signature_webauthn() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(13);

    let pubkey_hex = "305e300c060a2b0601040183b8430101034e00a5010203262001215820b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c183942258202a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e";

    // Webauthn signature for the message ID above.
    let signature_hex = "d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58847b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022436d6c6a4c584a6c6358566c6333514e414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100e4029fcf1cec44e0e2a33b2b2b981411376d89f90bec9ee7d4e20ca33ce8f088022070e95aa9dd3f0cf0d6f97f306d52211288482d565012202b349b2a2d80852635";

    let user_signature = UserSignature {
        signature: hex::decode(signature_hex).unwrap(),
        signer_pubkey: hex::decode(pubkey_hex).unwrap(),
        sender_delegation: None,
    };

    assert_eq!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Ok(CanisterIdSet::all())
    );
}

#[test]
fn validate_signature_webauthn_with_delegations() {
    let sig_verifier = temp_crypto_component_with_fake_registry(node_test_id(0));
    let message_id = message_test_id(13);

    // PK with the following corresponding secret key:
    // 2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204145532d3235362d4342432c41433946384133414541424132363345423345313041313939344441333131340a0a724f635a55306465685335623532437055795334427455393832796d4c36772b4e485576766137727a72373266613432526f68767459766b74432f70496242390a646861466a72666a6c493668754e53437a62464132484e4f4d447772516e4d74324d4550536e553439434a68514c4e2b4c353353526646324e78386a473352690a76416f2f63706e38763067784b787a394b336b2f4b3258514643416a6248696a2f67374a593351324141513d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a
    let pk1 = hex::decode("305e300c060a2b0601040183b8430101034e00a5010203262001215820aaf7276b278cf9c9a084e64f09db7255400705bee18145dfdff7c388e9a548e8225820eab7d1dc480ec1df9be1e4c73b28659d11a6c15b1786fd1c115fade01373fe53").unwrap();

    // PK with the following corresponding secret key:
    // 2d2d2d2d2d424547494e2045432050524956415445204b45592d2d2d2d2d0a50726f632d547970653a20342c454e435259505445440a44454b2d496e666f3a204145532d3235362d4342432c46433546313634394446324639333942414538343836333739383043394137440a0a475130706359302f744e6b6f566673534c632b635261324578426332763436724643376c596f4f63466d71656d4c73756952494f346f444b63715a68423962700a6b6248665374586e7168357557464b62674266776c617650377535625477396e61684e7553316a6c7653312b66492b79416255316f674e76423078514f4c41640a343864596333656f4877416b676848386e73426e796d3044574a386b59526b424b6136724e6f4e367154633d0a2d2d2d2d2d454e442045432050524956415445204b45592d2d2d2d2d0a
    let pk2 = hex::decode("305e300c060a2b0601040183b8430101034e00a5010203262001215820b487d183dc4806058eb31a29bedefd7bcca987b77a381a3684871d8449c183942258202a122cc711a80453678c3032de4b6fff2c86342e82d1e7adb617c4165c43ce5e").unwrap();
    let delegation = Delegation::new(pk2, UNIX_EPOCH);

    let delegation_sig = hex::decode("d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58997b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022476d6c6a4c584a6c6358566c63335174595856306143316b5a57786c5a32463061573975495f415149773979624b754a36593634394e6f6b715335575f6f37324777416b3057664d7535786f336c73222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100edf3fc39b51734da0aac5284b381308816f77bbccae7fbc8fd563c956c33121a0220280af63c8d01588e3242ac12f9c6f234f89c940df166ba53b07e5f7b1f67e360").unwrap();

    // Webauthn signature by pk2 for the message ID.
    let message_sig = hex::decode("d9d9f7a37261757468656e74696361746f725f646174615825bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5010000000170636c69656e745f646174615f6a736f6e58847b2274797065223a2022776562617574686e2e676574222c20226368616c6c656e6765223a2022436d6c6a4c584a6c6358566c6333514e414141414141414141414141414141414141414141414141414141414141414141414141414141414141222c20226f726967696e223a202268747470733a2f2f6578616d706c652e6f7267227d697369676e617475726558473045022100e4029fcf1cec44e0e2a33b2b2b981411376d89f90bec9ee7d4e20ca33ce8f088022070e95aa9dd3f0cf0d6f97f306d52211288482d565012202b349b2a2d80852635").unwrap();

    let user_signature = UserSignature {
        signature: message_sig,
        signer_pubkey: pk1,
        sender_delegation: Some(vec![SignedDelegation::new(delegation, delegation_sig)]),
    };

    assert_eq!(
        validate_signature(
            &sig_verifier,
            &message_id,
            &user_signature,
            UNIX_EPOCH,
            &MockRootOfTrustProvider::new()
        ),
        Ok(CanisterIdSet::all())
    );
}

mod validate_ingress_expiry {
    use super::*;
    use ic_types::messages::{HttpCallContent, SignedIngressContent};

    #[test]
    fn should_error_when_ingress_expiry_too_small() {
        let min_allowed_expiry = 1000;
        let request = http_request_with_ingress_expiry(min_allowed_expiry - 1);
        let current_time = Time::from_nanos_since_unix_epoch(min_allowed_expiry);

        let result = validate_ingress_expiry(&request, current_time);

        assert_matches!(result, Err(InvalidRequestExpiry(msg)) if msg.contains("Specified ingress_expiry not within expected range"))
    }

    #[test]
    fn should_error_when_ingress_expiry_too_large() {
        let min_allowed_expiry = 1000;
        let current_time = Time::from_nanos_since_unix_epoch(min_allowed_expiry);
        let max_allowed_expiry = (current_time + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_VALIDATOR)
            .as_nanos_since_unix_epoch();
        let request = http_request_with_ingress_expiry(max_allowed_expiry + 1);

        let result = validate_ingress_expiry(&request, current_time);

        assert_matches!(result, Err(InvalidRequestExpiry(msg)) if msg.contains("Specified ingress_expiry not within expected range"))
    }

    #[test]
    fn should_error_when_max_ingress_expiry_overflows() {
        let request = http_request_with_ingress_expiry(0);
        let current_time = Time::from_nanos_since_unix_epoch(u64::MAX);

        let result = validate_ingress_expiry(&request, current_time);

        assert_matches!(result, Err(InvalidRequestExpiry(msg)) if msg.ends_with("overflows"))
    }

    #[test]
    fn should_accept_valid_ingress_expiry() {
        let min_allowed_expiry = 1000;
        let current_time = Time::from_nanos_since_unix_epoch(min_allowed_expiry);
        let max_allowed_expiry = (current_time + MAX_INGRESS_TTL + PERMITTED_DRIFT_AT_VALIDATOR)
            .as_nanos_since_unix_epoch();
        let request = http_request_with_ingress_expiry(max_allowed_expiry);

        let result = validate_ingress_expiry(&request, current_time);

        assert_matches!(result, Ok(()))
    }

    fn http_request_with_ingress_expiry(ingress_expiry: u64) -> HttpRequest<SignedIngressContent> {
        use ic_types::messages::Blob;
        use ic_types::messages::HttpCanisterUpdate;
        use ic_types::messages::HttpRequestEnvelope;
        HttpRequest::try_from(HttpRequestEnvelope::<HttpCallContent> {
            content: HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(vec![42; 8]),
                    method_name: "some_method".to_string(),
                    arg: Default::default(),
                    sender: Blob(vec![0x04]),
                    nonce: None,
                    ingress_expiry,
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        })
        .expect("invalid http envelope")
    }
}

mod canister_id_set {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use rand::CryptoRng;
    use rand::Rng;

    #[test]
    fn should_contain_expected_elements() {
        let number_of_ids = MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION;
        let mut ids = Vec::with_capacity(number_of_ids);
        for i in 0..number_of_ids {
            ids.push(CanisterId::from_u64(i as u64));
        }

        let set = CanisterIdSet::try_from_iter(ids.clone()).expect("too many elements");

        for id in ids {
            assert!(set.contains(&id))
        }
    }

    #[test]
    fn should_not_store_duplicated_canister_ids() {
        let id0 = CanisterId::from_u64(0);
        let id1 = CanisterId::from_u64(1);
        let duplicated_ids = vec![id0, id1, id0];
        let set = CanisterIdSet::try_from_iter(duplicated_ids).expect("too many elements");

        assert!(set.contains(&id0));
        assert!(set.contains(&id1));
        assert_matches!(set.ids, internal::CanisterIdSet::Some(subset) if subset.len() == 2);
    }

    #[test]
    fn should_efficiently_intersect_large_canister_id_sets() {
        let rng = &mut reproducible_rng();
        let number_of_ids = MAXIMUM_NUMBER_OF_TARGETS_PER_DELEGATION;
        let (first_canister_ids, second_canister_ids) = {
            let mut first_set = BTreeSet::new();
            let mut second_set = BTreeSet::new();
            for _ in 1..=number_of_ids {
                assert!(first_set.insert(random_canister_id(rng)));
                assert!(second_set.insert(random_canister_id(rng)));
            }
            (
                CanisterIdSet::try_from_iter(first_set).expect("too many elements"),
                CanisterIdSet::try_from_iter(second_set).expect("too many elements"),
            )
        };

        let intersection = first_canister_ids.intersect(second_canister_ids);
        // Probability of collision is negligible (around 10^(-60)).
        assert!(
            intersection.is_empty(),
            "expected {intersection:?} to be empty but was not"
        )
    }

    fn random_canister_id<R: Rng + CryptoRng>(rng: &mut R) -> CanisterId {
        CanisterId::from_u64(rng.next_u64())
    }
}
