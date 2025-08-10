use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types::*;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::*;
use ic_crypto_sha2::Sha256;

/// ECDSA P-256 verification test vectors from the FIPS 186-4 ECDSA test
/// vectors (P-256, SHA-256, from `SigVer.rsp` in
/// `186-4ecdsatestvectors.zip`) see https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
/// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip
#[derive(Debug)]
pub struct SigVerTestVector {
    pub msg: Vec<u8>,
    pub q_x: Vec<u8>,
    pub q_y: Vec<u8>,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub is_valid: bool,
}

fn hex_to_byte_vec(h: &str) -> Vec<u8> {
    hex::decode(h).expect("Invalid hex")
}

pub fn p256_ecdsa_test_vectors() -> Vec<SigVerTestVector> {
    vec![
        SigVerTestVector {
            msg: hex_to_byte_vec("e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0"),
            q_x: hex_to_byte_vec("87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555"),
            q_y: hex_to_byte_vec("e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9"),
            r: hex_to_byte_vec("d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0"),
            s: hex_to_byte_vec("a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6"),
            is_valid: false
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d683877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae1873004565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e"),
            q_x: hex_to_byte_vec("5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2"),
            q_y: hex_to_byte_vec("ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85"),
            r: hex_to_byte_vec("dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693"),
            s: hex_to_byte_vec("d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c"),
            is_valid: false
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af714959896858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd86128cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de"),
            q_x: hex_to_byte_vec("2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb"),
            q_y: hex_to_byte_vec("5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64"),
            r: hex_to_byte_vec("9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8"),
            s: hex_to_byte_vec("9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc"),
            is_valid: false
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3"),
            q_x: hex_to_byte_vec("e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c"),
            q_y: hex_to_byte_vec("970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927"),
            r: hex_to_byte_vec("bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f"),
            s: hex_to_byte_vec("17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c"),
            is_valid: true
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730fb68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f22663bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08"),
            q_x: hex_to_byte_vec("e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864"),
            q_y: hex_to_byte_vec("7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a"),
            r: hex_to_byte_vec("1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407"),
            s: hex_to_byte_vec("cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a"),
            is_valid: true,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("666036d9b4a2426ed6585a4e0fd931a8761451d29ab04bd7dc6d0c5b9e38e6c2b263ff6cb837bd04399de3d757c6c7005f6d7a987063cf6d7e8cb38a4bf0d74a282572bd01d0f41e3fd066e3021575f0fa04f27b700d5b7ddddf50965993c3f9c7118ed78888da7cb221849b3260592b8e632d7c51e935a0ceae15207bedd548"),
            q_x: hex_to_byte_vec("a849bef575cac3c6920fbce675c3b787136209f855de19ffe2e8d29b31a5ad86"),
            q_y: hex_to_byte_vec("bf5fe4f7858f9b805bd8dcc05ad5e7fb889de2f822f3d8b41694e6c55c16b471"),
            r: hex_to_byte_vec("25acc3aa9d9e84c7abf08f73fa4195acc506491d6fc37cb9074528a7db87b9d6"),
            s: hex_to_byte_vec("9b21d5b5259ed3f2ef07dfec6cc90d3a37855d1ce122a85ba6a333f307d31537"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("7e80436bce57339ce8da1b5660149a20240b146d108deef3ec5da4ae256f8f894edcbbc57b34ce37089c0daa17f0c46cd82b5a1599314fd79d2fd2f446bd5a25b8e32fcf05b76d644573a6df4ad1dfea707b479d97237a346f1ec632ea5660efb57e8717a8628d7f82af50a4e84b11f21bdff6839196a880ae20b2a0918d58cd"),
            q_x: hex_to_byte_vec("3dfb6f40f2471b29b77fdccba72d37c21bba019efa40c1c8f91ec405d7dcc5df"),
            q_y: hex_to_byte_vec("f22f953f1e395a52ead7f3ae3fc47451b438117b1e04d613bc8555b7d6e6d1bb"),
            r: hex_to_byte_vec("548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5a"),
            s: hex_to_byte_vec("e93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce13e3a649700820f0061efabf849a85d474326c8a541d99830eea8131eaea584f22d88c353965dabcdc4bf6b55949fd529507dfb803ab6b480cd73ca0ba00ca19c438849e2cea262a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169"),
            q_x: hex_to_byte_vec("69b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214"),
            q_y: hex_to_byte_vec("d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f"),
            r: hex_to_byte_vec("288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790"),
            s: hex_to_byte_vec("247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("3fe60dd9ad6caccf5a6f583b3ae65953563446c4510b70da115ffaa0ba04c076115c7043ab8733403cd69c7d14c212c655c07b43a7c71b9a4cffe22c2684788ec6870dc2013f269172c822256f9e7cc674791bf2d8486c0f5684283e1649576efc982ede17c7b74b214754d70402fb4bb45ad086cf2cf76b3d63f7fce39ac970"),
            q_x: hex_to_byte_vec("bf02cbcf6d8cc26e91766d8af0b164fc5968535e84c158eb3bc4e2d79c3cc682"),
            q_y: hex_to_byte_vec("069ba6cb06b49d60812066afa16ecf7b51352f2c03bd93ec220822b1f3dfba03"),
            r: hex_to_byte_vec("f5acb06c59c2b4927fb852faa07faf4b1852bbb5d06840935e849c4d293d1bad"),
            s: hex_to_byte_vec("049dab79c89cc02f1484c437f523e080a75f134917fda752f2d5ca397addfe5d"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("983a71b9994d95e876d84d28946a041f8f0a3f544cfcc055496580f1dfd4e312a2ad418fe69dbc61db230cc0c0ed97e360abab7d6ff4b81ee970a7e97466acfd9644f828ffec538abc383d0e92326d1c88c55e1f46a668a039beaa1be631a89129938c00a81a3ae46d4aecbf9707f764dbaccea3ef7665e4c4307fa0b0a3075c"),
            q_x: hex_to_byte_vec("224a4d65b958f6d6afb2904863efd2a734b31798884801fcab5a590f4d6da9de"),
            q_y: hex_to_byte_vec("178d51fddada62806f097aa615d33b8f2404e6b1479f5fd4859d595734d6d2b9"),
            r: hex_to_byte_vec("87b93ee2fecfda54deb8dff8e426f3c72c8864991f8ec2b3205bb3b416de93d2"),
            s: hex_to_byte_vec("4044a24df85be0cc76f21a4430b75b8e77b932a87f51e4eccbc45c263ebf8f66"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("4a8c071ac4fd0d52faa407b0fe5dab759f7394a5832127f2a3498f34aac287339e043b4ffa79528faf199dc917f7b066ad65505dab0e11e6948515052ce20cfdb892ffb8aa9bf3f1aa5be30a5bbe85823bddf70b39fd7ebd4a93a2f75472c1d4f606247a9821f1a8c45a6cb80545de2e0c6c0174e2392088c754e9c8443eb5af"),
            q_x: hex_to_byte_vec("43691c7795a57ead8c5c68536fe934538d46f12889680a9cb6d055a066228369"),
            q_y: hex_to_byte_vec("f8790110b3c3b281aa1eae037d4f1234aff587d903d93ba3af225c27ddc9ccac"),
            r: hex_to_byte_vec("8acd62e8c262fa50dd9840480969f4ef70f218ebf8ef9584f199031132c6b1ce"),
            s: hex_to_byte_vec("cfca7ed3d4347fb2a29e526b43c348ae1ce6c60d44f3191b6d8ea3a2d9c92154"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("0a3a12c3084c865daf1d302c78215d39bfe0b8bf28272b3c0b74beb4b7409db0718239de700785581514321c6440a4bbaea4c76fa47401e151e68cb6c29017f0bce4631290af5ea5e2bf3ed742ae110b04ade83a5dbd7358f29a85938e23d87ac8233072b79c94670ff0959f9c7f4517862ff829452096c78f5f2e9a7e4e9216"),
            q_x: hex_to_byte_vec("9157dbfcf8cf385f5bb1568ad5c6e2a8652ba6dfc63bc1753edf5268cb7eb596"),
            q_y: hex_to_byte_vec("972570f4313d47fc96f7c02d5594d77d46f91e949808825b3d31f029e8296405"),
            r: hex_to_byte_vec("dfaea6f297fa320b707866125c2a7d5d515b51a503bee817de9faa343cc48eeb"),
            s: hex_to_byte_vec("8f780ad713f9c3e5a4f7fa4c519833dfefc6a7432389b1e4af463961f09764f2"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("785d07a3c54f63dca11f5d1a5f496ee2c2f9288e55007e666c78b007d95cc28581dce51f490b30fa73dc9e2d45d075d7e3a95fb8a9e1465ad191904124160b7c60fa720ef4ef1c5d2998f40570ae2a870ef3e894c2bc617d8a1dc85c3c55774928c38789b4e661349d3f84d2441a3b856a76949b9f1f80bc161648a1cad5588e"),
            q_x: hex_to_byte_vec("072b10c081a4c1713a294f248aef850e297991aca47fa96a7470abe3b8acfdda"),
            q_y: hex_to_byte_vec("9581145cca04a0fb94cedce752c8f0370861916d2a94e7c647c5373ce6a4c8f5"),
            r: hex_to_byte_vec("09f5483eccec80f9d104815a1be9cc1a8e5b12b6eb482a65c6907b7480cf4f19"),
            s: hex_to_byte_vec("a4f90e560c5e4eb8696cb276e5165b6a9d486345dedfb094a76e8442d026378d"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("76f987ec5448dd72219bd30bf6b66b0775c80b394851a43ff1f537f140a6e7229ef8cd72ad58b1d2d20298539d6347dd5598812bc65323aceaf05228f738b5ad3e8d9fe4100fd767c2f098c77cb99c2992843ba3eed91d32444f3b6db6cd212dd4e5609548f4bb62812a920f6e2bf1581be1ebeebdd06ec4e971862cc42055ca"),
            q_x: hex_to_byte_vec("09308ea5bfad6e5adf408634b3d5ce9240d35442f7fe116452aaec0d25be8c24"),
            q_y: hex_to_byte_vec("f40c93e023ef494b1c3079b2d10ef67f3170740495ce2cc57f8ee4b0618b8ee5"),
            r: hex_to_byte_vec("5cc8aa7c35743ec0c23dde88dabd5e4fcd0192d2116f6926fef788cddb754e73"),
            s: hex_to_byte_vec("9c9c045ebaa1b828c32f82ace0d18daebf5e156eb7cbfdc1eff4399a8a900ae7"),
            is_valid: false,
        },
        SigVerTestVector {
            msg: hex_to_byte_vec("60cd64b2cd2be6c33859b94875120361a24085f3765cb8b2bf11e026fa9d8855dbe435acf7882e84f3c7857f96e2baab4d9afe4588e4a82e17a78827bfdb5ddbd1c211fbc2e6d884cddd7cb9d90d5bf4a7311b83f352508033812c776a0e00c003c7e0d628e50736c7512df0acfa9f2320bd102229f46495ae6d0857cc452a84"),
            q_x: hex_to_byte_vec("2d98ea01f754d34bbc3003df5050200abf445ec728556d7ed7d5c54c55552b6d"),
            q_y: hex_to_byte_vec("9b52672742d637a32add056dfd6d8792f2a33c2e69dafabea09b960bc61e230a"),
            r: hex_to_byte_vec("06108e525f845d0155bf60193222b3219c98e3d49424c2fb2a0987f825c17959"),
            s: hex_to_byte_vec("62b5cdd591e5b507e560167ba8f6f7cda74673eb315680cb89ccbc4eec477dce"),
            is_valid: true,
        },
    ]
}

fn pk_bytes_from_x_y(x: &[u8], y: &[u8]) -> PublicKeyBytes {
    let der = der_encoding_from_xy_coordinates(x, y).unwrap();
    public_key_from_der(&der).unwrap()
}

fn sig_bytes_from_r_s(r: &[u8], s: &[u8]) -> SignatureBytes {
    SignatureBytes::try_from([r, s].concat()).unwrap()
}

#[test]
fn should_correctly_verify_nist_fips_test_vectors() {
    for v in p256_ecdsa_test_vectors() {
        let msg_hash = Sha256::hash(&v.msg);
        let pk = pk_bytes_from_x_y(&v.q_x, &v.q_y);
        let sig = sig_bytes_from_r_s(&v.r, &v.s);

        let verify_result = verify(&sig, &msg_hash, &pk);
        assert_eq!(
            verify_result.is_ok(),
            v.is_valid,
            "Unexpected verification result for test vector {:?}",
            v
        );
        if verify_result.is_err() {
            assert!(verify_result.unwrap_err().is_signature_verification_error());
        }
    }
}
