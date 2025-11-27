use ic_crypto_internal_seed::xmd;
use ic_crypto_sha2::Sha256;

fn xmd_check(msg: &str, dst: &str, want: &str) {
    let x = xmd::<Sha256>(msg.as_bytes(), dst.as_bytes(), want.len() / 2).expect("XMD failed");
    assert_eq!(hex::encode(x), want);
}

#[test]
fn test_xmd_output_lengths() {
    // Check we can handle lengths that are not a perfect multiple of 32.

    for i in 0..=8160 {
        let x = xmd::<Sha256>(b"foo", b"bar", i).expect("XMD failed");
        assert_eq!(x.len(), i);
    }

    for i in 8161..10000 {
        xmd::<Sha256>(b"foo", b"bar", i).expect_err("XMD unexpectedly succeeded with long output");
    }
}

#[test]
fn check_xmd_rfc9380_test_vectors() {
    // Test cases from Appendix K.1
    xmd_check(
        "",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
    );
    xmd_check(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
    );

    xmd_check(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
    );

    xmd_check(
        "",
        "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3",
    );
    xmd_check(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12",
    );
}
