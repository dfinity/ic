use ic_crypto_internal_seed::xmd;
use ic_crypto_sha2::{Sha256, Sha512};

fn xmd_check<const N: usize>(msg: &str, dst: &str, want: &str) {
    assert_eq!(want.len() / 2, N);
    let x = xmd::<N, Sha256>(msg.as_bytes(), dst.as_bytes());
    assert_eq!(hex::encode(x), want);
}

#[test]
fn test_xmd_sha256_output_lengths() {
    // Check we can handle lengths that are not a perfect multiple of 32.

    let inp = b"input";
    let dst = b"dst";

    assert_eq!(xmd::<3, Sha256>(inp, dst).len(), 3);
    assert_eq!(xmd::<63, Sha256>(inp, dst).len(), 63);
    assert_eq!(xmd::<257, Sha256>(inp, dst).len(), 257);
    assert_eq!(xmd::<8159, Sha256>(inp, dst).len(), 8159);
    assert_eq!(xmd::<8160, Sha256>(inp, dst).len(), 8160);

    // Will fail to compile:
    //assert_eq!(xmd::<8161, Sha256>(inp, dst).len(), 8161);
}

#[test]
fn test_xmd_sha512_output_lengths() {
    // Check we can handle lengths that are not a perfect multiple of 32.

    let inp = b"input";
    let dst = b"dst";

    assert_eq!(xmd::<3, Sha512>(inp, dst).len(), 3);
    assert_eq!(xmd::<63, Sha512>(inp, dst).len(), 63);
    assert_eq!(xmd::<257, Sha512>(inp, dst).len(), 257);
    assert_eq!(xmd::<8159, Sha512>(inp, dst).len(), 8159);
    assert_eq!(xmd::<8160, Sha512>(inp, dst).len(), 8160);
    assert_eq!(xmd::<16320, Sha512>(inp, dst).len(), 16320);

    // Will fail to compile:
    //assert_eq!(xmd::<16321, Sha512>(inp, dst).len(), 16321);
}

#[test]
fn check_xmd_test_vectors_with_unusual_lengths() {
    // Some XMD test vectors verifying we produce the expected output
    // even for output lengths not a multiple of the hash

    let dst = "XMD-unusual-input-len";

    xmd_check::<3>("XMD 3 bytes", dst, "8044a2");
    xmd_check::<31>(
        "XMD 31 bytes",
        dst,
        "519c6806079cddef23179d8b4717b4be2b1b8c09eb177d071ec084dc340610",
    );

    xmd_check::<67>(
        "XMD 67 bytes",
        dst,
        "c54e6cbd99f2be68ff16f9a5b4536ab8f90ef742b25c58a651fc87bd0f1fc684d679b70eda16b3e97353678f1a8c2a1cceabb4ca5ff72d79b2f580654cf6c453b7acba",
    );

    xmd_check::<511>(
        "XMD 511 bytes",
        dst,
        "d34de5205ebc6428698ef3eb84c612138c94bed1bb5eb9892e22dcc01ad5ae0e29072b7ee2a8e328a72dc7528371d19974a072743cb51a4ab43bd51033b3012c9311d20cf43a627d9247e5119b9b8ae1e07be9ac982e7b3ede06b44120154b65559a5052b8d8044023aa38e575ad87f29056dc9433f726b06650b2e3e8effa3a160c8345ec9186acd6c22814e312008f7ecc1c1a2c3f81983bba3ee6972f5d85c949cb66c5ae5d00ab508bb3e78c21020e4a2e4abb4eabcbe61903c3e997654b2126c6fcf8c8121302a9328580a5251a5ee92f7166545fab6da2065e7498cb8399256e3f84da9b7d382d95de7df8321074febbf29945860586824d1942073b8603802e988561d05dcd3a2845798dab0d2244566d7ac214b1f0f2eb243155294a5d0852322302837f18bfe698f93960ed0237fb3646c510613e4f250238cee6f7eaf6e478dbf6558e579656b3acebad40daaf5bf3934c05d4219681d269915bf449fcd852ac8672e971da154dc03ae11405feca5eae2b8dea22fce51cc7843f95362caadaceef7d6099c6623a6666ed04ee342949a920b0144b8655addb9e7f12d4f821b601099c02dace32c35a69657416c15c946e13a6e240b7acfad6cac3c0e04aacc77bf1de3860a3fbfa6ae1197316d3d23a4b9d0a7bc09dfd415bb220e7607d77bd944f39dfbc65931dc903b2bd69f057d8d495203f12be7a3bdea1e0",
    );
}

#[test]
fn check_xmd_rfc9380_test_vectors() {
    // Test cases from RFC 9380 Appendix K.1

    xmd_check::<32>(
        "",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235",
    );
    xmd_check::<32>(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615",
    );

    xmd_check::<128>(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128",
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40",
    );

    xmd_check::<32>(
        "",
        "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3",
    );
    xmd_check::<32>(
        "abc",
        "QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12",
    );
}
