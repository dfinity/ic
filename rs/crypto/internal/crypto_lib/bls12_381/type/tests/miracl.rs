use ic_crypto_internal_bls12_381_type::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn seeded_rng() -> ChaCha20Rng {
    let mut thread_rng = rand::thread_rng();
    let seed = thread_rng.gen::<u64>();
    println!("RNG seed {}", seed);
    ChaCha20Rng::seed_from_u64(seed)
}

fn assert_scalar_roundtrips(scalar: Scalar) {
    let miracl = scalar.to_miracl();
    let from_miracl = Scalar::from_miracl(&miracl);
    assert_eq!(scalar, from_miracl);
}

#[test]
fn test_miracl_scalar_conversions() {
    let mut rng = seeded_rng();

    for i in 0..300 {
        let scalar = Scalar::from_u32(i);
        assert_scalar_roundtrips(scalar);
    }

    for _ in 0..300 {
        let scalar = Scalar::random(&mut rng);
        assert_scalar_roundtrips(scalar);
    }
}

fn assert_g1_roundtrips(g1: G1Affine) {
    let miracl = g1.to_miracl();
    let from_miracl = G1Affine::from_miracl(&miracl);
    assert_eq!(g1, from_miracl);
}

#[test]
fn test_miracl_g1_conversions() {
    let mut rng = seeded_rng();

    assert_g1_roundtrips(G1Affine::identity());
    assert_g1_roundtrips(G1Affine::generator());

    for i in 0..300 {
        let g1 = G1Affine::generator() * Scalar::from_u32(i);
        assert_g1_roundtrips(g1.into());
    }

    for _ in 0..300 {
        let g1 = G1Affine::hash(b"dst", &rng.gen::<[u8; 32]>());
        assert_g1_roundtrips(g1);
    }
}

fn assert_g2_roundtrips(g2: G2Affine) {
    let miracl = g2.to_miracl();
    let from_miracl = G2Affine::from_miracl(&miracl);
    assert_eq!(g2, from_miracl);
}

#[test]
fn test_miracl_g2_conversions() {
    let mut rng = seeded_rng();

    assert_g2_roundtrips(G2Affine::identity());
    assert_g2_roundtrips(G2Affine::generator());

    for i in 0..300 {
        let g2 = G2Affine::generator() * Scalar::from_u32(i);
        assert_g2_roundtrips(g2.into());
    }

    for _ in 0..300 {
        let g2 = G2Affine::hash(b"dst", &rng.gen::<[u8; 32]>());
        assert_g2_roundtrips(g2);
    }
}
