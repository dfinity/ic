use dfn_core::{bytes, over, stable};
use rand::rngs::SmallRng;
use rand::{
    RngExt, SeedableRng,
    distr::{Distribution, StandardUniform, Uniform},
};

#[unsafe(export_name = "canister_query stable")]
fn main() {
    over(bytes, |_| {
        // This is a poor mans quick check
        let mut rng = SmallRng::seed_from_u64(0);
        let count_dist = Uniform::try_from(0..10000).unwrap();

        roundtrip_stable(0, &mut rng);
        for _ in 1..10 {
            let count = count_dist.sample(&mut rng);
            roundtrip_stable(count, &mut rng)
        }
        Vec::new()
    })
}

fn roundtrip_stable(count: u32, rng: &mut SmallRng) {
    let collection: Vec<u8> = rng
        .sample_iter(StandardUniform)
        .take(count as usize)
        .collect();
    stable::set(&collection);
    let result = stable::get();
    assert_eq!(collection, result);
}
