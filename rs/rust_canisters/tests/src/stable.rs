use dfn_core::{bytes, over, stable};
use mersenne_twister::MT19937;
use rand::Rng;

#[export_name = "canister_query stable"]
fn main() {
    over(bytes, |_| {
        // This is a poor mans quick check
        let mut rng = MT19937::new_unseeded();

        roundtrip_stable(0, rng);
        for _ in 1..10 {
            // This modulus can be removed and things will still work, but it slows the test
            // down a lot
            let count = rng.next_u32() % 1_000_000;
            roundtrip_stable(count, rng)
        }
        Vec::new()
    })
}

fn roundtrip_stable(count: u32, mut rng: MT19937) {
    let collection: Vec<u8> = rng.gen_iter().take(count as usize).collect();
    stable::set(&collection);
    let result = stable::get();
    assert_eq!(collection, result);
}
