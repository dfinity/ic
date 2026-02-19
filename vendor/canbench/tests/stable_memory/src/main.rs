use canbench_rs::bench;

#[bench]
fn read_from_stable_memory() {
    let mut buf = [0; 10];
    ic_cdk::api::stable_read(0, &mut buf);

    // There should be one page in stable memory.
    assert_eq!(ic_cdk::api::stable_size(), 1);

    // The `stable_memory.bin` specified in canbench.yml only has the first give bytes set.
    // The rest should be zero.
    assert_eq!(&buf, &[0x41, 0x42, 0x43, 0x44, 0x45, 0, 0, 0, 0, 0]);
}

fn main() {}
