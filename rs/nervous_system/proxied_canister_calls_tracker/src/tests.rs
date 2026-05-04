use super::*;

use pretty_assertions::assert_eq;

#[test]
fn test_slice_head_and_tail() {
    const L: u8 = CanisterCallArgsMetadata::SLICE_SIZE as u8;

    let blob = (0..=255).collect::<Vec<u8>>();
    let summary = CanisterCallArgsMetadata::new(&blob);
    assert_eq!(
        summary,
        CanisterCallArgsMetadata {
            len: 256,
            head: (0..L).collect::<Vec<u8>>(),
            tail: ((255 - L + 1)..=255).collect::<Vec<u8>>(),
        },
    );

    let blob = Vec::new();
    let summary = CanisterCallArgsMetadata::new(&blob);
    assert_eq!(
        summary,
        CanisterCallArgsMetadata {
            len: 0,
            head: vec![],
            tail: vec![],
        },
    );

    let blob = vec![42];
    let summary = CanisterCallArgsMetadata::new(&blob);
    assert_eq!(
        summary,
        CanisterCallArgsMetadata {
            len: 1,
            head: vec![42],
            tail: vec![42],
        },
    );

    let blob = vec![4, 2];
    let summary = CanisterCallArgsMetadata::new(&blob);
    assert_eq!(
        summary,
        CanisterCallArgsMetadata {
            len: 2,
            head: vec![4, 2],
            tail: vec![4, 2],
        },
    );

    let blob = (0..100).collect::<Vec<u8>>();
    let summary = CanisterCallArgsMetadata::new(&blob);
    let expected_tail = ((100 - L)..100).collect::<Vec<u8>>();
    assert_eq!(expected_tail.len(), L as usize);
    assert_eq!(
        summary,
        CanisterCallArgsMetadata {
            len: 100,
            head: (0..L).collect::<Vec<u8>>(),
            tail: expected_tail,
        },
    );
}
