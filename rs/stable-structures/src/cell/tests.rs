use crate::cell::{Cell, ValueError};
use crate::storable::Storable;
use crate::vec_mem::VectorMemory;
use crate::{Memory, RestrictedMemory, WASM_PAGE_SIZE};

fn reload<T: Default + Storable, M: Memory>(c: Cell<T, M>) -> Cell<T, M> {
    Cell::init(c.forget(), T::default()).unwrap()
}

#[test]
fn test_cell_init() {
    let mem = VectorMemory::default();
    let cell = Cell::init(mem, 1024u64).unwrap();
    assert_eq!(*cell.get(), 1024u64);
    let mem = cell.forget();
    assert_ne!(mem.size(), 0);
    let cell = Cell::init(mem, 0u64).unwrap();
    assert_eq!(1024u64, *cell.get());

    // Check that Cell::new overwrites the contents unconditionally.
    let cell = Cell::new(cell.forget(), 2048u64).unwrap();
    assert_eq!(2048u64, *cell.get());
}

#[test]
fn test_out_of_space() {
    let mem = RestrictedMemory::new(VectorMemory::default(), 0..1);
    let data = [1u8; 100];
    let mut cell = Cell::new(mem, data.to_vec()).unwrap();

    assert_eq!(&data[..], &cell.get()[..]);

    assert_eq!(
        Err(ValueError::ValueTooLarge {
            value_size: WASM_PAGE_SIZE,
        }),
        cell.set(vec![2u8; WASM_PAGE_SIZE as usize])
    );

    assert_eq!(&data[..], &cell.get()[..]);
}

#[test]
fn test_cell_grow_and_shrink() {
    let mem = VectorMemory::default();
    let mut cell = Cell::init(mem, vec![1u8; 10]).unwrap();

    cell.set(vec![2u8; 20]).unwrap();
    let mut cell = reload(cell);
    assert_eq!(&[2u8; 20][..], &cell.get()[..]);

    cell.set(vec![3u8; 5]).unwrap();
    let cell = reload(cell);
    assert_eq!(&[3u8; 5][..], &cell.get()[..]);
}
