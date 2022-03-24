use crate::{Memory, WASM_PAGE_SIZE};
use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

const MAX_PAGES: u64 = i64::MAX as u64 / WASM_PAGE_SIZE;

impl Memory for RefCell<Vec<u8>> {
    fn size(&self) -> u64 {
        self.borrow().len() as u64 / WASM_PAGE_SIZE
    }

    fn grow(&self, pages: u64) -> i64 {
        let size = self.size();
        match size.checked_add(pages) {
            Some(n) => {
                if n > MAX_PAGES {
                    return -1;
                }
                self.borrow_mut()
                    .resize((n * WASM_PAGE_SIZE as u64) as usize, 0);
                size as i64
            }
            None => -1,
        }
    }

    fn read(&self, offset: u64, dst: &mut [u8]) {
        let n = offset
            .checked_add(dst.len() as u64)
            .expect("read: out of bounds");

        if n as usize > self.borrow().len() {
            panic!("read: out of bounds");
        }

        dst.copy_from_slice(&self.borrow()[offset as usize..n as usize]);
    }

    fn write(&self, offset: u64, src: &[u8]) {
        let n = offset
            .checked_add(src.len() as u64)
            .expect("write: out of bounds");

        if n as usize > self.borrow().len() {
            panic!("write: out of bounds");
        }
        self.borrow_mut()[offset as usize..n as usize].copy_from_slice(src);
    }
}

impl<M: Memory> Memory for Rc<M> {
    fn size(&self) -> u64 {
        self.deref().size()
    }
    fn grow(&self, pages: u64) -> i64 {
        self.deref().grow(pages)
    }
    fn read(&self, offset: u64, dst: &mut [u8]) {
        self.deref().read(offset, dst)
    }
    fn write(&self, offset: u64, src: &[u8]) {
        self.deref().write(offset, src)
    }
}
