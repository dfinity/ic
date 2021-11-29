use lazy_static::lazy_static;
use slog::{debug, o};
use std::cell::RefCell;
use std::rc::Rc;

use memory_tracker::MemoryTracker;

pub struct Area<'a> {
    register_args: *mut memory_tracker_area_handler_args<'a>,
    mapping: Rc<RefCell<ExternalMapping<'a>>>,
    log: slog::Logger,
}

impl<'a> Area<'a> {
    pub fn area_mut<K>(&mut self) -> &mut [K] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.mapping.borrow().addr() as *mut K,
                self.mapping.borrow().size() / std::mem::size_of::<K>(),
            )
        }
    }

    pub fn area<K>(&self) -> &[K] {
        unsafe {
            std::slice::from_raw_parts(
                self.mapping.borrow().addr() as *const K,
                self.mapping.borrow().size() / std::mem::size_of::<K>(),
            )
        }
    }

    pub fn addr(&self) -> *mut libc::c_void {
        self.mapping.borrow().addr()
    }

    pub fn size(&self) -> usize {
        self.mapping.borrow().size()
    }

    pub fn register(
        base_addr: *mut libc::c_void,
        num_pages: usize,
        file_name: Option<String>,
        log: slog::Logger,
    ) -> Area<'a> {
        let length = *PAGE_SIZE * num_pages;
        let mapping = Rc::new(RefCell::new(ExternalMapping::new(
            base_addr,
            length,
            file_name,
            log.clone(),
        )));

        let page_init = Box::new({
            let log = log.new(o!("fn" => "page_init"));
            let mapping = mapping.clone();
            move |addr| {
                if let Some(ref data_mapping) = mapping.borrow().data_mapping {
                    let page_num = addr as usize / *PAGE_SIZE;
                    debug!(log, "get_page({})", page_num);
                    data_mapping.get_page(page_num)
                } else {
                    debug!(log, "zero page");
                    &[0u8; 4096][..]
                }
            }
        });

        let args = Box::new(memory_tracker_area_handler_args {
            page_init,
            mapping: mapping.clone(),
            log: log.new(o!("fn" => "memory_tracker_sigsegv_fault_handler")),
        });

        let register_args = Box::into_raw(args);

        debug!(
            log,
            "registering SIGSEGV handler for Area(addr={:?}, size={})",
            mapping.borrow().addr(),
            mapping.borrow().size(),
        );

        unsafe {
            if libc::mprotect(
                mapping.borrow().addr(),
                mapping.borrow().size(),
                libc::PROT_NONE,
            ) < 0
            {
                panic!("mprotect failed.\n");
            }
        }

        Area {
            mapping,
            register_args,
            log,
        }
    }

    pub fn commit(self) {
        self.mapping.borrow_mut().commit()
    }

    pub fn dirty_pages(&self) -> Vec<*const libc::c_void> {
        self.mapping.borrow().tracker.dirty_pages()
    }

    pub fn register_args(&self) -> *mut libc::c_void {
        self.register_args as *mut libc::c_void
    }
}

#[repr(C)]
struct memory_tracker_area_handler_args<'a> {
    page_init: Box<dyn Fn(usize) -> &'a [u8] + 'a>,
    mapping: Rc<RefCell<ExternalMapping<'a>>>,
    log: slog::Logger,
}

// Return `true` if signal has been handled.
pub extern "C" fn memory_tracker_sigsegv_fault_handler(
    fault_address: *mut libc::c_void,
    user_arg: *mut libc::c_void,
) -> bool {
    assert!(
        !user_arg.is_null(),
        "memory_tracker_area_handler_args must not be null"
    );
    let args: &mut memory_tracker_area_handler_args<'_> =
        unsafe { &mut *(user_arg as *mut memory_tracker_area_handler_args<'_>) };
    memory_tracker::sigsegv_fault_handler(
        &mut args.mapping.borrow(),
        &args.page_init,
        fault_address,
    )
}

impl<'a> Drop for Area<'a> {
    fn drop(&mut self) {
        debug!(
            self.log,
            "dropping Area(addr={:?}, size={})",
            self.mapping.borrow().addr(),
            self.mapping.borrow().size(),
        );
        // self.mapping.borrow_mut().commit();
        // Properly destroy area_handler_args. See:
        // https://doc.rust-lang.org/std/boxed/struct.Box.html#method.into_raw
        unsafe {
            let _: Box<memory_tracker_area_handler_args<'a>> = Box::from_raw(self.register_args);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// Tracks an external memory mapping backed by a file descriptor.
pub struct ExternalMapping<'a> {
    tracker: memory_tracker::SigsegvMemoryTracker,
    data_mapping: Option<MmapFile<'a>>,
    log: slog::Logger,
}

impl<'a> ExternalMapping<'a> {
    pub fn new(
        base_addr: *mut libc::c_void,
        length: usize,
        file_name: Option<String>,
        log: slog::Logger,
    ) -> Self {
        let data_mapping = file_name.map(|file_name| MmapFile::new(&file_name, length));
        let tracker = memory_tracker::SigsegvMemoryTracker::new(base_addr, length).unwrap();
        Self {
            tracker,
            data_mapping,
            log,
        }
    }

    #[inline]
    fn addr(&self) -> *mut libc::c_void {
        self.tracker.area().addr() as *mut libc::c_void
    }

    #[inline]
    fn size(&self) -> usize {
        self.tracker.area().size()
    }

    fn commit(&mut self) {
        let dirty_pages = self.tracker.dirty_pages();
        debug!(self.log, "committing Mapping(dirty={:?})", dirty_pages);
        let mut dirty_pages: Vec<u64> = dirty_pages.iter().map(|x| *x as u64).collect();
        dirty_pages.sort_unstable();
        for dirty_addr in dirty_pages {
            debug!(
                self.log,
                "committing Page(address=0x{:x}, bytes=[{}])",
                dirty_addr,
                show_bytes_compact(&get_page(dirty_addr as *mut u8)[..])
            );
            let page_num = (dirty_addr as usize - self.tracker.area().addr() as usize) / *PAGE_SIZE;
            if let Some(ref data_mapping) = self.data_mapping {
                data_mapping.put_page(page_num, dirty_addr as *const u8);
            }
        }
        debug!(self.log, "resetting dirty pages");
        *self.tracker.dirty_pages.borrow_mut() = Vec::new();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

struct MmapFile<'a> {
    addr: *mut libc::c_void,
    size: usize,
    marker: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> MmapFile<'a> {
    fn new(file_name: &str, file_size: usize) -> Self {
        let fd = open_and_truncate(&file_name, file_size);
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                file_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        unsafe {
            // The mmap() function shall add an extra reference to the file associated with the
            // file descriptor fildes which is not removed by a subsequent close() on that file
            // descriptor.
            libc::close(fd);
        }
        Self {
            addr,
            size: file_size,
            marker: std::marker::PhantomData,
        }
    }

    fn get_page(&self, page_num: usize) -> &'a [u8] {
        let addr = (self.addr as u64 + page_num as u64 * (*PAGE_SIZE as u64)) as *mut u8;
        unsafe { std::slice::from_raw_parts(addr, *PAGE_SIZE) }
    }

    fn put_page(&self, page_num: usize, bytes: *const u8) {
        let addr = (self.addr as u64 + page_num as u64 * (*PAGE_SIZE as u64)) as *mut u8;
        // semantically equivalent to C's memcpy, but with the argument order swapped.
        // std::ptr::copy_nonoverlapping(source, dest, count);
        unsafe { std::ptr::copy_nonoverlapping(bytes, addr, *PAGE_SIZE) };
    }
}

impl<'a> Drop for MmapFile<'a> {
    fn drop(&mut self) {
        unsafe {
            libc::msync(self.addr, self.size, libc::MS_SYNC);
            libc::munmap(self.addr, self.size);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// helpers

// TODO: either use Vec here or make PAGE_SIZE a const that could be used here instead of 4096.
// This would require cusotm build.rs and runtime check to make sure the value is correct.
fn get_page(addr: *mut u8) -> [u8; 4096] {
    assert_eq!(*PAGE_SIZE, 4096);
    unsafe {
        let mut bytes: [u8; 4096] = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(addr, bytes.as_mut_ptr() as *mut u8, *PAGE_SIZE);
        bytes
    }
}

#[allow(dead_code)]
fn show_bytes_compact(bytes: impl AsRef<[u8]>) -> String {
    let mut result = String::new();
    let mut count = 1;
    let mut current = None;
    for &b in bytes.as_ref().iter() {
        match current {
            Some(x) if x == b => {
                count += 1;
            }
            Some(x) => {
                result += &format!("{}x{:x} ", count, x);
                count = 1;
            }
            None => (),
        }
        current = Some(b);
    }
    if let Some(x) = current {
        result += &format!("{}x{:x}", count, x)
    }
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_show_page() {
        let mut bs = vec![0, 0, 0, 1, 2, 3, 0, 0, 4, 0];
        assert_eq!(
            "3x0 1x1 1x2 1x3 2x0 1x4 1x0".to_string(),
            super::show_bytes_compact(bs)
        );
        bs = vec![0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!("8x0".to_string(), super::show_bytes_compact(bs));
        bs = vec![];
        assert_eq!("".to_string(), super::show_bytes_compact(bs));
    }
}

lazy_static! {
    pub static ref PAGE_SIZE: usize = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) as usize };
}

pub fn open_and_truncate<F: AsRef<std::path::Path> + Clone>(
    file_name: F,
    length: usize,
) -> std::os::unix::io::RawFd {
    let f: std::fs::File = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_name.clone())
        .unwrap_or_else(|_| panic!("open file {}", file_name.as_ref().to_str().unwrap()));
    let fd = std::os::unix::io::IntoRawFd::into_raw_fd(f);
    unsafe {
        libc::ftruncate(fd, length as i64);
    }
    fd
}
