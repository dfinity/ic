// Stack grows down. Allocs start at stack_add + stacksize - 1
//
// +--------------------+
// |    frame n         | | Stack growth
// |                    | |
// |    frame 0         | v
// |                    |
// |                    |
// |    Stack addr      |
// +--------------------+
// |     Guard page     |
// |                    |
// +--------------------+

use libc::MAP_FAILED;
use libc::{mmap, mprotect, munmap};
use libc::{sigaltstack, SIGSTKSZ, SS_DISABLE};
use libc::{sysconf, _SC_PAGESIZE};
use libc::{MAP_ANON, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE};

use std::io::Error;
use std::mem::MaybeUninit;
use std::ptr;

unsafe fn get_act_sigstack() -> libc::stack_t {
    let mut prev_stack = std::mem::MaybeUninit::<libc::stack_t>::uninit();
    sigaltstack(std::ptr::null(), prev_stack.as_mut_ptr());
    prev_stack.assume_init()
}

pub struct ScopedSignalStack {
    stack: libc::stack_t,
    prev_stack: libc::stack_t,
}

//impl !Send for ScopedSignalStack {}
//impl !Sync for ScopedSignalStack {}

impl ScopedSignalStack {
    unsafe fn new(stack: libc::stack_t) -> Self {
        let mut prev_stack = MaybeUninit::<libc::stack_t>::uninit();
        let res = sigaltstack(&stack, prev_stack.as_mut_ptr());
        if res != 0 {
            panic!(
                "Setting sigaltstack failed. errno: {}",
                Error::last_os_error()
            );
        }
        Self {
            stack,
            prev_stack: prev_stack.assume_init(),
        }
    }
}

impl Drop for ScopedSignalStack {
    fn drop(&mut self) {
        unsafe {
            let act_stack = get_act_sigstack();
            //make sure someone else didn't change the stack in the meanwhile
            assert_eq!(
                act_stack.ss_flags & SS_DISABLE,
                0,
                "Alt sigstack not present"
            );
            assert_eq!(
                act_stack.ss_sp, self.stack.ss_sp,
                "Signal stack in use is not the one we registered"
            );
            let res = sigaltstack(&self.prev_stack, ptr::null_mut());
            if res != 0 {
                panic!(
                    "Setting sigaltstack failed. errno: {}",
                    Error::last_os_error()
                );
            }
        }
    }
}

#[derive(Debug)]
pub struct WasmtimeSignalStack {
    stack: libc::stack_t,
    mem: *mut libc::c_void,
    mem_size: usize,
}

impl WasmtimeSignalStack {
    pub fn new() -> Self {
        unsafe {
            let page_size = sysconf(_SC_PAGESIZE) as usize;
            // 2020-04-21: wasmtime now overwrites the signal stack if the size is less
            // than 64k. Thus we set it to 64k to avoid that. Current wasmtime work in
            // progress indicates this behavior will change in the future. We will keep our
            // own stack until the behavior stabilizes.
            let signal_stack_size = std::cmp::max(SIGSTKSZ, 64 * 1024);
            debug_assert_eq!(signal_stack_size % page_size, 0);
            let mem_size = page_size + signal_stack_size;
            let mem = mmap(
                ptr::null_mut(),
                mem_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            );
            if mem == MAP_FAILED {
                panic!(
                    "failed to allocate an alternative stack. Last os error: {}",
                    Error::last_os_error()
                );
            }
            let result = mprotect(mem, page_size, PROT_NONE);
            if result != 0 {
                panic!(
                    "failed to protect the sigstack guard page. Last os error: {}",
                    Error::last_os_error()
                );
            }

            let stackp = (mem as usize + page_size) as _;
            let stack = libc::stack_t {
                ss_sp: stackp,
                ss_flags: 0,
                ss_size: signal_stack_size,
            };

            Self {
                stack,
                mem,
                mem_size,
            }
        }
    }

    pub unsafe fn register(&mut self) -> ScopedSignalStack {
        ScopedSignalStack::new(self.stack)
    }
}

impl Drop for WasmtimeSignalStack {
    fn drop(&mut self) {
        unsafe {
            munmap(self.mem, self.mem_size);
        }
    }
}
