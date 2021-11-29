use slog::slog_o;
use slog_scope::info;

use yansi::Paint;

use memory_area::PAGE_SIZE;

mod test_utils;

fn run_memory_area_test() {
    let a1_num_pages = 3;
    // 1. Setup some mmaped memory and register with the handler.
    let a1 = {
        let addr = unsafe {
            libc::mmap(
                0xAAAA0000 as *mut libc::c_void,
                a1_num_pages * *PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                0,
                0,
            )
        };
        memory_area::Area::register(
            addr,
            a1_num_pages,
            None,
            slog_scope::logger().new(slog_o!("area" => "1")),
        )
    };

    // 2. And another memory chunk.
    let a2_num_pages = 5;
    let a2 = {
        let addr = unsafe {
            libc::mmap(
                0xFFFF0000 as *mut libc::c_void,
                a2_num_pages * *PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                0,
                0,
            )
        };
        memory_area::Area::register(
            addr,
            a2_num_pages,
            None,
            slog_scope::logger().new(slog_o!("area" => "2")),
        )
    };

    let mut index: usize;

    // Some sanity checks
    assert_eq!(
        a1.area::<i32>().len(),
        a1_num_pages * *PAGE_SIZE / std::mem::size_of::<i32>()
    );
    assert_eq!(
        a1.area::<i64>().len(),
        a1_num_pages * *PAGE_SIZE / std::mem::size_of::<i64>()
    );
    assert_eq!(a1.area::<i32>().len(), 2 * a1.area::<i64>().len());
    assert_eq!(a1.area::<u8>().len(), 8 * a1.area::<i64>().len());

    assert_eq!(
        a2.area::<i32>().len(),
        a2_num_pages * *PAGE_SIZE / std::mem::size_of::<i32>()
    );
    assert_eq!(
        a2.area::<i64>().len(),
        a2_num_pages * *PAGE_SIZE / std::mem::size_of::<i64>()
    );
    assert_eq!(a1.area::<i32>().len(), 2 * a1.area::<i64>().len());
    assert_eq!(a1.area::<u8>().len(), 8 * a1.area::<i64>().len());

    // Reading does not trigger SIGSEGV.
    test_utils::memory_read(a1.addr() as *mut i32, 0);
    test_utils::memory_read(a1.addr() as *mut i32, 1);
    test_utils::memory_read(a1.addr() as *mut i32, 2);

    // 3. Write an int at the end of page(0). This is the first write and triggers SIGSEGV.
    index = (*PAGE_SIZE / std::mem::size_of::<i32>()) - 1;
    test_utils::memory_write_read(a1.addr() as *mut i32, index, 42);

    // 4. Write an int at the beginning of page(0). Since page(0) has already been written to
    //    this doesn't trigger SIGSEGV.
    index = 0;
    test_utils::memory_write_read(a1.addr() as *mut i32, index, 11);

    // 4.1 Write an int at the very end of the second memory area.
    index = 5 * (*PAGE_SIZE / std::mem::size_of::<i32>()) - 1;
    test_utils::memory_write_read(a2.addr() as *mut i32, index, 42);

    // 5. Write an int in the middle of page(2).
    index = 2 * (*PAGE_SIZE / std::mem::size_of::<i32>())
        + (*PAGE_SIZE / std::mem::size_of::<i32>() / 2);
    test_utils::memory_write_read(a1.addr() as *mut i32, index, 123);

    // 6. Read the 8th `i32` from page(1) (i.e. 1024 + 8 = 1032)
    index = (*PAGE_SIZE / std::mem::size_of::<i32>()) + 8;
    test_utils::memory_read(a1.addr() as *mut i32, index);

    // 7. Create a compiler level memory barrier forcing optimizer to not re-order memory
    //    accesses across the barrier.
    // unsafe { asm!("" ::: "memory" : "volatile"); }

    // 8. I think in some circumstances the compiler can move the access to `dirty` to before
    //    the memory accesses above. The barrier ensures this doesn't happen.
    let mut dirty = a1
        .dirty_pages()
        .iter()
        .map(|x| (*x as usize - a1.addr() as usize) / *PAGE_SIZE)
        .collect::<Vec<usize>>();
    dirty.sort();
    info!("dirty pages: {:?}", dirty);
    assert_eq!(dirty, vec![0, 2]);
}

#[test]
fn test_memory_area() {
    let _guards = test_utils::init_logger();
    info!("{}", Paint::white("<< testing memory_area >>").bold());
    slog_scope::scope(
        &slog_scope::logger().new(slog_o!("test" => "memory_area")),
        run_memory_area_test,
    );
}
