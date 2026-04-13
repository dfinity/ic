//! Minimal reproducer for a potential kernel regression where
//! `madvise(MADV_REMOVE)` on a 4KiB range within a huge-page-backed
//! `MAP_SHARED` memfd region corrupts nearby pages.
//!
//! The parent process creates a memfd and forks. The child maps the file,
//! fills all pages with known patterns, applies MADV_HUGEPAGE, and then
//! continuously verifies non-punched pages. The parent maps the same file
//! and punches holes via MADV_REMOVE while the child reads.
//! This mirrors the replica/sandbox architecture where two processes share
//! a backing file via MAP_SHARED.

use std::ptr;
use std::time::Duration;

const PAGE_SIZE: usize = 4096;
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024; // 2 MiB
const FILE_SIZE: usize = 20 * 1024 * 1024; // 20 MiB
const TOTAL_PAGES: usize = FILE_SIZE / PAGE_SIZE;

/// Interval between punched pages. Every N-th page is punched.
/// Using a value that doesn't align with huge page boundaries
/// so we punch holes in the middle of huge pages.
const PUNCH_INTERVAL: usize = 7;

/// Number of reader threads in the child process.
const NUM_READER_THREADS: usize = 16;

const FILL_BYTE: u8 = 0xAF;

/// Shared control block between parent and child, placed in a small
/// anonymous MAP_SHARED region so both processes see the same values.
#[repr(C)]
struct SharedCtl {
    /// Child sets this to 1 after filling pages, telling parent it can start punching.
    ready: std::sync::atomic::AtomicU32,
    /// Parent sets this to 1 to tell the child to stop reading.
    stop: std::sync::atomic::AtomicU32,
    /// Child writes its total failure count here before exiting.
    child_failures: std::sync::atomic::AtomicUsize,
    /// Child writes total pages verified here.
    child_verified: std::sync::atomic::AtomicUsize,
}

const NUM_ITERATIONS: usize = 1000;

fn main() {
    println!("THP + MADV_REMOVE cross-process kernel regression test");
    println!("=======================================================");
    println!("File size:       {} MiB", FILE_SIZE / 1024 / 1024);
    println!("Total pages:     {}", TOTAL_PAGES);
    println!("Child readers:   {}", NUM_READER_THREADS);
    println!(
        "Punching every {}th page ({} pages)",
        PUNCH_INTERVAL,
        TOTAL_PAGES / PUNCH_INTERVAL
    );
    println!("Iterations:      {}", NUM_ITERATIONS);
    println!();

    for iteration in 1..=NUM_ITERATIONS {
        println!("--- Iteration {}/{} ---", iteration, NUM_ITERATIONS);
        let failures = run_iteration();
        if failures > 0 {
            eprintln!(
                "\nFAILED on iteration {}: {} pages corrupted by cross-process MADV_REMOVE!",
                iteration, failures
            );
            std::process::exit(1);
        }
        println!("Iteration {} PASSED\n", iteration);
    }

    println!(
        "All {} iterations PASSED: No corruption detected.",
        NUM_ITERATIONS
    );
}

/// Run a single iteration of the test. Returns total number of corrupted pages.
fn run_iteration() -> usize {
    // Allocate shared control block via anonymous MAP_SHARED.
    let ctl = unsafe {
        libc::mmap(
            ptr::null_mut(),
            std::mem::size_of::<SharedCtl>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(ctl != libc::MAP_FAILED, "mmap ctl failed: {}", errno());
    let ctl = ctl as *mut SharedCtl;
    unsafe {
        ptr::write_bytes(ctl as *mut u8, 0, std::mem::size_of::<SharedCtl>());
    }

    // Create memfd.
    let fd = unsafe { libc::memfd_create(b"thp_test\0".as_ptr() as *const _, 0) };
    assert!(fd >= 0, "memfd_create failed: {}", errno());
    assert!(unsafe { libc::ftruncate64(fd, FILE_SIZE as i64) } == 0);

    // Fork child process.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", errno());

    if pid == 0 {
        // ---- Child process ----
        // Map the file and fill it with known patterns.
        let child_base = mmap_file(fd);

        // Advise MADV_HUGEPAGE.
        let ret = unsafe { libc::madvise(child_base as *mut _, FILE_SIZE, libc::MADV_HUGEPAGE) };
        assert!(ret == 0, "madvise(MADV_HUGEPAGE) failed: {}", errno());

        // Fill every page with a known pattern.
        for page_idx in 0..TOTAL_PAGES {
            fill_page(child_base, page_idx);
        }

        // Signal parent that pages are ready.
        unsafe { (*ctl).ready.store(1, std::sync::atomic::Ordering::Release) };

        // Start reader loop (runs until parent signals stop).
        child_reader_loop(child_base, ctl);

        unsafe {
            libc::munmap(child_base as *mut _, FILE_SIZE);
            libc::_exit(0);
        }
    }

    // ---- Parent process ----
    // Map the file in the parent.
    let parent_base = mmap_file(fd);

    // Wait for child to finish filling pages.
    while unsafe { (*ctl).ready.load(std::sync::atomic::Ordering::Acquire) } == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }

    // Punch holes while child is reading.
    let mut is_punched = vec![false; TOTAL_PAGES];
    let punched_pages: Vec<usize> = (0..TOTAL_PAGES)
        .filter(|i| i % PUNCH_INTERVAL == 0)
        .collect();

    for &page_idx in &punched_pages {
        let page_ptr = unsafe { parent_base.add(page_idx * PAGE_SIZE) };
        let ret = unsafe { libc::madvise(page_ptr as *mut _, PAGE_SIZE, libc::MADV_REMOVE) };
        assert!(
            ret == 0,
            "madvise(MADV_REMOVE) failed on page {}: {}",
            page_idx,
            errno()
        );
        is_punched[page_idx] = true;
    }

    // Signal child to stop.
    unsafe { (*ctl).stop.store(1, std::sync::atomic::Ordering::Release) };

    // Wait for child.
    let mut status: i32 = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let child_failures = unsafe {
        (*ctl)
            .child_failures
            .load(std::sync::atomic::Ordering::Acquire)
    };
    let child_verified = unsafe {
        (*ctl)
            .child_verified
            .load(std::sync::atomic::Ordering::Acquire)
    };
    println!(
        "  Child: {} pages verified, {} failures",
        child_verified, child_failures
    );

    // Final verification from the parent.
    let parent_failures = verify_pages(parent_base, &is_punched);
    println!("  Parent verification failures: {}", parent_failures);

    // Cleanup.
    unsafe {
        libc::munmap(parent_base as *mut _, FILE_SIZE);
        libc::munmap(ctl as *mut _, std::mem::size_of::<SharedCtl>());
        libc::close(fd);
    }

    child_failures + parent_failures
}

/// The child reader loop: spawns threads that continuously verify pages
/// until the parent signals stop, then does a post-sleep recheck.
fn child_reader_loop(base: *mut u8, ctl: *mut SharedCtl) {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    let base_addr = base as usize;
    let ctl_addr = ctl as usize;
    let failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let verified = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let readers: Vec<_> = (0..NUM_READER_THREADS)
        .map(|tid| {
            let failures = Arc::clone(&failures);
            let verified = Arc::clone(&verified);
            std::thread::spawn(move || {
                let base = base_addr as *mut u8;
                let ctl = ctl_addr as *mut SharedCtl;
                let mut local_failures = 0usize;
                let mut pass = 0u64;

                while unsafe { (*ctl).stop.load(Ordering::Acquire) } == 0 {
                    for page_idx in (tid..TOTAL_PAGES) {
                        if page_idx % PUNCH_INTERVAL == 0 {
                            continue;
                        }
                        if check_page(base, page_idx) {
                            verified.fetch_add(1, Ordering::Relaxed);
                        } else {
                            local_failures += 1;
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if failures.load(Ordering::Relaxed) > 0 {
                        break;
                    }
                    pass += 1;
                }
            })
        })
        .collect();

    for h in readers {
        h.join().expect("child reader thread panicked");
    }

    // Post-sleep recheck.
    std::thread::sleep(Duration::from_millis(1));

    let mut recheck = 0usize;
    for page_idx in (0..TOTAL_PAGES) {
        if page_idx % PUNCH_INTERVAL == 0 {
            continue;
        }
        if !check_page(base, page_idx) {
            recheck += 1;
        }
    }
    eprintln!("post-sleep failures: {}", recheck,);

    unsafe {
        (*ctl)
            .child_failures
            .store(failures.load(Ordering::Relaxed), Ordering::Release);
        (*ctl)
            .child_verified
            .store(verified.load(Ordering::Relaxed), Ordering::Release);
    }
}

fn mmap_file(fd: i32) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            FILE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert!(p != libc::MAP_FAILED, "mmap failed: {}", errno());
    p as *mut u8
}

fn fill_page(base: *mut u8, page_idx: usize) {
    let page_ptr = unsafe { base.add(page_idx * PAGE_SIZE) };
    unsafe {
        ptr::write_bytes(page_ptr, FILL_BYTE, PAGE_SIZE);
        let idx_bytes = (page_idx as u64).to_le_bytes();
        ptr::copy_nonoverlapping(idx_bytes.as_ptr(), page_ptr, 8);
    }
}

/// Check a single page. Returns true if valid, false if corrupted.
fn check_page(base: *mut u8, page_idx: usize) -> bool {
    let page_ptr = unsafe { base.add(page_idx * PAGE_SIZE) };
    let expected_idx_bytes = (page_idx as u64).to_le_bytes();

    // Check the page index in the first 8 bytes.
    let mut first_8 = [0u8; 8];
    unsafe {
        ptr::copy_nonoverlapping(page_ptr, first_8.as_mut_ptr(), 8);
    }
    if first_8 != expected_idx_bytes {
        let got_idx = u64::from_le_bytes(first_8);
        let all_zero = unsafe { (0..PAGE_SIZE).all(|off| ptr::read(page_ptr.add(off)) == 0) };
        if all_zero {
            eprintln!(
                "CORRUPTED: page {} (huge page {}) is ALL ZEROS",
                page_idx,
                page_idx * PAGE_SIZE / HUGE_PAGE_SIZE,
            );
        } else {
            eprintln!(
                "CORRUPTED: page {} (huge page {}): expected bytes {:02x?}, got {:02x?}",
                page_idx,
                page_idx * PAGE_SIZE / HUGE_PAGE_SIZE,
                &expected_idx_bytes,
                &first_8,
            );
        }
        return false;
    }

    true
}

/// Verify all non-punched pages sequentially. Returns the number of corrupted pages.
fn verify_pages(base: *mut u8, is_punched: &[bool]) -> usize {
    let mut failures = 0;
    for page_idx in 0..TOTAL_PAGES {
        if is_punched[page_idx] {
            continue;
        }
        if !check_page(base, page_idx) {
            failures += 1;
            if failures >= 100 {
                eprintln!("... (truncated after 100 failures)");
                return failures;
            }
        }
    }
    if failures == 0 {
        let non_punched = is_punched.iter().filter(|&&p| !p).count();
        println!("  All {} non-punched pages verified OK", non_punched);
    } else {
        eprintln!("  {} non-punched pages are corrupted!", failures);
    }
    failures
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
