use dfn_core::api::print;
use dfn_macro::{query, update};

static mut MYVEC: Vec<u8> = Vec::new();
const ARRAYSIZE: usize = 10;
static mut TRAP: bool = false;

#[update]
async fn create_array() -> Result<String, String> {
    unsafe {
        MYVEC = vec![0; ARRAYSIZE];
    }

    print("Array created");
    Ok("Array created".into())
}

#[update]
async fn increment_array() -> Result<String, String> {
    unsafe {
        if MYVEC.is_empty() {
            return Err("Array not initialized".into());
        } else {
            let hi = MYVEC[ARRAYSIZE - 1];
            let lo = MYVEC[0];

            print(&format!("Before increment hi {} lo {}", hi, lo));

            for v in &mut MYVEC {
                *v += 1;
            }

            let hi = MYVEC[ARRAYSIZE - 1];
            let lo = MYVEC[0];

            print(&format!("After increment hi {} lo {}", hi, lo));

            if TRAP {
                unreachable!()
            }
        }
    }
    print("Done !!! ");
    Ok("Done !!! ".into())
}

#[query]
async fn compute_sum() -> Result<u32, String> {
    unsafe {
        if MYVEC.is_empty() {
            Err("Array not initialized".into())
        } else {
            let hi = MYVEC[ARRAYSIZE - 1];
            let lo = MYVEC[0];

            print(&format!("Compute sum hi {} lo {}", hi, lo));

            let mut sum: u32 = 0;

            for v in &MYVEC {
                sum += *v as u32;
            }

            print(&format!("Computed sum {}", sum));
            Ok(sum)
        }
    }
}

#[update]
async fn toggle_trap() -> Result<(), String> {
    unsafe {
        TRAP = !TRAP;
    }
    Ok(())
}

#[query]
async fn test() -> Result<String, String> {
    print("hello world");
    Ok("Hello World".into())
}

fn main() {}
