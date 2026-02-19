// This file should compile on windows
fn main() {
    unsafe {
        ic0::sys::trap(0, 0);
    }
}
