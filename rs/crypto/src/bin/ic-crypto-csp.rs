//! Placeholder process
use std::{thread, time};

fn main() {
    let delay = time::Duration::from_secs(3);

    loop {
        println!("Hello world, I am crypto.");
        thread::sleep(delay);
    }
}
