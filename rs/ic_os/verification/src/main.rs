use sev::firmware::guest::Firmware;
use std::time::Instant;

fn main() {
    let start = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..64 {
            scope.spawn(|| {
                let mut firmware = Firmware::open().unwrap();
                let mut v = Vec::with_capacity(1000);
                for _ in 0..100 {
                    v.push(
                        firmware
                            .get_report(Some(1), Some([1; 64]), Some(1))
                            .unwrap(),
                    );
                }
                println!("{:?} finished", std::thread::current().id());
                std::hint::black_box(v);
            });
        }
    });
    println!("{:?}", start.elapsed());
}
