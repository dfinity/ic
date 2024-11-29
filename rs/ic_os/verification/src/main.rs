use sev::firmware::guest::Firmware;

fn main() {
    let mut firmware = Firmware::open().unwrap();
    let report = firmware.get_report(None, Some([1; 64]), None).unwrap();
    println!("{report:?}");
}
