use sev::firmware::guest::{AttestationReport, Firmware};

fn main() {
    let mut sev = Firmware::open().unwrap();
    let report = sev.get_report(None, None, None).unwrap();
    // let measurement = AttestationReport::from_bytes(&report).unwrap().measurement;
    let image_id = AttestationReport::from_bytes(&report).unwrap().measurement;
    println!("Measurement: {}", image_id.to_string());
}
