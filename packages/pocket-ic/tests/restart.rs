use pocket_ic::PocketIcBuilder;
use std::time::Duration;

#[test]
fn hyper_issue() {
    let mut pic = PocketIcBuilder::new().with_nns_subnet().build();
    std::thread::sleep(Duration::from_secs(5));
    let _url = pic.make_live(None);
}
