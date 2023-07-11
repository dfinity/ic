use pocket_ic::PocketIC;

#[test]
fn calltest() {
    println!("test start");
    let pic = PocketIC::new("../../target/debug/pocket-ic-backend");
    pic.test_call();
    println!("test end");
}
