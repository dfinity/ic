use common::system_test_environment::RosettaTestingEnvironment;

mod common;

#[test]
fn smoke_test() {
    let rosetta_testing_environment = RosettaTestingEnvironment::builder().build();
}
