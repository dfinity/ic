use pocket_ic::PocketIcBuilder;
use reqwest::blocking::Client;
use std::{thread, time::Duration};

// This test must be in a separate test suite so that the PocketIC server is not reused
// by a different test.
#[test]
fn create_instance_twice() {
    let mut pic = PocketIcBuilder::new().with_nns_subnet().build();
    let url = pic.make_live(None);
    let status_endpoint = url.join("api/v2/status").unwrap();

    // Check that the server is running.
    let client = Client::new();
    let response = client.get(status_endpoint.clone()).send().unwrap();
    assert_eq!(response.status(), 200);
}
