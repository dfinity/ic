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

    // Drop the instance since dropping the instance at the end of the test fails after the original server is stopped.
    drop(pic);

    // Wait for the server to stop upon TTL (60s).
    thread::sleep(Duration::from_secs(90));

    // Check that the server is stopped.
    let err = client.get(status_endpoint).send().unwrap_err();
    assert!(err.status().is_none());

    // Creating a new PocketIC instance should start a new server.
    let mut pic = PocketIcBuilder::new().with_nns_subnet().build();
    let url = pic.make_live(None);
    let status_endpoint = url.join("api/v2/status").unwrap();

    // Check that the server is running.
    let response = client.get(status_endpoint.clone()).send().unwrap();
    assert_eq!(response.status(), 200);
}
