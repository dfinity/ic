use candid::Principal;
use pocket_ic::PocketIc;
use reqwest::Url;
use reqwest::blocking::Client;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub fn frontend_canister(
    pic: &PocketIc,
    canister_id: Principal,
    raw: bool,
    path: impl ToString,
) -> (Client, Url) {
    let mut url = pic.url().unwrap();
    assert_eq!(url.host_str().unwrap(), "localhost");
    let maybe_raw = if raw { ".raw" } else { "" };
    let host = format!("{}{}.localhost", canister_id, maybe_raw);
    url.set_host(Some(&host)).unwrap();
    url.set_path(&path.to_string());
    // Windows doesn't automatically resolve localhost subdomains.
    let client = if cfg!(windows) {
        Client::builder()
            .resolve(
                &host,
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    pic.get_server_url().port().unwrap(),
                ),
            )
            .build()
            .unwrap()
    } else {
        Client::new()
    };
    (client, url)
}
