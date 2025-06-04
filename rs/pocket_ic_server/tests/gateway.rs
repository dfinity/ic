use crate::common::{send_signal_to_pic, start_server, start_server_helper};
use candid::{Encode, Principal};
use ic_utils::interfaces::ManagementCanister;
use nix::sys::signal::Signal;
use pocket_ic::common::rest::{
    CreateHttpGatewayResponse, HttpGatewayBackend, HttpGatewayConfig, HttpGatewayDetails,
    HttpsConfig, Topology,
};
use pocket_ic::PocketIcBuilder;
use rcgen::{CertificateParams, KeyPair};
use reqwest::blocking::Client;
use reqwest::Url;
use reqwest::{Client as NonblockingClient, StatusCode};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tempfile::NamedTempFile;

mod common;

async fn test_gateway(server_url: Url, https: bool) {
    // create PocketIC instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // retrieve the first canister ID on the application subnet
    // which will be the effective and expected canister ID for canister creation
    let topology = pic.topology().await;
    let effective_canister_id: Principal = topology.default_effective_canister_id.into();

    // define HTTP protocol for this test
    let proto = if https { "https" } else { "http" };

    // define two domains for canister ID resolution
    let localhost = "localhost";
    let sub_localhost = &format!("{}.{}", effective_canister_id, localhost);
    let sub_raw_localhost = &format!("{}.raw.{}", effective_canister_id, localhost);
    let alt_domain = "example.com";
    let sub_alt_domain = &format!("{}.{}", effective_canister_id, alt_domain);
    let sub_raw_alt_domain = &format!("{}.raw.{}", effective_canister_id, alt_domain);

    // generate root TLS certificate (only used if `https` is set to `true`,
    // but defining it here unconditionally simplifies the test)
    let root_key_pair = KeyPair::generate().unwrap();
    let root_cert = CertificateParams::new(vec![
        localhost.to_string(),
        sub_localhost.to_string(),
        sub_raw_localhost.to_string(),
        alt_domain.to_string(),
        sub_alt_domain.to_string(),
        sub_raw_alt_domain.to_string(),
    ])
    .unwrap()
    .self_signed(&root_key_pair)
    .unwrap();
    let (mut cert_file, cert_path) = NamedTempFile::new().unwrap().keep().unwrap();
    cert_file.write_all(root_cert.pem().as_bytes()).unwrap();
    let (mut key_file, key_path) = NamedTempFile::new().unwrap().keep().unwrap();
    key_file
        .write_all(root_key_pair.serialize_pem().as_bytes())
        .unwrap();

    // make PocketIc instance live with an HTTP gateway
    let domains = Some(vec![localhost.to_string(), alt_domain.to_string()]);
    let https_config = if https {
        Some(HttpsConfig {
            cert_path: cert_path.into_os_string().into_string().unwrap(),
            key_path: key_path.into_os_string().into_string().unwrap(),
        })
    } else {
        None
    };
    let port = pic
        .make_live_with_params(
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            None,
            domains.clone(),
            https_config.clone(),
        )
        .await
        .port_or_known_default()
        .unwrap();

    // check that an HTTP gateway with the matching port is returned when listing all HTTP gateways
    // and its details are set properly
    let client = NonblockingClient::new();
    let http_gateways: Vec<HttpGatewayDetails> = client
        .get(server_url.join("http_gateway").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http_gateway_details = http_gateways
        .into_iter()
        .find(|details| details.port == port)
        .unwrap();
    assert_eq!(
        http_gateway_details.forward_to,
        HttpGatewayBackend::PocketIcInstance(pic.instance_id)
    );
    assert_eq!(http_gateway_details.domains, domains);
    assert_eq!(http_gateway_details.https_config, https_config);

    // create a non-blocking reqwest client resolving localhost/example.com and <canister-id>.(raw.)localhost/example.com to 127.0.0.1
    let mut builder = NonblockingClient::builder();
    for domain in [
        localhost,
        sub_localhost,
        sub_raw_localhost,
        alt_domain,
        sub_alt_domain,
        sub_raw_alt_domain,
    ] {
        builder = builder.resolve(
            domain,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        );
    }
    // add a custom root certificate
    if https {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(root_cert.pem().as_bytes()).unwrap(),
        );
    }
    let client = builder.build().unwrap();

    // create agent
    let agent = ic_agent::Agent::builder()
        .with_url(format!("{}://{}:{}", proto, localhost, port))
        .with_http_client(client.clone())
        .build()
        .unwrap();
    agent.fetch_root_key().await.unwrap();

    // deploy II canister to PocketIC instance using agent and proxying through HTTP(S) gateway
    let ic00 = ManagementCanister::create(&agent);
    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap();
    assert_eq!(canister_id, effective_canister_id);

    // install II canister WASM
    let ii_path = std::env::var_os("II_WASM").expect("Missing II_WASM (path to II wasm) in env.");
    let ii_wasm = std::fs::read(ii_path).expect("Could not read II wasm file.");
    ic00.install_code(&canister_id, &ii_wasm)
        .with_raw_arg(Encode!(&()).unwrap())
        .call_and_wait()
        .await
        .unwrap();

    // perform frontend asset request for the title page at http://127.0.0.1:<port>/?canisterId=<canister-id>
    let mut test_urls = vec![];
    if !https {
        assert_eq!(proto, "http");
        let canister_url = format!(
            "{}://{}:{}/?canisterId={}",
            "http", "127.0.0.1", port, canister_id
        );
        test_urls.push(canister_url);
    }

    // perform frontend asset request for the title page at http(s)://localhost:<port>/?canisterId=<canister-id>
    let canister_url = format!(
        "{}://{}:{}/?canisterId={}",
        proto, localhost, port, canister_id
    );
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.localhost:<port>
    let canister_url = format!("{}://{}.{}:{}", proto, canister_id, localhost, port);
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.raw.localhost:<port>
    let canister_url = format!("{}://{}.raw.{}:{}", proto, canister_id, localhost, port);
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.example.com:<port>
    let canister_url = format!("{}://{}.{}:{}", proto, canister_id, alt_domain, port);
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.raw.example.com:<port>
    let canister_url = format!("{}://{}.raw.{}:{}", proto, canister_id, alt_domain, port);
    test_urls.push(canister_url.clone());

    for url in test_urls {
        let res = client.get(url).send().await.unwrap();
        let page = String::from_utf8(res.bytes().await.unwrap().to_vec()).unwrap();
        assert!(page.contains("<title>Internet Identity</title>"));
    }

    // stop HTTP gateway and disable auto progress
    pic.stop_live().await;

    // HTTP gateway should eventually stop and requests to it fail
    loop {
        if client.get(canister_url.clone()).send().await.is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    pic.drop().await;
}

#[tokio::test]
async fn test_http_gateway() {
    let server_url = start_server();
    test_gateway(server_url, false).await;
}

#[tokio::test]
async fn test_https_gateway() {
    let server_url = start_server();
    test_gateway(server_url, true).await;
}

fn kill_gateway_with_signal(shutdown_signal: Signal) {
    let (server_url, child) = start_server_helper(None, None, false, false);
    let mut pic = PocketIcBuilder::new()
        .with_server_url(server_url)
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let _ = pic.make_live(None);

    send_signal_to_pic(pic, child, Some(shutdown_signal));
}

#[test]
fn kill_gateway_with_sigint() {
    kill_gateway_with_signal(Signal::SIGINT);
}

#[test]
fn kill_gateway_with_sigterm() {
    kill_gateway_with_signal(Signal::SIGTERM);
}

/// Tests that HTTP gateway can handle requests with IP address hosts.
#[test]
fn test_gateway_ip_addr_host() {
    // Create PocketIC instance with one NNS subnet and one app subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a canister on the app subnet.
    pic.create_canister_on_subnet(None, None, app_subnet);

    let mut endpoint = pic.make_live(None);
    endpoint
        .set_ip_host(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        .unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let metrics = agent.read_state_subnet_metrics(app_subnet).await.unwrap();
        assert_eq!(metrics.num_canisters, 1);
    })
}

#[test]
fn test_unresponsive_gateway_backend() {
    let client = Client::new();

    // Create PocketIC instance with one NNS subnet and one app subnet.
    let (backend_server_url, mut backend_process) = start_server_helper(None, None, false, false);
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_server_url(backend_server_url.clone())
        .build();

    // Create HTTP gateway on a different gateway server.
    let (gateway_server_url, _) = start_server_helper(None, None, false, false);
    let create_gateway_endpoint = gateway_server_url.join("http_gateway").unwrap();
    let backend_instance_url = backend_server_url
        .join(&format!("instances/{}/", pic.instance_id()))
        .unwrap();
    let http_gateway_config = HttpGatewayConfig {
        ip_addr: None,
        port: None,
        forward_to: HttpGatewayBackend::Replica(backend_instance_url.to_string()),
        domains: None,
        https_config: None,
    };
    let res = client
        .post(create_gateway_endpoint)
        .json(&http_gateway_config)
        .send()
        .unwrap()
        .json::<CreateHttpGatewayResponse>()
        .unwrap();
    let endpoint = match res {
        CreateHttpGatewayResponse::Created(info) => {
            let port = info.port;
            Url::parse(&format!("http://localhost:{}/", port)).unwrap()
        }
        CreateHttpGatewayResponse::Error { message } => {
            panic!("Failed to crate http gateway: {}", message)
        }
    };

    // Query the status endpoint via HTTP gateway.
    let resp = client
        .get(endpoint.join("api/v2/status").unwrap())
        .send()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Kill the backend server, but keep the HTTP gateway running.
    drop(pic);
    backend_process.kill().unwrap();

    // Query the status endpoint via HTTP gateway again.
    let resp = client
        .get(endpoint.join("api/v2/status").unwrap())
        .send()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let page = String::from_utf8(resp.bytes().unwrap().as_ref().to_vec()).unwrap();
    assert!(page.contains("error: upstream_error"));
}

#[test]
fn test_invalid_gateway_backend() {
    // Create HTTP gateway with an invalid backend URL
    let (gateway_server_url, _) = start_server_helper(None, None, false, false);
    let create_gateway_endpoint = gateway_server_url.join("http_gateway").unwrap();
    let backend_url = "http://240.0.0.0";
    let http_gateway_config = HttpGatewayConfig {
        ip_addr: None,
        port: None,
        forward_to: HttpGatewayBackend::Replica(backend_url.to_string()),
        domains: None,
        https_config: None,
    };
    let client = Client::new();
    let res = client
        .post(create_gateway_endpoint)
        .json(&http_gateway_config)
        .send()
        .unwrap()
        .json::<CreateHttpGatewayResponse>()
        .unwrap();
    match res {
        CreateHttpGatewayResponse::Created(_info) => {
            panic!("Suceeded to create http gateway!")
        }
        CreateHttpGatewayResponse::Error { message } => {
            assert!(message.contains(&format!("Timed out fetching root key from {}", backend_url))
            || message.contains(&format!("An error happened during communication with the replica: error sending request for url ({}/api/v2/status)", backend_url)));
        }
    };
}

#[test]
fn http_gateway_route_underscore() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let gateway = pic.make_live(None);

    let client = Client::new();

    // Requests to paths starting with `/_/dashboard` and `/_/topology` are routed directly to the PocketIC instance/replica.

    let dashboard_url = gateway.join("_/dashboard").unwrap().to_string();
    let dashboard = client.get(dashboard_url).send().unwrap();
    let page = String::from_utf8(dashboard.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains("<h1>PocketIC Dashboard</h1>"));

    let topology_url = gateway.join("_/topology").unwrap().to_string();
    let topology_bytes = client.get(topology_url).send().unwrap();
    let topology_json = String::from_utf8(topology_bytes.bytes().unwrap().to_vec()).unwrap();
    let topology: Topology = serde_json::from_str(&topology_json).unwrap();
    assert_eq!(topology.get_app_subnets().len(), 1);

    // If a canister ID can be found,
    // then the HTTP gateway tries to handle the request
    // (which fails because the canister does not exist).

    for invalid_suffix in [
        "_/foo?canisterId=rwlgt-iiaaa-aaaaa-aaaaa-cai",
        "foo?canisterId=rwlgt-iiaaa-aaaaa-aaaaa-cai",
    ] {
        let invalid_url = gateway.join(invalid_suffix).unwrap().to_string();
        let error_page = client.get(invalid_url).send().unwrap();
        let page = String::from_utf8(error_page.bytes().unwrap().to_vec()).unwrap();
        assert!(page.contains("404 - canister not found"));
    }

    // If no canister ID can be found,
    // then the HTTP gateway complains that it could not find a canister ID.

    let invalid_url = gateway.join("_/foo").unwrap().to_string();
    let error_page = client.get(invalid_url).send().unwrap();
    assert_eq!(error_page.status(), StatusCode::BAD_REQUEST);
    let page = String::from_utf8(error_page.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains("400 - canister id not resolved"));

    let invalid_url = gateway.join("foo").unwrap().to_string();
    let error_page = client.get(invalid_url).send().unwrap();
    assert_eq!(error_page.status(), StatusCode::BAD_REQUEST);
    let page = String::from_utf8(error_page.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains("400 - canister id not resolved"));
}

fn create_gateway(
    server_url: Url,
    port: Option<u16>,
    forward_to: HttpGatewayBackend,
) -> Result<u16, String> {
    let endpoint = server_url.join("http_gateway").unwrap();
    let http_gateway_config = HttpGatewayConfig {
        ip_addr: None,
        port,
        forward_to,
        domains: None,
        https_config: None,
    };
    let res = reqwest::blocking::Client::new()
        .post(endpoint)
        .json(&http_gateway_config)
        .send()
        .expect("HTTP failure")
        .json::<CreateHttpGatewayResponse>()
        .expect("Could not parse response for create HTTP gateway request");
    match res {
        CreateHttpGatewayResponse::Created(info) => Ok(info.port),
        CreateHttpGatewayResponse::Error { message } => Err(message),
    }
}

#[test]
fn test_gateway_address_in_use() {
    let (server_url, _) = start_server_helper(None, None, false, false);

    // create PocketIC instance
    let pic = PocketIcBuilder::new()
        .with_server_url(server_url.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // create an HTTP gateway at an arbitrary port
    let port = create_gateway(
        server_url.clone(),
        None,
        HttpGatewayBackend::PocketIcInstance(pic.instance_id()),
    )
    .unwrap();

    // try to create another HTTP gateway at the same port
    let err = create_gateway(
        server_url,
        Some(port),
        HttpGatewayBackend::PocketIcInstance(pic.instance_id()),
    )
    .unwrap_err();
    assert!(err.contains(&format!(
        "Failed to bind to address 127.0.0.1:{}: Address already in use",
        port
    )));
}
