use crate::common::{send_signal_to_pic, start_server, start_server_helper};
use candid::{Encode, Principal};
use nix::sys::signal::Signal;
use pocket_ic::common::rest::{
    CreateHttpGatewayResponse, HttpGatewayBackend, HttpGatewayConfig, HttpGatewayDetails,
    HttpsConfig, Topology,
};
use pocket_ic::{PocketIc, PocketIcBuilder};
use rcgen::{CertificateParams, KeyPair};
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header;
use reqwest::{Client as NonblockingClient, StatusCode};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tempfile::NamedTempFile;

mod common;

fn deploy_ii(pic: &PocketIc) -> Principal {
    let canister_id = pic.create_canister();
    let ii_path = std::env::var_os("II_WASM").expect("Missing II_WASM (path to II wasm) in env.");
    let ii_wasm = std::fs::read(ii_path).expect("Could not read II wasm file.");
    pic.add_cycles(canister_id, 1_000_000_000_000);
    let arg = Encode!(&()).unwrap();
    pic.install_canister(canister_id, ii_wasm, arg, None);
    canister_id
}

async fn deploy_ii_async(pic: &pocket_ic::nonblocking::PocketIc) -> Principal {
    let canister_id = pic.create_canister().await;
    let ii_path = std::env::var_os("II_WASM").expect("Missing II_WASM (path to II wasm) in env.");
    let ii_wasm = std::fs::read(ii_path).expect("Could not read II wasm file.");
    pic.add_cycles(canister_id, 1_000_000_000_000).await;
    let arg = Encode!(&()).unwrap();
    pic.install_canister(canister_id, ii_wasm, arg, None).await;
    canister_id
}

// Test the server endpoint to list HTTP gateways and the following HTTP gateway endpoints:
// - http://127.0.0.1:<port>/?canisterId=<canister-id>
// - http(s)://localhost:<port>/?canisterId=<canister-id>
// - http(s)://<canister-id>.localhost:<port>
// - http(s)://<canister-id>.raw.localhost:<port>
// - http(s)://<canister-id>.example.com:<port>
// - http(s)://<canister-id>.raw.example.com:<port>
// and the following referer headers:
// - http(s)://<canister-id>.localhost:<port>
// - http(s)://<canister-id>.raw.localhost:<port>
// - http(s)://localhost:<port>/?canisterId=<canister-id>

async fn test_gateway(server_url: Url, https: bool) {
    // Create a PocketIC instance.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // Deploy II onto that instance.
    let canister_id = deploy_ii_async(&pic).await;

    // define HTTP protocol for this test
    let proto = if https { "https" } else { "http" };

    // define two domains for canister ID resolution
    let localhost = "localhost";
    let sub_localhost = &format!("{canister_id}.{localhost}");
    let sub_raw_localhost = &format!("{canister_id}.raw.{localhost}");
    let alt_domain = "example.com";
    let sub_alt_domain = &format!("{canister_id}.{alt_domain}");
    let sub_raw_alt_domain = &format!("{canister_id}.raw.{alt_domain}");

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
    let bind_address = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let port = pic
        .make_live_with_params(
            Some(bind_address),
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
        builder = builder.resolve(domain, SocketAddr::new(bind_address, port));
    }
    // add a custom root certificate
    if https {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(root_cert.pem().as_bytes()).unwrap(),
        );
    }
    let client = builder.build().unwrap();

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
    let canister_url = format!("{proto}://{localhost}:{port}/?canisterId={canister_id}");
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.localhost:<port>
    let canister_url = format!("{proto}://{canister_id}.{localhost}:{port}");
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.raw.localhost:<port>
    let canister_url = format!("{proto}://{canister_id}.raw.{localhost}:{port}");
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.example.com:<port>
    let canister_url = format!("{proto}://{canister_id}.{alt_domain}:{port}");
    test_urls.push(canister_url);

    // perform frontend asset request for the title page at http(s)://<canister-id>.raw.example.com:<port>
    let canister_url = format!("{proto}://{canister_id}.raw.{alt_domain}:{port}");
    test_urls.push(canister_url.clone());

    for url in test_urls {
        let res = client.get(url).send().await.unwrap();
        let page = String::from_utf8(res.bytes().await.unwrap().to_vec()).unwrap();
        assert!(page.contains("<title>Internet Identity</title>"));
    }

    // infer canister ID from the referer header
    let mut test_referers = vec![];

    // perform request where canister ID is specified in the referer header host
    let referer_url = format!("{proto}://{canister_id}.{localhost}:{port}");
    test_referers.push(referer_url);

    let referer_url = format!("{proto}://{canister_id}.raw.{localhost}:{port}");
    test_referers.push(referer_url);

    // perform request where canister ID is specified in the referer header query parameters
    let referer_url = format!("{proto}://{localhost}:{port}/?canisterId={canister_id}");
    test_referers.push(referer_url);

    let test_url = format!("{proto}://{localhost}:{port}");

    for referer in test_referers {
        // perform request where canister ID is specified in the referer header
        let res = client
            .get(&test_url)
            .header(header::REFERER, referer)
            .send()
            .await
            .unwrap();
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

// Test that the HTTP gateway exits gracefully upon receiving a signal.

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

// Test that the HTTP gateway handles `/_/dashboard` and `/_/topology` correctly.

#[test]
fn http_gateway_route_underscore() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let gateway = pic.make_live(None);

    let client = Client::new();

    let dashboard_url = gateway.join("_/dashboard").unwrap().to_string();
    let dashboard = client.get(dashboard_url).send().unwrap();
    let page = String::from_utf8(dashboard.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains("<h1>PocketIC Dashboard</h1>"));

    let topology_url = gateway.join("_/topology").unwrap().to_string();
    let topology_bytes = client.get(topology_url).send().unwrap();
    let topology_json = String::from_utf8(topology_bytes.bytes().unwrap().to_vec()).unwrap();
    let topology: Topology = serde_json::from_str(&topology_json).unwrap();
    assert_eq!(topology.get_app_subnets().len(), 1);
}

// Test that the HTTP reports the expected error if canister does not exist.

#[test]
fn http_gateway_canister_not_found() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let gateway = pic.make_live(None);

    let client = Client::new();

    for path in [
        "_/foo?canisterId=rwlgt-iiaaa-aaaaa-aaaaa-cai",
        "foo?canisterId=rwlgt-iiaaa-aaaaa-aaaaa-cai",
    ] {
        let invalid_url = gateway.join(path).unwrap().to_string();
        let error_page = client.get(invalid_url).send().unwrap();
        assert_eq!(error_page.status(), StatusCode::NOT_FOUND);
    }
}

// Test that the HTTP reports the expected error if canister id could not be resolved.

#[test]
fn http_gateway_missing_canister_id() {
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let gateway = pic.make_live(None);

    let client = Client::new();

    for path in ["_/foo", "foo"] {
        let invalid_url = gateway.join(path).unwrap().to_string();
        let error_page = client.get(invalid_url).send().unwrap();
        assert_eq!(error_page.status(), StatusCode::BAD_REQUEST);
    }
}

// Test that the HTTP gateway can handle `/api` requests with an IP address as the host.

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

    // Start an HTTP gateway and override its host to `127.0.0.1`.
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

// Test that the HTTP gateway fails gracefully in case of an unresponsive backend.

#[test]
fn test_unresponsive_gateway_backend() {
    let client = Client::new();

    // Start a private server instance.
    let (backend_server_url, mut backend_process) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance on that server instance.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_server_url(backend_server_url.clone())
        .build();

    // Deploy II onto that instance.
    let canister_id = deploy_ii(&pic);

    // Enable auto progress for asset certification to work.
    pic.auto_progress();

    // Create an HTTP gateway on a different (private) server instance.
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
            Url::parse(&format!("http://localhost:{port}/")).unwrap()
        }
        CreateHttpGatewayResponse::Error { message } => {
            panic!("Failed to create http gateway: {message}")
        }
    };

    // Query a few endpoints on the HTTP gateway:
    // - a custom dashboard endpoint (handled by the PocketIC server);
    // - an /api endpoint (proxied by `ic-gateway`);
    // - an asset endpoint (handled by `ic-http-gateway`).
    let paths = vec![
        "_/dashboard".to_string(),
        "api/v2/status".to_string(),
        format!("favicon.ico?canisterId={}", canister_id),
    ];
    for path in &paths {
        let resp = client.get(endpoint.join(path).unwrap()).send().unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Kill the backend server, but keep the HTTP gateway running.
    drop(pic);
    backend_process.kill().unwrap();

    // Query the endpoints again.
    for path in &paths {
        let resp = client.get(endpoint.join(path).unwrap()).send().unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

// Test that trying to bind the HTTP gateway to an invalid backend fails gracefully.

#[test]
fn test_gateway_invalid_forward_to() {
    // Start a private server instance.
    let (server_url, _) = start_server_helper(None, None, false, false);

    let invalid_backend_url = "http://240.0.0.0";
    let invalid_instance_id = 42;
    for (forward_to, expected_err) in [
        (
            HttpGatewayBackend::Replica(invalid_backend_url.to_string()),
            "error: upstream_error",
        ),
        (
            HttpGatewayBackend::PocketIcInstance(invalid_instance_id),
            "Instance not found",
        ),
    ] {
        let http_gateway_config = HttpGatewayConfig {
            ip_addr: None,
            port: None,
            forward_to,
            domains: None,
            https_config: None,
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(300)) // same as bazel test timeout for this test
            .build()
            .unwrap();
        let create_gateway_endpoint = server_url.join("http_gateway").unwrap();
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
                assert!(message.contains(expected_err));
            }
        };
    }
}

// Test that trying to bind the HTTP gateway to the same port twice fails gracefully.

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
    // Start a private server instance.
    let (server_url, _) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance on that server.
    let pic = PocketIcBuilder::new()
        .with_server_url(server_url.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Create an HTTP gateway at an arbitrary port.
    let port = create_gateway(
        server_url.clone(),
        None,
        HttpGatewayBackend::PocketIcInstance(pic.instance_id()),
    )
    .unwrap();

    // Trying to create another HTTP gateway at the same port fails.
    let err = create_gateway(
        server_url,
        Some(port),
        HttpGatewayBackend::PocketIcInstance(pic.instance_id()),
    )
    .unwrap_err();
    assert!(err.contains(&format!(
        "Failed to bind to address 127.0.0.1:{port}: Address already in use"
    )));
}
