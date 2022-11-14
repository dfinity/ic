use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env_api::{HasTopologySnapshot, IcNodeContainer, RetrieveIpv4Addr};
use crate::driver::universal_vm::*;
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::util::{self, create_and_install};
use canister_test::Canister;
use canister_test::Runtime;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
pub use ic_types::{CanisterId, PrincipalId};
use slog::info;
use std::fs;
use std::net::Ipv6Addr;
use std::time::Duration;

pub const UNIVERSAL_VM_NAME: &str = "httpbin";
pub const EXPIRATION: Duration = Duration::from_secs(120);
pub const BACKOFF_DELAY: Duration = Duration::from_secs(5);

const CA_ROOT: &str = "
-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIIfdwd7TYMCCkwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVbWluaWNhIHJvb3QgY2EgN2RkYzFkMCAXDTIyMDYyODIxMDAxOVoYDzIxMjIw
NjI4MjEwMDE5WjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSA3ZGRjMWQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDF5HCazG92S/PJBPqOQnxP3/Ti
tSRv2kFc+LNRm3wEGVueVrktkqvt2A2wLD665YATFzubsAMd+mTHP1Mihv2NfN2N
95R0CHXcMkV1G+eqYlZ4cZqEO1Z+WwtrZ3N2k/KICPEHTlsaB984DDz3iz1jmyO4
oshnDEup2cHpNxHHju5H4Lilsc7lO77iLR91YxZ4bDqHj9NCCvYk4H/4k2kKTj5Z
B1ufnY0Pxre2LO2DwSVFRU3ViCdYE+3y1pVHk3ZARuYAiw94C03SaThCqtMConVW
hH1BdsvhHu5G1MMpImvWr461zQznIe3lki/mo9rRLUsCsRDebMJTetsVTX7RAgMB
AAGjgYYwgYMwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQQK5SoJdlP+3f4
LMg/f3s4BxhlgzAfBgNVHSMEGDAWgBQQK5SoJdlP+3f4LMg/f3s4BxhlgzANBgkq
hkiG9w0BAQsFAAOCAQEATiBesgZbQgXShaL9jFuwn//O9i0gClgRc4/QWDFxzwPy
HrHcpzOV97VLuYZ/bAROGDd+9kdvRd+m8/SKHuFl626LdCSne/MJ0u+jtCfqJJU6
DVBvn+2WWx2t25xuhHXTuKYrq6Eg5MtQsE7XbzYCgg3gpENf1wWjpEetmR7byrJ6
ypaYPJ6kR/LRQAxhXOs3fK+2QkoJxNeulLUrAD35/DHJemPT5MiQd44rd2P2FMJr
Y9z+Xfy5b87JC97Cn8bcUqeUtpKRv3Vkzu7lm1aH2+HTs1KwR8QPOHzsyB/d2UUO
+e6SF6GSf544d3UGyNVJsvKnUkJf61t/Ar/IqIfFGA==
-----END CERTIFICATE-----
";

const CA_ROOT_KEY: &str = "
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxeRwmsxvdkvzyQT6jkJ8T9/04rUkb9pBXPizUZt8BBlbnla5
LZKr7dgNsCw+uuWAExc7m7ADHfpkxz9TIob9jXzdjfeUdAh13DJFdRvnqmJWeHGa
hDtWflsLa2dzdpPyiAjxB05bGgffOAw894s9Y5sjuKLIZwxLqdnB6TcRx47uR+C4
pbHO5Tu+4i0fdWMWeGw6h4/TQgr2JOB/+JNpCk4+WQdbn52ND8a3tiztg8ElRUVN
1YgnWBPt8taVR5N2QEbmAIsPeAtN0mk4QqrTAqJ1VoR9QXbL4R7uRtTDKSJr1q+O
tc0M5yHt5ZIv5qPa0S1LArEQ3mzCU3rbFU1+0QIDAQABAoIBACH5FMfOfvgtE94X
x7fyfAruZMki1e2J55zBaW+CJOlDPTJSqxnCy1datwbeoapOSg18+JPCxNY5rWFz
Yp9T02Wd4R9FOKwu46T40GnJb50VosisoB1BXpj0omI+8ViTD5kBB/f8ILG4Vj72
AuVwdwqJkLla4NKoDrlLE/oopRnAB1aJ4k0lkELMmL50IkjkhSmXGOs61lIt/lRn
qgilRFX83zUf+RG4DEtwocxnvTv5yaYvZ7fsTmdTMf6gZk92xBtp4fDH/5Z4ucvR
p1bje1F1ZvCNkmVLMd+93THhXpGnREi1MJpsC3oI0GO+5dPNCvpaofwxBQW8iqry
ijVVyO0CgYEA9r7f2ElykucYxagqNFamu9r9Y4ujz3bimLghCG6ZqST9ijq015FB
x5LGsDYPM5M8wkCCpPZpDIC0/cQZDh79pIDgeeoiei771+xO0sXQwCap+NGnLCPS
OdpIqzHgpKC+NGbbNw9a03TaMccURUus3R8PtiQ+DrVGAWtv0aEji+cCgYEAzVCA
WGhDkizDCEP68Bo8KMg/y/DwAcSknELQNBz6tKZUKF3HH4+M5WCsczzSWiGBRzEP
bqkao0HSLXY+5+6y0Sy7JfgC3dAeRFoc9seIc7jvw0LA/WiaMOSwmzwfUWi+u0V5
b1hurVnhvm1fL6V62k4Tvojfg+JaMKkf93VkiIcCgYEAyQrgrAO8HMG6x2GrcZWg
qLNXfgJK6EE/g5uTHqGvBcgj5LrMmk+6Pvfyd6S0Yht3h/az++Dh2tQLpDBhEcZi
d+SiAfOpP9CEVnwuBUI0Qju+hgOcqDRPl9+pEgPDu59VGrErsAMMx/oPxjsk4wkz
wb8LOCbzgVxlu8ZkB3O52MUCgYA7SP+Gh7TbRKmcfWS8aBbu/8PMM+pZ2Fpf9LsC
EUwjVdP/Q/T3nA/nPB8Pt4RWGk6mK/h0z8etVJhIIFjRyA9Cb1QrBo5tVmcm/Y5X
hA5WvBQfoerwQYAkliSY7qdsbn6EvO7vw+1RiR6ySgquS25KEzmITyWbg4TfgDaG
0hMRiQKBgANPaPcb1Fe5g4o4ORxlKkvue6fHkUkpjSoO27bjiNWXZwKxp2dOVoQo
Bm1zzKM2Xx7M7y4/F3bkK5tyFhsfEJ0qyDujWXsqeJS1CsELEfD460BmVRb1Ij65
mrqGpnFXHV4xz5FqtPpCX7KBozwJWJr+D4EfIY4ik2Qvpw2OiCQL
-----END RSA PRIVATE KEY-----
";

pub enum PemType {
    PemCert,
    PemKey,
}

pub fn get_universal_vm_activation_script() -> String {
    fs::read_to_string("src/canister_http/universal_vm_activation.sh").expect("File not found")
}

pub fn await_nodes_healthy(env: &TestEnv) {
    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn install_nns_canisters(env: &TestEnv) {
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");
    info!(&env.logger(), "NNS canisters installed");
}

pub fn config(env: TestEnv) {
    // Set up Universal VM with HTTP Bin testing service
    let activate_script = &get_universal_vm_activation_script()[..];
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();
    let _ = insert_file_to_config(
        config_dir.clone(),
        "cert.pem",
        get_pem_content(&PemType::PemCert).as_bytes(),
    );
    let _ = insert_file_to_config(
        config_dir.clone(),
        "key.pem",
        get_pem_content(&PemType::PemKey).as_bytes(),
    );

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(&env)
        .expect("failed to set up universal VM");

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_features(SubnetFeatures {
                    http_requests: true,
                    ..SubnetFeatures::default()
                })
                .add_nodes(3),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    await_nodes_healthy(&env);
    install_nns_canisters(&env);
}

pub fn get_pem_content(typ: &PemType) -> String {
    match typ {
        PemType::PemCert => CA_ROOT.to_string(),
        PemType::PemKey => CA_ROOT_KEY.to_string(),
    }
}

pub fn get_universal_vm_address(env: &TestEnv) -> Ipv6Addr {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let universal_vm = deployed_universal_vm.get_vm().unwrap();
    let webserver_ipv6: Ipv6Addr = universal_vm.ipv6;
    info!(&env.logger(), "Webserver has IPv6 {:?}", webserver_ipv6);
    let webserver_ipv4 = deployed_universal_vm
        .block_on_ipv4()
        .expect("Universal VM IPv4 not found.");
    info!(&env.logger(), "Webserver has IPv4 {:?}", webserver_ipv4);
    webserver_ipv6
}

pub fn get_node_snapshots(env: &TestEnv) -> Box<dyn Iterator<Item = IcNodeSnapshot>> {
    env.topology_snapshot()
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet")
        .nodes()
}

pub fn get_runtime_from_node(node: &IcNodeSnapshot) -> Runtime {
    util::runtime_from_url(node.get_public_url())
}

pub fn create_proxy_canister<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    node: &IcNodeSnapshot,
) -> Canister<'a> {
    info!(&env.logger(), "Installing proxy_canister.");

    // Create proxy canister with maximum canister cycles.
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let proxy_canister_id = rt.block_on(create_and_install(
        &node.build_default_agent(),
        node.effective_canister_id(),
        &env.load_wasm("rs/rust_canisters/proxy_canister/proxy_canister.wasm"),
    ));
    info!(
        &env.logger(),
        "proxy_canister {} installed", proxy_canister_id
    );
    Canister::new(
        runtime,
        CanisterId::new(PrincipalId::from(proxy_canister_id)).unwrap(),
    )
}
