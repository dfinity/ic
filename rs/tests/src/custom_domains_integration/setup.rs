use certificate_orchestrator_interface::InitArg;
use ic_system_test_driver::{
    driver::{
        asset_canister::{DeployAssetCanister, UploadAssetRequest},
        boundary_node::{
            BoundaryNode, BoundaryNodeCustomDomainsConfig, BoundaryNodeSnapshot, BoundaryNodeVm,
        },
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
            IcNodeContainer, NnsInstallationBuilder, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
        universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms},
    },
    util::{agent_observes_canister_module, block_on},
};

use serde_json::json;
use std::{env, io::Read, net::SocketAddrV6, time::Duration};

use anyhow::{anyhow, Context, Error};
use candid::{Encode, Principal};
use chacha20poly1305::{aead::OsRng as ChaChaOsRng, KeyInit, XChaCha20Poly1305};
use ic_agent::{identity::Secp256k1Identity, Identity};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use k256::{elliptic_curve::SecretKey, Secp256k1};
use pem::Pem;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use reqwest::{redirect::Policy, Client, ClientBuilder};
use tokio::task::{self, JoinHandle};

pub(crate) const CLOUDFLARE_API_PYTHON_PATH: &str = "/config/cloudflare_api.py";
pub(crate) const PEBBLE_CACHE_PYTHON_PATH: &str = "/config/pebble_cache.py";

pub(crate) const BOUNDARY_NODE_VM_ID: &str = "boundary-node-1";
pub(crate) const REMOTE_DOCKER_HOST_VM_ID: &str = "docker-host";

pub(crate) const ACME_PROVIDER_PORT: u16 = 14001;
pub(crate) const CLOUDFLARE_API_PORT: u16 = 8001;
pub(crate) const NAME_SERVER_PORT: u16 = 5053;

pub(crate) const DELEGATION_DOMAIN: &str = "domains.example.com";

async fn flatten<T>(handle: JoinHandle<Result<T, Error>>) -> Result<T, Error> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(err.into()),
    }
}

pub fn setup(env: TestEnv) {
    block_on(async {
        let (_, remote_docker_host) = tokio::try_join!(
            flatten(task::spawn(
                // IC Testnet
                setup_ic_testnet(env.clone()),
            )),
            flatten(task::spawn(
                // Remote Docker Host
                setup_remote_docker_host(env.clone(), &["coredns", "pebble", "python3", "openssl"])
            )),
        )?;

        // Certificates (CA)
        let ca_pair = generate_ca_certificate_pair(&remote_docker_host)
            .await
            .context("failed to generate ca certificate")?;

        // Certificates (Pebble)
        let pebble_pair = generate_leaf_certificate_pair(&remote_docker_host, &ca_pair, "acme")
            .await
            .context("failed to generate pebble certificate")?;

        // Certificates (Nginx)
        let nginx_pair = generate_leaf_certificate_pair(&remote_docker_host, &ca_pair, "ic0.app")
            .await
            .context("failed to generate nginx certificate")?;

        // CoreDNS + Cloudflare API Work Directory
        let work_dir = exec_ssh_mktemp(&remote_docker_host, MkTempMode::Dir)?;

        // CoreDNS
        setup_coredns(&remote_docker_host, NAME_SERVER_PORT, &work_dir).await?;

        // Cloudflare API
        setup_mock_cloudflare_api(&remote_docker_host, CLOUDFLARE_API_PORT, &work_dir).await?;

        // Pebble + Pebble Cache Work Directory
        let work_dir = exec_ssh_mktemp(&remote_docker_host, MkTempMode::Dir)?;

        // Pebble
        setup_pebble(&remote_docker_host, &pebble_pair, &work_dir).await?;

        // Pebble Cache
        setup_pebble_cache_shim(&remote_docker_host, ACME_PROVIDER_PORT, &work_dir).await?;

        // Certificate Orchestartor
        let (_root_key, root_identity) = {
            let mut rng = ChaChaRng::from_rng(OsRng).expect("failed to initialize rng");
            let key = SecretKey::random(&mut rng);
            (key.clone(), Secp256k1Identity::from_private_key(key))
        };

        let (issuer_key, issuer_identity) = {
            let mut rng = ChaChaRng::from_rng(OsRng).expect("failed to initialize rng");
            let key = SecretKey::random(&mut rng);
            (key.clone(), Secp256k1Identity::from_private_key(key))
        };

        let (orchestrator_canister_id,) = tokio::try_join!(flatten(task::spawn({
            let (root_principals, allowed_principals) = (
                vec![root_identity.sender().unwrap()],
                vec![issuer_identity.sender().unwrap()],
            );

            setup_certificate_orchestartor(
                env.clone(),
                root_identity,
                root_principals,
                allowed_principals,
            )
        })))?;

        // Boundary Node
        let remote_docker_host_ip = remote_docker_host.get_vm()?.ipv6;

        let boundary_node = setup_boundary_node(
            env,                                                         // env
            &format!("{remote_docker_host_ip}"),                         // name_server_ip
            NAME_SERVER_PORT,                                            // name_server_port
            &format!("acme:{ACME_PROVIDER_PORT}"),                       // acme_server_addr
            &format!("[{remote_docker_host_ip}]:{CLOUDFLARE_API_PORT}"), // cloudflare_api_addr
            &orchestrator_canister_id,
            issuer_key,
        )
        .await?;

        // Disable read-only filesystem
        disable_read_only_filesystem(&boundary_node)
            .await
            .context("failed to disable read-only filesystem")?;

        // Update nftables
        update_nftables_allow_egress(
            &boundary_node,
            &[
                ACME_PROVIDER_PORT,  // acme
                CLOUDFLARE_API_PORT, // cloudflare
            ],
            &[
                NAME_SERVER_PORT, // dns
            ],
        )
        .await?;

        // Install self-signed certificates (pebble and nginx)
        configure_boundary_node_trust_certificate(&boundary_node, &ca_pair.certificate).await?;

        // Update Nginx TLS Certificates
        update_nginx_tls_certificate(&boundary_node, &nginx_pair).await?;

        // Update /etc/hosts on Boundary Node
        update_etc_hosts(&boundary_node, "ic0.app", &boundary_node.ipv6().to_string()).await?;
        update_etc_hosts(&boundary_node, "acme", &remote_docker_host_ip.to_string()).await?;

        // Restart Certificate-Issuer
        exec_ssh_restart_service(&boundary_node, "certificate-issuer")?;

        Ok::<(), Error>(())
    })
    .expect("failed to run tasks");
}

async fn setup_ic_testnet(env: TestEnv) -> Result<(), Error> {
    let log = env.logger();
    slog::info!(&log, "setting up ic testnet");

    task::spawn_blocking({
        let env = env.clone();
        move || {
            InternetComputer::new()
                .add_fast_single_node_subnet(SubnetType::System)
                .add_fast_single_node_subnet(SubnetType::Application)
                .setup_and_start(&env)
                .context("failed to setup IC under test")
        }
    })
    .await
    .expect("failed to spawn task")?;

    slog::info!(&log, "done setting up ic testnet");

    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .context("node failed to become healthy")?;
        }
    }

    // NNS Canisters
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .context("failed to retrieve first NNS node")?;

    slog::info!(&log, "installing canisters");
    slog::info!(&log, "installing canisters");
    task::spawn_blocking(move || {
        NnsInstallationBuilder::new()
            .install(&nns_node, &env)
            .context("could not install NNS canisters")
    })
    .await
    .expect("failed to spawn task")?;
    slog::info!(&log, "done installing canisters");

    Ok(())
}

async fn setup_remote_docker_host(
    env: TestEnv,
    images: &[&str],
) -> Result<DeployedUniversalVm, Error> {
    task::spawn_blocking({
        let env = env.clone();
        move || {
            UniversalVm::new(REMOTE_DOCKER_HOST_VM_ID.into())
                .with_config_img(
                    env.get_dependency_path("rs/tests/custom_domains_uvm_config_image.zst"),
                )
                .start(&env)
                .context("failed to setup universal VM")
        }
    })
    .await
    .expect("failed to spawn task")?;

    let vm = env
        .get_deployed_universal_vm(REMOTE_DOCKER_HOST_VM_ID)
        .context("failed to get deployed universal vm")?;

    // Wait for UVM
    for image in images {
        wait_for_docker_image(&vm, image, Duration::from_secs(30))
            .await
            .context("failed to wait for docker image")?;
    }

    Ok(vm)
}

async fn setup_coredns(vm: &dyn SshSession, port: u16, work_dir: &str) -> Result<(), Error> {
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Ensuring Docker network acme exists"
        if ! docker network inspect acme >/dev/null 2>&1; then
            docker network create acme
        fi

        echo "--> Setting up Zones directory"
        if ! ls "{work_dir}/zones"; then
            mkdir -p "{work_dir}/zones"
        fi

        echo "--> Creating empty Corefile"
        if ! ls "{work_dir}/Corefile"; then
            touch "{work_dir}/Corefile"
        fi

        echo "--> Start CoreDNS"
        docker run \
            -d \
            --name coredns \
            --network acme \
            -p {port}:53 \
            -p {port}:53/udp \
            -v {work_dir}/Corefile:/Corefile:ro \
            -v {work_dir}/zones:/zones:ro \
            coredns \
                -conf /Corefile
    "#})?;

    Ok(())
}

async fn setup_mock_cloudflare_api(
    vm: &dyn SshSession,
    port: u16,
    work_dir: &str,
) -> Result<(), Error> {
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Ensuring Docker network acme exists"
        if ! docker network inspect acme >/dev/null 2>&1; then
            docker network create acme
        fi

        echo "--> Starting Cloudflare API"
        docker run \
            -d \
            --name cloudflare-api \
            --network acme \
            -p {port}:8000 \
            -v {CLOUDFLARE_API_PYTHON_PATH}:/main.py:ro \
            -v {work_dir}/Corefile:/Corefile \
            -v {work_dir}/zones:/zones \
            -v /var/run/docker.sock:/var/run/docker.sock \
            python3 \
                python /main.py
    "#})?;

    Ok(())
}

async fn setup_pebble(
    vm: &dyn SshSession,
    pair: &CertificatePair,
    work_dir: &str,
) -> Result<(), Error> {
    let CertificatePair {
        key,
        certificate: cert,
    } = pair;

    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Ensuring Docker network acme exists"
        if ! docker network inspect acme >/dev/null 2>&1; then
            docker network create acme
        fi

        echo "--> Installing pebble TLS private key"
        cat > "{work_dir}/pebble.key" <<EOF
        {key}
        EOF

        echo "--> Installing pebble TLS certificate"
        cat > "{work_dir}/pebble.crt" <<EOF
        {cert}
        EOF

        echo "--> Creating pebble-config.json"
        cat > {work_dir}/pebble-config.json <<EOF
        {{
            "pebble": {{
                "listenAddress": "0.0.0.0:14000",
                "managementListenAddress": "0.0.0.0:15000",
                "certificate": "/pebble.crt",
                "privateKey": "/pebble.key",
                "httpPort": 5002,
                "tlsPort": 5001,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": false,
                "domainBlocklist": [],
                "retryAfter": {{
                    "authz": 3,
                    "order": 5
                }}
            }}
        }}
        EOF

        docker run \
            -d \
            --name pebble \
            --network acme \
            -p 14000:14000 -p 15000:15000 \
            -e PEBBLE_VA_NOSLEEP=1 \
            -e PEBBLE_WFE_NONCEREJECT=0 \
            -v {work_dir}/pebble-config.json:/pebble-config.json:ro \
            -v {work_dir}/pebble.key:/pebble.key:ro \
            -v {work_dir}/pebble.crt:/pebble.crt:ro \
            pebble pebble \
                -config /pebble-config.json \
                -dnsserver coredns:53
    "#})?;

    Ok(())
}

async fn setup_pebble_cache_shim(
    vm: &dyn SshSession,
    port: u16,
    work_dir: &str,
) -> Result<(), Error> {
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        PYTHON_SCRIPT_BASE64='<PYTHON_SCRIPT_BASE64>'

        echo "--> Ensuring Docker network acme exists"
        if ! docker network inspect acme >/dev/null 2>&1; then
            docker network create acme
        fi

        echo "--> Starting Pebble Cache Shim"
        docker run \
            -d \
            --name pebble-cache \
            --network acme \
            -p {port}:{port} \
            -v {PEBBLE_CACHE_PYTHON_PATH}:/main.py:ro \
            -v {work_dir}/pebble.key:/pebble.key:ro \
            -v {work_dir}/pebble.crt:/pebble.crt:ro \
            python3 \
                python /main.py \
                    --hostname acme \
                    --port {port} \
                    --acme_host pebble \
                    --acme_port 14000 \
                    --tls_key /pebble.key \
                    --tls_cert /pebble.crt
    "#})?;

    Ok(())
}

async fn setup_certificate_orchestartor(
    env: TestEnv,
    identity: Secp256k1Identity,
    root_principals: Vec<Principal>,
    allowed_principals: Vec<Principal>,
) -> Result<String, Error> {
    // Create Canister
    let cid = task::spawn_blocking({
        let env = env.clone();
        move || {
            env.get_first_healthy_application_node_snapshot()
                .create_and_install_canister_with_arg(
                    &env::var("CERTIFICATE_ORCHESTRATOR_WASM_PATH")
                        .expect("CERTIFICATE_ORCHESTRATOR_WASM_PATH not set"),
                    Encode!(&InitArg {
                        id_seed: 0,
                        root_principals,
                        registration_expiration_ttl: None,
                        in_progress_ttl: None,
                        management_task_interval: None,
                    })
                    .ok(),
                )
        }
    })
    .await
    .expect("failed to spawn task");

    // Await Canister
    let mut agent = task::spawn_blocking({
        let env = env.clone();
        move || {
            env.get_first_healthy_application_node_snapshot()
                .build_default_agent()
        }
    })
    .await
    .expect("failed to spawn task");

    ic_system_test_driver::retry_with_msg_async!(
        format!("observing canister module {}", cid.to_string()),
        &env.logger(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match agent_observes_canister_module(&agent, &cid).await {
                true => Ok(()),
                false => Err(anyhow!("canister not ready")),
            }
        }
    )
    .await
    .expect("failed to await orchestrator to become ready");

    // Configure allowed_principals
    agent.set_identity(identity);

    for p in allowed_principals {
        let arg = Encode!(&p).context("failed to encode arg")?;
        agent
            .update(&cid, "addAllowedPrincipal")
            .with_arg(arg)
            .call_and_wait()
            .await
            .context("failed to add allowed principal")?;
    }

    Ok(cid.to_text())
}

async fn setup_boundary_node(
    env: TestEnv,
    name_server_ip: &str,
    name_server_port: u16,
    acme_server_addr: &str,
    cloudflare_api_addr: &str,
    orchestrator_canister_id: &str,
    issuer_key: SecretKey<Secp256k1>,
) -> Result<BoundaryNodeSnapshot, Error> {
    // Configure Custom Domains Feature
    let custom_domains_config = BoundaryNodeCustomDomainsConfig {
        orchestrator_uri: "https://ic0.app".into(),
        orchestrator_canister_id: orchestrator_canister_id.to_owned(),
        delegation_domain: DELEGATION_DOMAIN.into(),
        name_servers: vec![name_server_ip.to_owned()],
        name_servers_port: name_server_port,
        acme_provider_url: format!("https://{acme_server_addr}/dir"),
        cloudflare_api_url: format!("http://{cloudflare_api_addr}/client/v4/"),
        cloudflare_api_key: "cf_api_key".into(),
        issuer_identity: {
            issuer_key
                .to_sec1_pem(Default::default())
                .context("failed to convert key to pem")?
                .to_string()
        },
        issuer_encryption_key: {
            pem::encode(&Pem {
                tag: "SYMMETRIC_KEY".into(),
                contents: XChaCha20Poly1305::generate_key(&mut ChaChaOsRng).to_vec(),
            })
        },
        task_delay_sec: Some(5),
        task_error_delay_sec: Some(10),
        peek_sleep_sec: Some(5),
        polling_interval_sec: Some(1),
    };

    // Start Boundary Node
    let bn = BoundaryNode::new(BOUNDARY_NODE_VM_ID.into())
        .allocate_vm(&env)
        .context("failed to allocate boundary node vm")?
        .for_ic(&env, "")
        .with_custom_domains(custom_domains_config);

    bn.start(&env).context("failed to start boundary-node vm")?;

    // Await NNS Registry
    let registry = RegistryCanister::new(bn.nns_node_urls);

    ic_system_test_driver::retry_with_msg_async!(
        "getting routing table from registry",
        &env.logger(),
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let (bytes, _) = registry
                .get_value(
                    make_routing_table_record_key().into(), // key
                    None,                                   // version
                )
                .await
                .context("failed to get routing table from registry")?;

            let routes = PbRoutingTable::decode(bytes.as_slice())
                .context("failed to decode registry routes")?;

            RoutingTable::try_from(routes).context("failed to convert registry routes")?;

            Ok(())
        }
    )
    .await
    .context("failed to poll registry")?;

    // Await Boundary Node Readiness
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_VM_ID)
        .context("failed to get boundary node")?
        .get_snapshot()
        .context("failed to get snapshot")?;

    boundary_node
        .await_status_is_healthy()
        .context("failed to await bn healthy status")?;

    Ok(boundary_node)
}

#[derive(Debug)]
struct CertificatePair {
    key: String,
    certificate: String,
}

async fn generate_ca_certificate_pair(vm: &dyn SshSession) -> Result<CertificatePair, Error> {
    let work_dir = exec_ssh_mktemp(vm, MkTempMode::Dir)?;

    // Create CA
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Creating CA"
        docker run --rm \
            -v {work_dir}:{work_dir} -w {work_dir} \
            openssl req -x509 \
                -newkey rsa:4096 \
                -sha256 -nodes \
                -keyout ca.key -out ca.crt \
                -subj "/CN=Test CA"
    "#})?;

    // Retrieve key and certificate
    let p = CertificatePair {
        // Key
        key: exec_ssh_cat(vm, &format!("{work_dir}/ca.key"))
            .context("failed to retrieve ca key")?,

        // Certificate
        certificate: exec_ssh_cat(vm, &format!("{work_dir}/ca.crt"))
            .context("failed to retrieve ca certificate")?,
    };

    // Clean up
    exec_ssh_rm(vm, &work_dir)?;

    Ok(p)
}

async fn generate_leaf_certificate_pair(
    vm: &dyn SshSession,
    ca_pair: &CertificatePair,
    name: &str,
) -> Result<CertificatePair, Error> {
    let work_dir = exec_ssh_mktemp(vm, MkTempMode::Dir)?;

    let CertificatePair {
        key: ca_key,
        certificate: ca_crt,
    } = ca_pair;

    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Copy CA Key"
        cat > {work_dir}/ca.key <<EOF
        {ca_key}
        EOF

        echo "--> Copy CA Certificate"
        cat > {work_dir}/ca.crt <<EOF
        {ca_crt}
        EOF

        echo "--> Create CSR"
        docker run \
            --rm \
            -v {work_dir}:{work_dir} -w {work_dir} \
            openssl req \
                -newkey rsa:4096 \
                -sha256 -nodes \
                -keyout "{name}.key" \
                -out "{name}.csr" \
                -subj "/CN={name}"

        echo "--> Create OpenSSL Configuration"
        cat > "{work_dir}/{name}.ext" <<EOF
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        subjectAltName = @alt_names

        [alt_names]
        DNS.1 = {name}
        EOF

        echo "--> Sign CSR"
        docker run \
            --rm \
            -v {work_dir}:{work_dir} -w {work_dir} \
            openssl x509 -req \
                -in "{name}.csr" \
                -out "{name}.crt" \
                -CA ca.crt \
                -CAkey ca.key \
                -CAcreateserial \
                -extfile "{name}.ext"
    "#})?;

    // Retrieve key and certificate
    let p = CertificatePair {
        // Key
        key: exec_ssh_cat(vm, &format!("{work_dir}/{name}.key"))
            .context("failed to retrieve self-signed certificate key")?,

        // Certificate
        certificate: exec_ssh_cat(vm, &format!("{work_dir}/{name}.crt"))
            .context("failed to retrieve self-signed certificate")?,
    };

    // Clean up
    exec_ssh_rm(vm, &work_dir)?;

    Ok(p)
}

async fn disable_read_only_filesystem(vm: &dyn SshSession) -> Result<(), Error> {
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Disabling read-only file-system at /"
        sudo mount -o remount,rw /
    "#})?;

    Ok(())
}

async fn configure_boundary_node_trust_certificate(
    vm: &dyn SshSession,
    cert: &str,
) -> Result<(), Error> {
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Installing certificate"
        sudo bash -c 'cat > /usr/local/share/ca-certificates/ca.crt <<EOF
        {cert}
        EOF'

        echo "--> Trusting self-signed certificate"
        sudo update-ca-certificates
    "#})?;

    Ok(())
}

async fn update_etc_hosts(vm: &dyn SshSession, name: &str, ip: &str) -> Result<(), Error> {
    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Updating /etc/hosts for name: {name} and IP: {ip}"
        if [[ -z "$(grep {name} /etc/hosts)" ]]; then
            echo "{ip} {name}" | sudo tee -a /etc/hosts
        fi
    "#})?;

    Ok(())
}

async fn update_nginx_tls_certificate(
    vm: &dyn SshSession,
    pair: &CertificatePair,
) -> Result<(), Error> {
    let CertificatePair {
        key,
        certificate: cert,
    } = pair;

    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        echo "--> Installing nginx private key"
        sudo bash -c 'cat > /run/ic-node/etc/nginx/keys/privkey.pem <<EOF
        {key}
        EOF'

        echo "--> Installing nginx certificate chain"
        sudo bash -c 'cat > /run/ic-node/etc/nginx/certs/chain.pem <<EOF
        {cert}
        EOF'

        echo "--> Installing nginx full certificate chain"
        sudo bash -c 'cat > /run/ic-node/etc/nginx/certs/fullchain.pem <<EOF
        {cert}
        EOF'

        echo "--> Restarting Nginx"
        sudo nginx -s reload
    "#})?;

    Ok(())
}

async fn update_nftables_allow_egress(
    vm: &dyn SshSession,
    tcp_ports: &[u16],
    udp_ports: &[u16],
) -> Result<(), Error> {
    let tcp_ports = tcp_ports
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join(" ");

    let udp_ports = udp_ports
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join(" ");

    vm.block_on_bash_script(&indoc::formatdoc! {r#"
        set -euo pipefail

        TCP_PORTS=({tcp_ports})
        UDP_PORTS=({udp_ports})

        echo "--> Updating /etc/nftables"
        for PORT in "${{TCP_PORTS[@]}}"; do
            sudo sed -i -E "s/^(    ct state new tcp dport \{{[^\}}]*)( \}} accept)$/\1, ${{PORT}}\2/" /etc/nftables.conf
        done

        for PORT in "${{UDP_PORTS[@]}}"; do
            sudo sed -i -E "s/^(    ct state new udp dport \{{[^\}}]*)( \}} accept)$/\1, ${{PORT}}\2/" /etc/nftables.conf
        done

        echo "--> Restarting nftables"
        sudo systemctl restart nftables
    "#})?;

    Ok(())
}

fn exec_ssh_command(vm: &dyn SshSession, command: &str) -> Result<(String, i32), Error> {
    let mut channel = vm.block_on_ssh_session()?.channel_session()?;

    channel.exec(command)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;

    Ok((output, channel.exit_status()?))
}

enum MkTempMode {
    Dir,
}

impl std::fmt::Display for MkTempMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MkTempMode::Dir => f.write_str("-d"),
        }
    }
}

fn exec_ssh_mktemp(vm: &dyn SshSession, mode: MkTempMode) -> Result<String, Error> {
    let (output, status) = exec_ssh_command(vm, &format!("echo -n $(mktemp {mode})"))?;
    if status != 0 {
        return Err(anyhow!(format!(
            "failed to mktemp {mode}: status {status}, output: {output}"
        )));
    }

    Ok(output)
}

fn exec_ssh_cat(vm: &dyn SshSession, path: &str) -> Result<String, Error> {
    let (output, status) = exec_ssh_command(vm, &format!("sudo cat {path}"))?;
    if status != 0 {
        return Err(anyhow!(format!(
            "failed to cat {path}: status {status}, output: {output}"
        )));
    }

    Ok(output)
}

fn exec_ssh_rm(vm: &dyn SshSession, path: &str) -> Result<(), Error> {
    let (output, status) = exec_ssh_command(vm, &format!("sudo rm -r {path} 2>&1"))?;
    if status != 0 {
        return Err(anyhow!(format!(
            "failed to rm path {path}: status {status}, output: {output}"
        )));
    }

    Ok(())
}

fn exec_ssh_restart_service(vm: &dyn SshSession, name: &str) -> Result<(), Error> {
    let (output, status) = exec_ssh_command(vm, &format!("sudo systemctl restart {name} 2>&1"))?;
    if status != 0 {
        return Err(anyhow!(format!(
            "failed to restart service {name}: status {status}, output: {output}"
        )));
    }

    Ok(())
}

async fn wait_for_docker_image(
    vm: &DeployedUniversalVm,
    name: &str,
    timeout: Duration,
) -> Result<(), Error> {
    for _ in 0..(timeout.as_secs()) {
        let cmd = format!("docker images -q {name} 2>&1");
        let (output, exit_code) = exec_ssh_command(vm, &cmd)?;
        if exit_code != 0 {
            return Err(anyhow!("failed to check for docker image: {name}"));
        }

        if !output.is_empty() {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Err(anyhow!("docker image {name} was not ready"))
}

pub async fn setup_asset_canister(
    env: TestEnv,
    domain_names: Vec<&str>,
    index_content: Option<&str>,
) -> Result<Principal, Error> {
    let asset_canister = env
        .deploy_asset_canister()
        .await
        .expect("Could not install asset canister");

    // upload the `/.well-known/ic-domains` file
    let file_content = domain_names.join("\n").as_bytes().to_vec();

    asset_canister
        .upload_asset(&UploadAssetRequest {
            key: "/.well-known/ic-domains".to_string(),
            content: file_content,
            content_type: "text/plain".to_string(),
            content_encoding: "identity".to_string(),
            sha_override: None,
        })
        .await?;

    if let Some(index_content) = index_content {
        asset_canister
            .upload_asset(&UploadAssetRequest {
                key: "/index.html".to_string(),
                content: index_content.as_bytes().to_vec(),
                content_type: "text/plain".to_string(),
                content_encoding: "identity".to_string(),
                sha_override: None,
            })
            .await?;
    }

    Ok(asset_canister.canister_id)
}

pub async fn setup_dns_records(
    env: TestEnv,
    domain_name: &str,
    canister_id: Principal,
) -> Result<(), Error> {
    // get the docker host
    let docker_host = env
        .get_deployed_universal_vm(REMOTE_DOCKER_HOST_VM_ID)
        .unwrap();
    let docker_host_ip = docker_host.get_vm().unwrap().ipv6;
    let base_url = format!("http://[{:?}]:{:?}", docker_host_ip, CLOUDFLARE_API_PORT);
    let client = Client::new();

    // create the zone if it doesn't exist yet
    let url = format!("{base_url}//client/v4/zones?name={DELEGATION_DOMAIN}");
    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to get the zone")?;

    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;

    // if the zone doesn't exist, create it
    if response_json["result"].is_array() && response_json["result"].as_array().unwrap().is_empty()
    {
        let url = format!("{}//client/v4/zones", base_url);
        let json_body = json!({ "name": DELEGATION_DOMAIN });
        let _response = client
            .post(&url)
            .json(&json_body)
            .send()
            .await
            .context("failed to configure the DNS records")?;
    }

    // create the zone
    let url = format!("{}//client/v4/zones", base_url);
    let json_body = json!({ "name": domain_name });
    let response = client
        .post(&url)
        .json(&json_body)
        .send()
        .await
        .context("failed to create the zone for {domain_name}")?;

    // extract the zone id from the response
    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;
    let zone_id = response_json["result"]["id"].as_str().unwrap();

    // set the TXT record containing the canister id
    let url = format!("{}//client/v4/zones/{}/dns_records", base_url, zone_id);
    let json_body = json!({"type": "TXT", "name": format!("_canister-id.{domain_name}"), "content": canister_id.to_string()});
    let _response = client
        .post(&url)
        .json(&json_body)
        .send()
        .await
        .context("failed to set the TXT record with the canister id: {}")?;

    // set the CNAME record for the ACME challenge
    let url = format!("{}//client/v4/zones/{}/dns_records", base_url, zone_id);
    let json_body = json!({"type": "CNAME", "name": format!("_acme-challenge.{domain_name}"), "content": format!("_acme-challenge.{domain_name}.{DELEGATION_DOMAIN}")});
    let _response = client
        .post(&url)
        .json(&json_body)
        .send()
        .await
        .context("failed to set the CNAME record for the ACME challenge")?;

    Ok(())
}

pub async fn update_dns_records(
    env: TestEnv,
    domain_name: &str,
    canister_id: Principal,
) -> Result<(), Error> {
    // get the docker host
    let docker_host = env
        .get_deployed_universal_vm(REMOTE_DOCKER_HOST_VM_ID)
        .unwrap();
    let docker_host_ip = docker_host.get_vm().unwrap().ipv6;
    let base_url = format!("http://[{:?}]:{:?}", docker_host_ip, CLOUDFLARE_API_PORT);
    let client = Client::new();

    // get the zone for the given domain
    let url = format!("{base_url}//client/v4/zones?name={domain_name}");
    let response = client
        .get(&url)
        .send()
        .await
        .context(format!("failed to get the zone for {domain_name}"))?;

    // extract the zone id from the response
    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;
    let zone_id = response_json["result"][0]["id"].as_str().unwrap();

    // get the existing record
    let url = format!(
        "{base_url}//client/v4/zones/{zone_id}/dns_records?name=_canister-id.{domain_name}"
    );
    let response = client.get(&url).send().await.context(format!(
        "failed to get the DNS records for _canister-id.{domain_name}"
    ))?;

    // extract the record id from the response
    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;
    let record_id = response_json["result"][0]["id"].as_str().unwrap();

    // update the TXT record containing the canister id
    let url = format!(
        "{}//client/v4/zones/{}/dns_records/{record_id}",
        base_url, zone_id
    );
    let json_body = json!({"type": "TXT", "name": format!("_canister-id.{domain_name}"), "content": canister_id.to_string()});
    let _response = client
        .put(&url)
        .json(&json_body)
        .send()
        .await
        .context("failed to update the TXT record with the canister id: {}")?;

    Ok(())
}

pub async fn remove_dns_records(env: TestEnv, domain_name: &str) -> Result<(), Error> {
    // get the docker host
    let docker_host = env
        .get_deployed_universal_vm(REMOTE_DOCKER_HOST_VM_ID)
        .unwrap();
    let docker_host_ip = docker_host.get_vm().unwrap().ipv6;
    let base_url = format!("http://[{:?}]:{:?}", docker_host_ip, CLOUDFLARE_API_PORT);
    let client = Client::new();

    // get the zone for the given domain
    let url = format!("{base_url}//client/v4/zones?name={domain_name}");
    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to get the zone")?;

    // extract the zone id from the response
    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;
    let zone_id = response_json["result"][0]["id"].as_str().unwrap();

    // get the existing record
    let url = format!(
        "{base_url}//client/v4/zones/{zone_id}/dns_records?name=_canister-id.{domain_name}"
    );
    let response = client.get(&url).send().await.context(format!(
        "failed to get the DNS records for _canister-id.{domain_name}"
    ))?;

    // extract the record id from the response
    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;
    let record_id = response_json["result"][0]["id"].as_str().unwrap();

    // delete the record
    let url = format!(
        "{}//client/v4/zones/{}/dns_records/{record_id}",
        base_url, zone_id
    );
    let _response = client
        .delete(&url)
        .send()
        .await
        .context("failed to delete record for _canister-id.{domain_name}")?;

    // get the existing record
    let url = format!(
        "{base_url}//client/v4/zones/{zone_id}/dns_records?name=_acme-challenge.{domain_name}"
    );
    let response = client.get(&url).send().await.context(format!(
        "failed to get the DNS records for _acme-challenge.{domain_name}"
    ))?;

    // extract the record id from the response
    let response_json: serde_json::Value = response
        .json()
        .await
        .context("failed to decode the response")?;
    let record_id = response_json["result"][0]["id"].as_str().unwrap();

    // delete the record
    let url = format!(
        "{}//client/v4/zones/{}/dns_records/{record_id}",
        base_url, zone_id
    );
    let _response = client
        .delete(&url)
        .send()
        .await
        .context("failed to delete record for _acme-challenge.{domain_name}")?;

    Ok(())
}

pub fn create_bn_http_client(env: TestEnv, domain_names: Vec<&str>) -> Client {
    // get the boundary node
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_VM_ID)
        .unwrap()
        .get_snapshot()
        .unwrap();

    // create a simple HTTP client to request a new custom domain registration
    let client_builder = ClientBuilder::new().redirect(Policy::none());
    let host = "ic0.app";
    let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
    let mut client_builder = client_builder
        .danger_accept_invalid_certs(true)
        .resolve(host, bn_addr.into());
    for domain_name in domain_names.iter() {
        client_builder = client_builder.resolve(domain_name, bn_addr.into());
    }
    client_builder.build().unwrap()
}

pub enum RegistrationRequestState {
    Accepted(String),
    Rejected(String),
}

pub enum UpdateRequestState {
    Accepted,
    Rejected(String),
}

pub enum RemoveRequestState {
    Accepted,
    Rejected(String),
}

pub enum GetRequestState {
    Accepted(String),
    Rejected(String),
}

pub async fn submit_registration_request(
    bn_client: Client,
    domain_name: &str,
) -> Result<RegistrationRequestState, Error> {
    let url = "https://ic0.app/registrations";
    let request_body = json!({ "name": domain_name });

    let response = bn_client
        .post(url)
        .json(&request_body)
        .send()
        .await
        .context("failed to submit the registration")?;

    // check the response status code
    if response.status().is_success() {
        let response_json: serde_json::Value = response
            .json()
            .await
            .expect("failed to decode the response");
        let registration_id = response_json["id"].as_str().unwrap();
        Ok(RegistrationRequestState::Accepted(
            registration_id.to_string(),
        ))
    } else {
        let response_text = response
            .text()
            .await
            .expect("failed to get the text from the response");
        Ok(RegistrationRequestState::Rejected(
            response_text.to_string(),
        ))
    }
}

pub async fn update_registration(
    bn_client: Client,
    registration_id: &str,
) -> Result<UpdateRequestState, Error> {
    let url = format!("https://ic0.app/registrations/{registration_id}");

    let response = bn_client
        .put(url)
        .send()
        .await
        .context("failed to submit the request to update the domain")?;

    // check the response status code
    if response.status().is_success() {
        Ok(UpdateRequestState::Accepted)
    } else {
        let response_text = response
            .text()
            .await
            .expect("failed to get the text from the response");
        Ok(UpdateRequestState::Rejected(response_text.to_string()))
    }
}

pub async fn remove_registration(
    bn_client: Client,
    registration_id: &str,
) -> Result<RemoveRequestState, Error> {
    let url = format!("https://ic0.app/registrations/{registration_id}");

    let response = bn_client
        .delete(url)
        .send()
        .await
        .context("failed to submit the request to remove the domain")?;

    // check the response status code
    if response.status().is_success() {
        Ok(RemoveRequestState::Accepted)
    } else {
        let response_text = response
            .text()
            .await
            .expect("failed to get the text from the response");
        Ok(RemoveRequestState::Rejected(response_text.to_string()))
    }
}

pub async fn get_registration_status(
    bn_client: Client,
    registration_id: &str,
) -> Result<GetRequestState, Error> {
    let url = format!("https://ic0.app/registrations/{registration_id}");
    let response = bn_client
        .get(url)
        .send()
        .await
        .context("failed to get the registration status")?;

    // check the response status code
    if response.status().is_success() {
        let response_json: serde_json::Value = response
            .json()
            .await
            .context("failed to decode the response")?;
        let registration_state = response_json["state"].as_str().unwrap();
        Ok(GetRequestState::Accepted(registration_state.to_string()))
    } else {
        let response_text = response
            .text()
            .await
            .expect("failed to get the text from the response");
        Ok(GetRequestState::Rejected(response_text.to_string()))
    }
}

pub fn get_certificate_syncer_state(vm: &dyn SshSession, domain_name: &str) -> String {
    let cmd = format!(
        r#"cat /var/opt/nginx/domain_canister_mappings.js | grep -o '"{domain_name}":"[^"]*' | sed 's/"{domain_name}":"//'"#
    );
    vm.block_on_bash_script(&cmd).unwrap().trim().to_string()
}

fn get_service_status(vm: &dyn SshSession, service: &str) -> String {
    vm.block_on_bash_script(&format!("systemctl is-active {service} 2>&1"))
        .unwrap()
}

pub fn is_service_active(vm: &dyn SshSession, service: &str) -> bool {
    let cmd_output = get_service_status(vm, service);
    let result = get_service_status(vm, service) == "active";
    println!("SERVICE-RJB: {service}: {cmd_output} - {result}");
    result
}

pub fn get_service_errors(vm: &dyn SshSession, service: &str) -> String {
    vm.block_on_bash_script(&format!(
        r#"journalctl -u {service}.service --since "20 seconds ago" -p err | grep "No entries""#
    ))
    .unwrap()
    .trim()
    .to_string()
}

pub async fn access_domain(bn_client: Client, domain_name: &str) -> Result<String, Error> {
    let url = format!("https://{domain_name}");
    let response = bn_client
        .get(url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        )
        .send()
        .await
        .context("failed to access the domain")?;

    // check the response status code
    if response.status().is_success() {
        let response_text = response
            .text()
            .await
            .expect("failed to get the text from the response");
        Ok(response_text.to_string())
    } else {
        panic!("boundary node returned an error: {:?}", response.status())
    }
}
