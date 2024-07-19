use std::time::Duration;

/**
 * 1. Delete existing tc rules (if present).
 * 2. Add a root qdisc (queueing discipline) for an htb (hierarchical token bucket).
 * 3. Add a class with bandwidth limit.
 * 4. Add a qdisc to introduce latency.
 * 5. Add a filter to associate IPv6 traffic with the class and specific port.
 * 6. Read the active tc rules.
 */
pub fn limit_tc_ssh_command(bandwith_mbit_per_sec: u32, latency: Duration) -> String {
    const DEVICE_NAME: &str = "enp1s0"; // network interface name

    let cfg = ic_system_test_driver::util::get_config();
    let p2p_listen_port = cfg.transport.unwrap().listening_port;
    format!(
        r#"set -euo pipefail
sudo tc qdisc del dev {device} root 2> /dev/null || true
sudo tc qdisc add dev {device} root handle 1: htb default 10
sudo tc class add dev {device} parent 1: classid 1:10 htb rate {bandwidth_mbit}mbit ceil {bandwidth_mbit}mbit
sudo tc qdisc add dev {device} parent 1:10 handle 10: netem delay {latency_ms}ms
sudo tc filter add dev {device} parent 1: protocol ipv6 prio 1 u32 match ip6 dport {p2p_listen_port} 0xFFFF flowid 1:10
sudo tc qdisc show dev {device}
"#,
        device = DEVICE_NAME,
        bandwidth_mbit = bandwith_mbit_per_sec,
        latency_ms = latency.as_millis(),
        p2p_listen_port = p2p_listen_port
    )
}
