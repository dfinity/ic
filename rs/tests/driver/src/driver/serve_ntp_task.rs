//! Per-group SNTP server for the Local system-test backend.
//!
//! IC-OS runs `chrony` against public NTS and pool servers
//! (`ic-os/components/misc/chrony/chrony.conf`). The Local backend has no
//! external connectivity and its `dnsmasq` runs `--no-resolv`, so chrony can
//! never resolve, let alone reach, any of them and the clock stays formally
//! unsynchronized. On GuestOS and HostOS that is only cosmetic — every VM reads
//! the host's clock through `-rtc base=utc`, so the nodes agree with each other.
//! On SetupOS it is fatal: `check-ntp.sh` is the one SetupOS check that is *not*
//! gated on `ic.setupos.run_checks`, and it waits 60s for
//! `timedatectl show -p NTPSynchronized` to become `yes` before halting the
//! installation forever (`log_and_halt_installation_on_error` ends in
//! `sleep infinity`). That blocks the nested tests, which install a node from
//! SetupOS.
//!
//! So serve NTP ourselves. This task answers SNTP on UDP
//! [`NTP_PORT`] at the group's gateway address
//! ([`LocalBackend::group_gateway_ipv6`](crate::driver::local_backend::LocalBackend::group_gateway_ipv6)),
//! and [`start_dnsmasq`](crate::driver::local_backend::LocalBackend::start_dnsmasq)
//! resolves the plain-NTP pool names in `chrony.conf` to that address. The
//! gateway is the guests' default router and already carries the resolver
//! addresses GuestOS is hard-coded to query, so this puts the group's NTP service
//! alongside its DNS service on the one address every guest already talks to.
//! (A dedicated address is not available: the `/64`'s subnet-id field is two bits
//! wide and all four values are taken — nodes, management, journald and the file
//! server.)
//!
//! Binding a privileged port needs no extra capability work: the driver created
//! the user namespace it runs in (see
//! [`ensure_administrable_netns`](crate::driver::local_backend::LocalBackend::ensure_administrable_netns)),
//! so it holds `CAP_NET_BIND_SERVICE` in its effective set, and task subprocesses
//! are forked rather than `exec`ed. `raise_ambient_net_caps` puts the capability
//! in the ambient set too, so this keeps working if that ever changes.
//!
//! The task is modelled exactly like
//! [`serve_files_task`](crate::driver::serve_files_task): it never returns and is
//! wired into the plan as a supervisor over the setup -> tests -> teardown
//! subtree, so the task scheduler silently kills it once the subtree finishes
//! (this is not treated as a failure).

use crate::driver::{
    constants::GROUP_SETUP_DIR,
    context::GroupContext,
    local_backend::LocalBackend,
    test_env::{TestEnv, TestEnvAttribute},
    test_setup::GroupSetup,
};
use slog::{debug, info, warn};
use std::collections::HashSet;
use std::net::{IpAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const SERVE_NTP_TASK_NAME: &str = "serve_ntp";

/// Delay between retries while waiting for the group setup / binding the socket.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// UDP port on which the per-group NTP server listens (on the group's IPv6
/// gateway address). Fixed by the protocol: `chrony.conf` names its servers
/// without a port, so they are reached on 123.
pub const NTP_PORT: u16 = 123;

/// Length of an NTP packet's header, which is the whole packet for the SNTP
/// requests IC-OS's chrony sends. Longer packets (extension fields, an
/// authenticator) are answered from their header alone.
const NTP_HEADER_LEN: usize = 48;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_UNIX_EPOCH_DELTA_SECS: u64 = 2_208_988_800;

pub(crate) fn serve_ntp_task(group_ctx: GroupContext) {
    let logger = group_ctx.logger().clone();
    debug!(logger, ">>> {SERVE_NTP_TASK_NAME}");

    // Wait until `GroupSetup` has been persisted so we can derive the group's
    // gateway address. Under the Local backend that address is assigned to the
    // group bridge inline in the parent process before the task scheduler starts,
    // so this normally succeeds on the first iteration; the loop only guards
    // against an unexpected startup race.
    let group_setup = loop {
        let setup_dir = group_ctx.group_dir.join(GROUP_SETUP_DIR);
        if setup_dir.exists() {
            let env = TestEnv::new_without_duplicating_logger(setup_dir, logger.clone());
            if let Ok(group_setup) = GroupSetup::try_read_attribute(&env) {
                break group_setup;
            }
        }
        info!(
            logger,
            "{SERVE_NTP_TASK_NAME}: waiting for group setup to be persisted ..."
        );
        std::thread::sleep(RETRY_DELAY);
    };

    let gateway = LocalBackend::group_gateway_ipv6(&group_setup.infra_group_name);
    let addr = format!("[{gateway}]:{NTP_PORT}");
    let socket = loop {
        match UdpSocket::bind(&addr) {
            Ok(socket) => break socket,
            Err(err) => {
                warn!(
                    logger,
                    "{SERVE_NTP_TASK_NAME}: failed to bind {addr}: {err}; retrying ..."
                );
                std::thread::sleep(RETRY_DELAY);
            }
        }
    };
    info!(logger, "{SERVE_NTP_TASK_NAME}: listening on {addr}");

    // Log the first request from each client at info level and the rest at debug
    // level: the interesting signal is *which* VMs found the server (an IC-OS
    // node that never appears here has a resolver or routing problem), while
    // chrony then polls indefinitely and would drown the test log.
    let mut clients_seen: HashSet<IpAddr> = HashSet::new();
    let mut buf = [0_u8; 1024];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(err) => {
                warn!(logger, "{SERVE_NTP_TASK_NAME}: recv_from failed: {err}");
                continue;
            }
        };
        if len < NTP_HEADER_LEN {
            debug!(
                logger,
                "{SERVE_NTP_TASK_NAME}: ignoring {len}-byte packet from {peer} \
                 (shorter than an NTP header)"
            );
            continue;
        }
        if clients_seen.insert(peer.ip()) {
            info!(logger, "{SERVE_NTP_TASK_NAME}: first request from {peer}");
        } else {
            debug!(logger, "{SERVE_NTP_TASK_NAME}: request from {peer}");
        }

        let request: &[u8; NTP_HEADER_LEN] = buf[..NTP_HEADER_LEN]
            .try_into()
            .expect("slice of the checked length converts to an array");
        let reply = sntp_reply(request, SystemTime::now());
        if let Err(err) = socket.send_to(&reply, peer) {
            warn!(
                logger,
                "{SERVE_NTP_TASK_NAME}: failed to reply to {peer}: {err}"
            );
        }
    }
}

/// Build the SNTP server reply to `request`, reading the time from `now`.
///
/// Field layout and semantics follow RFC 5905 section 7.3 (and RFC 4330 section
/// 5, which specifies exactly this unicast-server behaviour). We present
/// ourselves as a stratum-1 server with the reference identifier `LOCL` — the
/// conventional code for an uncalibrated local clock, which is what the driver
/// host's clock is from the guests' point of view — with zero root delay and root
/// dispersion, since we *are* the reference clock rather than a relay for one.
fn sntp_reply(request: &[u8; NTP_HEADER_LEN], now: SystemTime) -> [u8; NTP_HEADER_LEN] {
    let mut reply = [0_u8; NTP_HEADER_LEN];

    // Leap indicator 0 (no warning), version echoed from the request, mode 4
    // (server). Echoing the version is what RFC 4330 section 5 prescribes; a
    // client that asked in version 3 must not be answered in version 4.
    let version = (request[0] >> 3) & 0b111;
    reply[0] = (version << 3) | 4;
    reply[1] = 1; // Stratum 1: a primary reference.
    reply[2] = request[2]; // Poll interval: echo the client's, we impose none.
    reply[3] = 0xec; // Precision: -20, i.e. 2^-20 s ~ 1 us, the host clock's.
    // Bytes 4..12 (root delay, root dispersion) stay zero.
    reply[12..16].copy_from_slice(b"LOCL"); // Reference identifier.

    let now = ntp_timestamp(now);
    reply[16..24].copy_from_slice(&now); // Reference timestamp: last "sync", i.e. now.
    // Originate timestamp: the client's transmit timestamp, echoed back
    // unmodified. This is what lets the client compute the round trip, so it
    // must be copied verbatim rather than re-encoded.
    reply[24..32].copy_from_slice(&request[40..48]);
    reply[32..40].copy_from_slice(&now); // Receive timestamp.
    reply[40..48].copy_from_slice(&now); // Transmit timestamp.

    reply
}

/// Encode `time` as a 64-bit NTP timestamp: seconds since the NTP epoch in the
/// high 32 bits, binary fraction of a second in the low 32.
///
/// The seconds field wraps every ~136 years (the current era ends in 2036), which
/// is why the addition is a wrapping one; clients resolve the era themselves.
fn ntp_timestamp(time: SystemTime) -> [u8; 8] {
    let since_unix_epoch = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let seconds = since_unix_epoch
        .as_secs()
        .wrapping_add(NTP_UNIX_EPOCH_DELTA_SECS) as u32;
    // `subsec_nanos() < 1e9`, so shifting it left by 32 stays well inside u64.
    let fraction = (((since_unix_epoch.subsec_nanos() as u64) << 32) / 1_000_000_000) as u32;

    let mut timestamp = [0_u8; 8];
    timestamp[0..4].copy_from_slice(&seconds.to_be_bytes());
    timestamp[4..8].copy_from_slice(&fraction.to_be_bytes());
    timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client request in NTP version 4, mode 3 (client), with a recognisable
    /// transmit timestamp in bytes 40..48.
    fn client_request() -> [u8; NTP_HEADER_LEN] {
        let mut request = [0_u8; NTP_HEADER_LEN];
        request[0] = (4 << 3) | 3;
        request[2] = 6; // Poll interval 2^6 s.
        request[40..48].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
        request
    }

    #[test]
    fn reply_header_presents_a_synchronized_stratum_1_server() {
        let reply = sntp_reply(&client_request(), UNIX_EPOCH + Duration::from_secs(1));

        assert_eq!(reply[0] >> 6, 0, "leap indicator must be 0 (no warning)");
        assert_eq!((reply[0] >> 3) & 0b111, 4, "version must be echoed");
        assert_eq!(reply[0] & 0b111, 4, "mode must be 4 (server)");
        assert_eq!(reply[1], 1, "stratum must be 1");
        assert_eq!(reply[2], 6, "poll interval must be echoed");
        assert_eq!(&reply[4..12], &[0_u8; 8], "root delay/dispersion must be 0");
        assert_eq!(&reply[12..16], b"LOCL");
    }

    #[test]
    fn reply_echoes_the_originate_timestamp_and_stamps_the_rest() {
        let request = client_request();
        // One second past the Unix epoch, so the NTP seconds field is the epoch
        // delta plus one and the fraction is zero.
        let reply = sntp_reply(&request, UNIX_EPOCH + Duration::from_secs(1));

        assert_eq!(&reply[24..32], &request[40..48], "originate is echoed");

        let expected = (NTP_UNIX_EPOCH_DELTA_SECS as u32 + 1).to_be_bytes();
        for (name, field) in [
            ("reference", &reply[16..24]),
            ("receive", &reply[32..40]),
            ("transmit", &reply[40..48]),
        ] {
            assert_eq!(&field[0..4], &expected, "{name} timestamp seconds");
            assert_eq!(&field[4..8], &[0_u8; 4], "{name} timestamp fraction");
        }
    }

    #[test]
    fn reply_echoes_a_version_3_request() {
        let mut request = client_request();
        request[0] = (3 << 3) | 3;

        let reply = sntp_reply(&request, UNIX_EPOCH);

        assert_eq!((reply[0] >> 3) & 0b111, 3);
        assert_eq!(reply[0] & 0b111, 4);
    }

    #[test]
    fn ntp_timestamp_encodes_the_subsecond_fraction() {
        let half_a_second = ntp_timestamp(UNIX_EPOCH + Duration::from_millis(500));

        assert_eq!(
            &half_a_second[0..4],
            &(NTP_UNIX_EPOCH_DELTA_SECS as u32).to_be_bytes()
        );
        assert_eq!(&half_a_second[4..8], &0x8000_0000_u32.to_be_bytes());
    }
}
