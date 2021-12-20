/// SSH Key Utilities
use ic_types::time::current_time;
use openssh_keys::PublicKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use pem::{encode, Pem};
use ssh2::Session;
use std::net::{IpAddr, TcpStream};
use std::time::Duration;

pub(crate) fn generate_key_strings() -> (String, String) {
    // Our keys are Ed25519, and not RSA. Once we figure out a direct way to encode
    // an Ed25519 private key the SSH way, we might consider switching to it.
    let rsa = Rsa::generate(1024).unwrap();
    let e = rsa.e();
    let n = rsa.n();

    let private_key = private_key_to_pem_string(&rsa);
    let public_key = public_key_to_string(e.to_vec(), n.to_vec());
    (private_key, public_key)
}

fn private_key_to_pem_string(rsa: &Rsa<Private>) -> String {
    let private_key = rsa.private_key_to_der().unwrap();
    let private_pem = Pem {
        tag: String::from("RSA PRIVATE KEY"),
        contents: private_key,
    };
    encode(&private_pem)
}

fn public_key_to_string(e: Vec<u8>, n: Vec<u8>) -> String {
    let mut key = PublicKey::from_rsa(e, n);
    key.set_comment("ci@ci.ci");
    key.to_string()
}

pub(crate) enum AuthMean {
    PrivateKey(String),
    Password(String),
    None,
}

pub(crate) struct SshSession {
    pub session: Session,
}

impl SshSession {
    pub fn new() -> Self {
        Self {
            session: Session::new().unwrap(),
        }
    }

    pub fn login(
        &mut self,
        ip: &IpAddr,
        username: &str,
        mean: &AuthMean,
    ) -> Result<(), ssh2::Error> {
        let ip_str = format!("[{}]:22", ip);
        let tcp = TcpStream::connect(ip_str).unwrap();
        self.session.set_tcp_stream(tcp);
        self.session.handshake().unwrap();

        match mean {
            AuthMean::PrivateKey(pk) => self
                .session
                .userauth_pubkey_memory(username, None, pk, None),
            AuthMean::Password(pw) => self.session.userauth_password(username, pw),
            AuthMean::None => self.session.userauth_agent(username),
        }
    }
}

pub(crate) fn assert_authentication_works(ip: &IpAddr, username: &str, mean: &AuthMean) {
    SshSession::new().login(ip, username, mean).unwrap();
}

pub(crate) fn assert_authentication_fails(ip: &IpAddr, username: &str, mean: &AuthMean) {
    assert!(SshSession::new().login(ip, username, mean).is_err());
}

pub(crate) fn wait_until_authentication_is_granted(ip: &IpAddr, username: &str, mean: &AuthMean) {
    // The orchestrator updates the access keys every 10 seconds. If we are lucky,
    // this call succeeds at the first trial. If we are unlucky, it starts
    // succeeding after 10 secs.
    let deadline = current_time() + Duration::from_secs(30);
    loop {
        match SshSession::new().login(ip, username, mean) {
            Ok(_) => return,
            Err(e) if current_time() > deadline => panic!("Authentication failed: {}", e),
            _ => {}
        }
    }
}

pub(crate) fn wait_until_authentication_fails(ip: &IpAddr, username: &str, mean: &AuthMean) {
    // The orchestrator updates the access keys every 10 seconds. If we are lucky,
    // this call succeeds at the first trial. If we are unlucky, it starts
    // succeeding after 10 secs.
    let deadline = current_time() + Duration::from_secs(30);
    loop {
        match SshSession::new().login(ip, username, mean) {
            Err(_) => return,
            Ok(_) if current_time() > deadline => panic!("Authentication still succeeds"),
            _ => {}
        }
    }
}
