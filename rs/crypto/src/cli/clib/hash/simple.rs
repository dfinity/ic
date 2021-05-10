use ic_crypto_internal_csp::hash::Sha256Hasher;
use ic_crypto_internal_types::context::Context;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [domain_separator, message] => core(domain_separator, message),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <domain_separator> <message>".to_string(), 1))
}

fn core(domain_separator: &str, message: &str) -> Result<(), (String, i32)> {
    let context = domain_separator.as_bytes();
    let data = message.as_bytes();
    let mut state = Sha256Hasher::new(&ByteWrapper::new(&context));
    state.update(data);
    let digest = state.finalize();
    // TODO(DFN-1350): Digest doesn't provide a default stringification. Use base64.
    println!("Hash: {:?}", digest);
    Ok(())
}

#[derive(Debug)]
struct ByteWrapper {
    bytes: Vec<u8>,
}

impl ByteWrapper {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

impl Context for ByteWrapper {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
