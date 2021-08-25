use ic_crypto_sha256::Context;
use ic_crypto_sha256::Sha256;
use std::cmp::min;
use std::collections::HashSet;
use std::time::{Duration, Instant};

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        [message_size] => core(message_size),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err((
        "Args: .. bench <size:usize>[units:[KMG]]
          \n
          \nE.g.:   cargo run --release lib hash bench 4G
          \nor:     cargo run --release lib hash bench 27"
            .to_string(),
        1,
    ))
}

fn parse_message_size(message_size: &str) -> Result<usize, (String, i32)> {
    if message_size.is_empty() {
        return Err(("Invalid message length: ''".to_string(), 2));
    }
    let mut chars = message_size.chars();
    let last_char = chars.next_back().expect("Message size arg was empty");

    let mult = match last_char {
        'G' => Some(1 << 30),
        'M' => Some(1 << 20),
        'K' => Some(1 << 10),
        _ => None,
    };

    match mult {
        Some(mult) => {
            let d = chars
                .as_str()
                .parse::<usize>()
                .map_err(|_| (format!("Invalid message length {}", message_size), 2))?;
            Ok(d * mult)
        }
        None => {
            let d = message_size
                .parse::<usize>()
                .map_err(|_| (format!("Invalid message length {}", message_size), 2))?;
            Ok(d)
        }
    }
}

pub fn print_time(title: &str, interval: Duration, iterations: usize) {
    let interval = interval.as_nanos() as f64 / iterations as f64 / 1_000_000f64;
    println!("{:30}: {} ms", title, interval,);
}

fn core(message_size: &str) -> Result<(), (String, i32)> {
    let message_byte_len = parse_message_size(message_size)?;
    let data: Vec<u8> = vec![69u8; message_byte_len];
    let max_iterations = 100;
    let iterations = if message_byte_len == 0 {
        max_iterations
    } else {
        min(100, (10 << 30) / message_byte_len + 1)
    };
    let mut results = HashSet::new();
    let mut total_time = Duration::new(0, 0);
    for iteration in 0..iterations {
        let context = format!("Run {}", iteration);
        let time_start = Instant::now();
        let mut state = Sha256::new_with_context(&ByteWrapper::new(&context.as_bytes()));
        state.write(&data);
        let digest = state.finish();
        let time_stop = Instant::now();
        results.insert(digest);
        total_time += time_stop.duration_since(time_start);
    }
    assert_eq!(
        results.len(),
        iterations,
        "The domain separator doesn't work"
    );
    println!(
        "Times: ({} iterations of {} bytes)",
        iterations, message_byte_len
    );
    print_time(
        &format!("Hashing {}", message_size),
        total_time,
        iterations as usize,
    );
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
