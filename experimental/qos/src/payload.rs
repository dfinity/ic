//! Payload utils

use crate::interface::Payload;

pub struct PayloadGenerator {
    pat: u8,
    payload_size: usize,
}

impl PayloadGenerator {
    pub fn generate(&mut self) -> Payload {
        self.pat = if self.pat == 255 { 0 } else { self.pat + 1 };

        vec![self.pat; self.payload_size]
    }
}

impl Default for PayloadGenerator {
    fn default() -> Self {
        Self {
            pat: 10,
            payload_size: 1024 * 192,
        }
    }
}

pub struct PayloadChecker {
    pat: u8,
}

impl PayloadChecker {
    pub fn check(&mut self, payload: &[u8]) {
        self.pat = if self.pat == 255 { 0 } else { self.pat + 1 };

        let count: Vec<u8> = payload
            .iter()
            .filter(|&v| *v == payload[0])
            .cloned()
            .collect::<Vec<u8>>();
        assert_eq!(count.len(), payload.len());
        assert_eq!(payload[0], self.pat);

        for i in 0..payload.len() {
            if payload[i] != payload[0] {
                panic!(
                    "Unexpected: i = {}, val = {}, count = {}",
                    i,
                    payload[i],
                    count.len()
                );
            }
        }
        println!(
            "checker(): Read validated({}): {}/{}",
            payload[0],
            payload.len(),
            count.len()
        );
    }
}

impl Default for PayloadChecker {
    fn default() -> Self {
        Self { pat: 10 }
    }
}
