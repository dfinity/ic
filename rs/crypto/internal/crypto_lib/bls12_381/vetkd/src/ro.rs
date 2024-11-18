use ic_crypto_internal_bls12_381_type::Scalar;
use ic_sha3::Shake256;

#[derive(Clone)]
pub(crate) struct RandomOracle {
    shake: Shake256,
}

impl RandomOracle {
    pub(crate) fn new(domain_separator: &str) -> Self {
        let mut ro = Self {
            shake: Shake256::default(),
        };

        ro.update_str(domain_separator);

        ro
    }

    pub(crate) fn update_str(&mut self, s: &str) {
        self.update_bin(s.as_bytes());
    }

    pub(crate) fn update_bin(&mut self, v: &[u8]) {
        let v_len = v.len() as u64;
        self.shake.update(v_len.to_be_bytes());
        self.shake.update(v);
    }

    fn finalize(mut self, output: &mut [u8]) {
        let o_len = output.len() as u64;
        self.shake.update(o_len.to_be_bytes());

        let mut xof = self.shake.finalize_xof();
        xof.read(output);
    }

    pub(crate) fn finalize_to_vec(self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        self.finalize(&mut output);
        output
    }

    pub(crate) fn finalize_to_scalar(self) -> Scalar {
        let mut output = [0u8; 2 * Scalar::BYTES];
        self.finalize(&mut output);
        Scalar::from_bytes_wide(&output)
    }
}
