use sha3::{
    digest::{ExtendableOutputReset, Update, XofReader},
    Shake256,
};

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
        self.shake.update(&v_len.to_be_bytes());
        self.shake.update(v);
    }

    fn finalize(&mut self, output: &mut [u8]) {
        let o_len = output.len() as u64;
        self.shake.update(&o_len.to_be_bytes());

        let mut xof = self.shake.finalize_xof_reset();
        xof.read(output);
    }

    pub(crate) fn finalize_to_scalar(mut self) -> ic_bls12_381::Scalar {
        let mut ro_output = [0u8; 64];
        self.finalize(&mut ro_output);
        ro_output.reverse(); // convert to little-endian
        ic_bls12_381::Scalar::from_bytes_wide(&ro_output)
    }

    pub(crate) fn finalize_to_array<const N: usize>(mut self) -> [u8; N] {
        let mut output = [0u8; N];
        self.finalize(&mut output);
        output
    }

    pub(crate) fn finalize_to_vec(mut self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        self.finalize(&mut output);
        output
    }
}
