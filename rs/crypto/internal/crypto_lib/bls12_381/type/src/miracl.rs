use miracl_core_bls12381::bls12381::{big::BIG, big::MODBYTES, ecp::ECP, ecp2::ECP2, fp2::FP2};

/// Conversion utility function
///
/// MIRACL requires BIG::frombytes be called with exactly a
/// 48 byte array
fn miracl_big_from_bytes(bytes: &[u8]) -> BIG {
    let mut buf = [0u8; MODBYTES];
    let offset = buf.len() - bytes.len();
    buf[offset..].copy_from_slice(bytes);
    BIG::frombytes(&buf)
}

/// Conversion utility function
///
/// MIRACL encodes a BIG always as a 48 byte array
fn miracl_big_to_bytes(big: &BIG) -> [u8; 48] {
    let mut buf = [0u8; 48];
    big.tobytes(&mut buf);
    buf
}

impl crate::Scalar {
    /// Convert this Scalar to a MIRACL BIG
    ///
    /// This is a temporary function included until CRP-1541
    /// is completed, after which this function will be removed.
    pub fn to_miracl(&self) -> BIG {
        miracl_big_from_bytes(&self.serialize())
    }

    /// Convert a MIRACL BIG into a Scalar
    ///
    /// The integer value is reduced modulo the curve order
    ///
    /// This is a temporary function included until CRP-1541
    /// is completed, after which this function will be removed.
    pub fn from_miracl(big: &BIG) -> Self {
        let mut wider = [0u8; 64];
        wider[16..].copy_from_slice(&miracl_big_to_bytes(big));
        wider.reverse(); // bls12_381 uses little endian!
        Self::new(bls12_381::Scalar::from_bytes_wide(&wider))
    }
}

impl crate::G1Affine {
    /// Convert this G1Affine to a MIRACL ECP
    ///
    /// This is a temporary function included until CRP-1541
    /// is completed, after which this function will be removed.
    pub fn to_miracl(&self) -> ECP {
        if self.is_identity() {
            let mut ecp = ECP::new();
            ecp.inf();
            return ecp;
        }

        let xy = self.value.to_uncompressed();
        let x = miracl_big_from_bytes(&xy[..48]);
        let y = miracl_big_from_bytes(&xy[48..]);
        ECP::new_bigs(&x, &y)
    }

    /// Convert a MIRACL ECP into a G1Affine
    ///
    /// This is a temporary function included until CRP-1541
    /// is completed, after which this function will be removed.
    pub fn from_miracl(ecp: &ECP) -> Self {
        let affine_ecp = {
            let mut affine_ecp = ECP::new();
            affine_ecp.copy(ecp);
            affine_ecp.affine();
            affine_ecp
        };

        if affine_ecp.is_infinity() {
            return Self::identity();
        }

        let mut xy = [0u8; 96];
        xy[..48].copy_from_slice(&miracl_big_to_bytes(&affine_ecp.getpx().redc()));
        xy[48..].copy_from_slice(&miracl_big_to_bytes(&affine_ecp.getpy().redc()));

        Self::new(bls12_381::G1Affine::from_uncompressed_unchecked(&xy).unwrap())
    }
}

impl crate::G2Affine {
    /// Convert this G2Affine to a MIRACL ECP2
    ///
    /// This is a temporary function included until CRP-1541
    /// is completed, after which this function will be removed.
    pub fn to_miracl(&self) -> ECP2 {
        if self.is_identity() {
            let mut ecp = ECP2::new();
            ecp.inf();
            return ecp;
        }

        let abcd = self.value.to_uncompressed();
        let a = miracl_big_from_bytes(&abcd[0..48]);
        let b = miracl_big_from_bytes(&abcd[48..96]);
        let c = miracl_big_from_bytes(&abcd[96..144]);
        let d = miracl_big_from_bytes(&abcd[144..192]);
        ECP2::new_fp2s(&FP2::new_bigs(&b, &a), &FP2::new_bigs(&d, &c))
    }

    /// Convert a MIRACL ECP2 into a G2Affine
    ///
    /// This is a temporary function included until CRP-1541
    /// is completed, after which this function will be removed.
    pub fn from_miracl(ecp: &ECP2) -> Self {
        let affine_ecp = {
            let mut affine_ecp = ECP2::new();
            affine_ecp.copy(ecp);
            affine_ecp.affine();
            affine_ecp
        };

        if affine_ecp.is_infinity() {
            return Self::identity();
        }

        let mut abcd = [0u8; 192];
        abcd[0..48].copy_from_slice(&miracl_big_to_bytes(&affine_ecp.getpx().getB().redc()));
        abcd[48..96].copy_from_slice(&miracl_big_to_bytes(&affine_ecp.getpx().getA().redc()));
        abcd[96..144].copy_from_slice(&miracl_big_to_bytes(&affine_ecp.getpy().getB().redc()));
        abcd[144..192].copy_from_slice(&miracl_big_to_bytes(&affine_ecp.getpy().getA().redc()));

        Self::new(bls12_381::G2Affine::from_uncompressed_unchecked(&abcd).unwrap())
    }
}
