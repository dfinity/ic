use crate::*;

pub const PROOF_OF_DLOG_EQUIV_DST: &str = "ic-crypto-tecdsa-zk-proof-of-dlog-eq";
pub const PROOF_OF_EQUAL_OPENINGS_DST: &str = "ic-crypto-tecdsa-zk-proof-of-equal-openings";
pub const PROOF_OF_PRODUCT_DST: &str = "ic-crypto-tecdsa-zk-proof-of-product";

/// A ZK proof that a Simple and Pedersen commitment are committing
/// to the same value.
///
/// This is, a zero-knowledge proof for the following relation R:
///
/// Instance = `(A, B)` ∈  G²,
/// Witness = `a, b, r` ∈  Zₚ,
/// such that:
/// - `A = PedersenCom(a,r)`,
/// - `B = SimpleCom(b)`
/// - `a=b`
///
/// Note that this proof does not prove knowledge of `a` and `b`, but just the equality of the openings.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ProofOfEqualOpenings {
    challenge: EccScalar,
    response: EccScalar,
}

#[derive(Debug, Copy, Clone)]
struct ProofOfEqualOpeningsInstance {
    curve_type: EccCurveType,
    // Commitment key for simple commitments and first element in the commitment key for Pedersen commitments.
    g: EccPoint,
    // Second element in the commitment key for Pedersen  commitments.
    h: EccPoint,
    // Pedersen commitment.
    a: EccPoint,
    // Simple commitment
    b: EccPoint,
}

impl ProofOfEqualOpeningsInstance {
    fn from_witness(secret: &EccScalar, masking: &EccScalar) -> ThresholdEcdsaResult<Self> {
        let curve_type = secret.curve_type();
        let g = EccPoint::generator_g(curve_type)?;
        let h = EccPoint::generator_h(curve_type)?;
        let a = EccPoint::pedersen(secret, masking)?;
        let b = EccPoint::mul_by_g(secret)?;
        Ok(Self {
            curve_type,
            g,
            h,
            a,
            b,
        })
    }

    fn from_commitments(pedersen: &EccPoint, simple: &EccPoint) -> ThresholdEcdsaResult<Self> {
        let curve_type = pedersen.curve_type();
        let g = EccPoint::generator_g(curve_type)?;
        let h = EccPoint::generator_h(curve_type)?;
        Ok(Self {
            curve_type,
            g,
            h,
            a: *pedersen,
            b: *simple,
        })
    }

    fn recover_commitment(&self, proof: &ProofOfEqualOpenings) -> ThresholdEcdsaResult<EccPoint> {
        let amb = self.a.sub_points(&self.b)?;
        let c_amb = amb.scalar_mul(&proof.challenge)?;
        let h_c = self.h.scalar_mul(&proof.response)?;
        h_c.sub_points(&c_amb)
    }

    fn hash_to_challenge(
        &self,
        commitment: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<EccScalar> {
        let mut ro = ro::RandomOracle::new(PROOF_OF_EQUAL_OPENINGS_DST);
        ro.add_bytestring("associated_data", associated_data)?;
        ro.add_point("instance_g", &self.g)?;
        ro.add_point("instance_h", &self.h)?;
        ro.add_point("instance_a", &self.a)?;
        ro.add_point("instance_b", &self.b)?;
        ro.add_point("commitment", commitment)?;
        ro.output_scalar(self.curve_type)
    }
}

impl ProofOfEqualOpenings {
    pub fn create(
        seed: Seed,
        secret: &EccScalar,
        masking: &EccScalar,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<Self> {
        let instance = ProofOfEqualOpeningsInstance::from_witness(secret, masking)?;

        // Create the blinding commitment
        let mut rng = seed.into_rng();
        let r = EccScalar::random(instance.curve_type, &mut rng)?;
        let r_com = instance.h.scalar_mul(&r)?;

        // Create challenge
        let challenge = instance.hash_to_challenge(&r_com, associated_data)?;

        // Create opening
        let response = masking.mul(&challenge)?.add(&r)?;

        Ok(Self {
            challenge,
            response,
        })
    }

    pub fn verify(
        &self,
        pedersen: &EccPoint,
        simple: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<()> {
        let instance = ProofOfEqualOpeningsInstance::from_commitments(pedersen, simple)?;

        let r_com = instance.recover_commitment(self)?;

        if self.challenge != instance.hash_to_challenge(&r_com, associated_data)? {
            return Err(ThresholdEcdsaError::InvalidProof);
        }

        Ok(())
    }
}

/// A ZK proof that a Pedersen commitment opens to the product of the
/// openings of a Simple commitment and a Pedersen commitment. This
/// is, a zero-knowledge proof for the following relation R:
///
/// Instance = `(A, B, C)` ∈  G³,
/// Witness = `(a, (b, beta), (c, gamma))` ∈  Zₚ⁵
/// such that:
/// - `A = SimpleCom(a)`,
/// - `B = PedersenCom(b, beta)`,
/// - `C = PedersenCom(c, gamma)`,
/// - `c=a*b`
///
/// The proof also shows knowledge of `(a, gamma)`.
///
/// Note: in the IDKG protocol it is not necessary to explicitly prove
/// knowledge of `b`, as in the security proof this is already known
/// by the simulator.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ProofOfProduct {
    challenge: EccScalar,
    response1: EccScalar,
    response2: EccScalar,
}

#[derive(Debug, Copy, Clone)]
struct ProofOfProductInstance {
    curve_type: EccCurveType,
    g: EccPoint,
    h: EccPoint,
    lhs_com: EccPoint,
    rhs_com: EccPoint,
    product_com: EccPoint,
}

impl ProofOfProductInstance {
    fn from_witness(
        lhs: &EccScalar,
        rhs: &EccScalar,
        rhs_masking: &EccScalar,
        product: &EccScalar,
        product_masking: &EccScalar,
    ) -> ThresholdEcdsaResult<Self> {
        let curve_type = lhs.curve_type();
        let g = EccPoint::generator_g(curve_type)?;
        let h = EccPoint::generator_h(curve_type)?;

        let lhs_com = g.scalar_mul(lhs)?;
        let rhs_com = EccPoint::mul_points(&g, rhs, &h, rhs_masking)?;
        let product_com = EccPoint::mul_points(&g, product, &h, product_masking)?;

        Ok(Self {
            curve_type,
            g,
            h,
            lhs_com,
            rhs_com,
            product_com,
        })
    }

    fn from_commitments(
        lhs_com: &EccPoint,
        rhs_com: &EccPoint,
        product_com: &EccPoint,
    ) -> ThresholdEcdsaResult<Self> {
        let curve_type = lhs_com.curve_type();
        let g = EccPoint::generator_g(curve_type)?;
        let h = EccPoint::generator_h(curve_type)?;
        Ok(Self {
            curve_type,
            g,
            h,
            lhs_com: *lhs_com,
            rhs_com: *rhs_com,
            product_com: *product_com,
        })
    }

    fn recover_commitment(
        &self,
        proof: &ProofOfProduct,
    ) -> ThresholdEcdsaResult<(EccPoint, EccPoint)> {
        let r1_com = EccPoint::mul_by_g(&proof.response1)?
            .sub_points(&self.lhs_com.scalar_mul(&proof.challenge)?)?;

        let r2_com =
            EccPoint::mul_points(&self.rhs_com, &proof.response1, &self.h, &proof.response2)?
                .sub_points(&self.product_com.scalar_mul(&proof.challenge)?)?;

        Ok((r1_com, r2_com))
    }

    fn hash_to_challenge(
        &self,
        c1: &EccPoint,
        c2: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<EccScalar> {
        let mut ro = ro::RandomOracle::new(PROOF_OF_PRODUCT_DST);
        ro.add_bytestring("associated_data", associated_data)?;
        ro.add_point("instance_g", &self.g)?;
        ro.add_point("instance_h", &self.h)?;
        ro.add_point("instance_lhs", &self.lhs_com)?;
        ro.add_point("instance_rhs", &self.rhs_com)?;
        ro.add_point("instance_product", &self.product_com)?;
        ro.add_point("commitment1", c1)?;
        ro.add_point("commitment2", c2)?;
        ro.output_scalar(self.curve_type)
    }
}

impl ProofOfProduct {
    pub fn create(
        seed: Seed,
        lhs: &EccScalar,
        rhs: &EccScalar,
        rhs_masking: &EccScalar,
        product: &EccScalar,
        product_masking: &EccScalar,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<Self> {
        let instance =
            ProofOfProductInstance::from_witness(lhs, rhs, rhs_masking, product, product_masking)?;

        // Compute blinding commitments:
        let mut rng = seed.into_rng();

        let r1 = EccScalar::random(instance.curve_type, &mut rng)?;
        let r1_com = instance.g.scalar_mul(&r1)?;

        let r2 = EccScalar::random(instance.curve_type, &mut rng)?;
        let r2_com = EccPoint::mul_points(&instance.rhs_com, &r1, &instance.h, &r2)?;

        // Compute the challenge:
        let challenge = instance.hash_to_challenge(&r1_com, &r2_com, associated_data)?;

        // Compute the openings:
        let response1 = lhs.mul(&challenge)?.add(&r1)?;
        let response2 = product_masking
            .sub(&lhs.mul(rhs_masking)?)?
            .mul(&challenge)?
            .add(&r2)?;

        Ok(Self {
            challenge,
            response1,
            response2,
        })
    }

    pub fn verify(
        &self,
        lhs_com: &EccPoint,
        rhs_com: &EccPoint,
        product_com: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<()> {
        let instance = ProofOfProductInstance::from_commitments(lhs_com, rhs_com, product_com)?;

        let (r1_com, r2_com) = instance.recover_commitment(self)?;

        if self.challenge != instance.hash_to_challenge(&r1_com, &r2_com, associated_data)? {
            return Err(ThresholdEcdsaError::InvalidProof);
        }

        Ok(())
    }
}

/// A ZK proof of discrete logarithm equivalence
/// This is, a zero-knowledge proof for the following relation R:
///
/// Instance = `(g, h, A, B)` ∈  G⁴,
/// Witness = `x` ∈  Zₚ,
/// such that:
/// `A = g*x` and `B = h*x`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDLogEquivalence {
    challenge: EccScalar,
    response: EccScalar,
}

#[derive(Debug, Copy, Clone)]
struct ProofOfDLogEquivalenceInstance {
    curve_type: EccCurveType,
    g: EccPoint,
    h: EccPoint,
    g_x: EccPoint,
    h_x: EccPoint,
}

impl ProofOfDLogEquivalenceInstance {
    fn from_witness(g: &EccPoint, h: &EccPoint, x: &EccScalar) -> ThresholdEcdsaResult<Self> {
        let curve_type = x.curve_type();
        let g_x = g.scalar_mul(x)?;
        let h_x = h.scalar_mul(x)?;
        Ok(Self {
            curve_type,
            g: *g,
            h: *h,
            g_x,
            h_x,
        })
    }

    fn from_commitments(
        g: &EccPoint,
        h: &EccPoint,
        g_x: &EccPoint,
        h_x: &EccPoint,
    ) -> ThresholdEcdsaResult<Self> {
        let curve_type = g.curve_type();
        Ok(Self {
            curve_type,
            g: *g,
            h: *h,
            g_x: *g_x,
            h_x: *h_x,
        })
    }

    fn recover_commitment(
        &self,
        proof: &ProofOfDLogEquivalence,
    ) -> ThresholdEcdsaResult<(EccPoint, EccPoint)> {
        let g_z = self.g.scalar_mul(&proof.response)?;
        let h_z = self.h.scalar_mul(&proof.response)?;

        let g_r = g_z.sub_points(&self.g_x.scalar_mul(&proof.challenge)?)?;
        let h_r = h_z.sub_points(&self.h_x.scalar_mul(&proof.challenge)?)?;

        Ok((g_r, h_r))
    }

    fn hash_to_challenge(
        &self,
        c1: &EccPoint,
        c2: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<EccScalar> {
        let mut ro = ro::RandomOracle::new(PROOF_OF_DLOG_EQUIV_DST);
        ro.add_bytestring("associated_data", associated_data)?;
        ro.add_point("instance_g", &self.g)?;
        ro.add_point("instance_h", &self.h)?;
        ro.add_point("instance_g_x", &self.g_x)?;
        ro.add_point("instance_h_x", &self.h_x)?;
        ro.add_point("commitment1", c1)?;
        ro.add_point("commitment2", c2)?;
        ro.output_scalar(self.curve_type)
    }
}

impl ProofOfDLogEquivalence {
    /// Create a dlog equivalence proof
    pub fn create(
        seed: Seed,
        x: &EccScalar,
        g: &EccPoint,
        h: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<Self> {
        let instance = ProofOfDLogEquivalenceInstance::from_witness(g, h, x)?;

        // Compute blinding commitments:
        let mut rng = seed.into_rng();
        let r = EccScalar::random(instance.curve_type, &mut rng)?;
        let r_com_g = g.scalar_mul(&r)?;
        let r_com_h = h.scalar_mul(&r)?;

        // Compute the challenge:
        let challenge = instance.hash_to_challenge(&r_com_g, &r_com_h, associated_data)?;

        // Computing the opening:
        let response = x.mul(&challenge)?.add(&r)?;

        Ok(Self {
            challenge,
            response,
        })
    }

    /// Verify a dlog equivalence proof
    pub fn verify(
        &self,
        g: &EccPoint,
        h: &EccPoint,
        g_x: &EccPoint,
        h_x: &EccPoint,
        associated_data: &[u8],
    ) -> ThresholdEcdsaResult<()> {
        let instance = ProofOfDLogEquivalenceInstance::from_commitments(g, h, g_x, h_x)?;

        let (r_com_g, r_com_h) = instance.recover_commitment(self)?;

        if self.challenge != instance.hash_to_challenge(&r_com_g, &r_com_h, associated_data)? {
            return Err(ThresholdEcdsaError::InvalidProof);
        }

        Ok(())
    }
}
