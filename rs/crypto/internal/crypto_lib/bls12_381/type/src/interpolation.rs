use crate::{G1Affine, G1Projective, G2Affine, G2Projective, NodeIndex, Scalar};

#[derive(Copy, Clone, Debug)]
/// Error when constructing NodeIndices
pub enum InvalidNodeIndices {
    /// A node index was duplicated
    DuplicatedNodeIndex,
}

#[derive(Copy, Clone, Debug)]
/// Error during interpolation
pub enum InterpolationError {
    /// No samples were provided for interpolation
    NoSamples,
    /// The set of samples did not match the coefficient count
    WrongSampleCount,
}

/// Lagrange interoplation samples
pub struct NodeIndices {
    indices: Vec<NodeIndex>,
}

impl NodeIndices {
    /// Construct a NodeIndices from a slice of NodeIndex values
    ///
    /// This function will fail if there are any duplicated indices
    pub fn from_slice(indices: &[NodeIndex]) -> Result<Self, InvalidNodeIndices> {
        // We assume the node indices are public, so variable time behavior is ok
        let mut seen = std::collections::HashSet::new();

        for nidx in indices {
            if !seen.insert(nidx) {
                return Err(InvalidNodeIndices::DuplicatedNodeIndex);
            }
        }

        Ok(Self {
            indices: indices.to_vec(),
        })
    }

    /// Construct a NodeIndices from a BTreeMap with NodeIndex keys
    ///
    /// The values of the BTreeMap are ignored
    pub fn from_map<T>(map: &std::collections::BTreeMap<NodeIndex, T>) -> Self {
        // The BTreeMap keys are already guaranteed to be unique
        let indices = map.keys().copied().collect();
        Self { indices }
    }

    /// Construct a NodeIndices from a BTreeSet with NodeIndex values
    pub fn from_set(map: &std::collections::BTreeSet<NodeIndex>) -> Self {
        // The BTreeSet values are already guaranteed to be unique
        let indices = map.iter().copied().collect();
        Self { indices }
    }
}

/// Lagrange interpolation
pub struct LagrangeCoefficients {
    coefficients: Vec<Scalar>,
}

impl LagrangeCoefficients {
    fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// Computes Lagrange polynomials evaluated at zero
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0) * (x_1) * ... * (x_(i-1)) *(x_(i+1)) * ... *(x_n)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_zero(samples: &NodeIndices) -> Self {
        Self::at_value(Scalar::zero_ref(), samples)
    }

    /// Computes Lagrange polynomials evaluated at a given value.
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0-value) * (x_1-value) * ... * (x_(i-1)-value) *(x_(i+1)-value) * ... *(x_n-value)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_value(value: &Scalar, samples: &NodeIndices) -> Self {
        if samples.indices.is_empty() {
            return Self::new(vec![]);
        }

        if samples.indices.len() == 1 {
            return Self::new(vec![Scalar::one()]);
        }

        let samples: Vec<Scalar> = samples
            .indices
            .iter()
            .map(|s| Scalar::from_node_index(*s))
            .collect();

        let mut numerator = Vec::with_capacity(samples.len());
        let mut tmp = Scalar::one();
        numerator.push(tmp.clone());
        for x in samples.iter().take(samples.len() - 1) {
            tmp *= x - value;
            numerator.push(tmp.clone());
        }

        tmp = Scalar::one();
        for (i, x) in samples[1..].iter().enumerate().rev() {
            tmp *= x - value;
            numerator[i] *= &tmp;
        }

        let mut denominator = Vec::with_capacity(samples.len());

        for i in 0..samples.len() {
            // Compute the value at 0 of the i-th Lagrange polynomial that is `0` at the
            // other data points but `1` at `x_i`.
            let mut denom = Scalar::one();
            let x_i = samples[i].clone();
            for x_j in samples.iter().filter(|x_j| **x_j != x_i) {
                denom *= x_j - &x_i;
            }

            denominator.push(denom);
        }

        /*
         * This expect can never fire because:
         *
         * 1) The denom is in the prime order scalar group. Thus the only value which
         *    does not have a valid inverse is zero.
         * 2) We initialize each value denom with 1.
         * 3) We multiply into denom various values, all of which are non-zero
         *     (because in the loop x_j - x_i must be non-zero)
         * 4) Since denom is not equal to zero, the inverse must exist.
         */
        let inv_denominator =
            Scalar::batch_inverse_vartime(&denominator).expect("Inversion unexpectedly failed");

        for i in 0..samples.len() {
            numerator[i] *= &inv_denominator[i];
        }
        Self::new(numerator)
    }

    /// Return the Lagrange coefficients
    pub fn coefficients(&self) -> &[Scalar] {
        &self.coefficients
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some integer `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_scalar(&self, y: &[Scalar]) -> Result<Scalar, InterpolationError> {
        if y.len() != self.coefficients.len() {
            return Err(InterpolationError::WrongSampleCount);
        } else if y.is_empty() {
            return Err(InterpolationError::NoSamples);
        }

        Ok(Scalar::muln_vartime(y, &self.coefficients))
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_g1(&self, y: &[G1Affine]) -> Result<G1Affine, InterpolationError> {
        if y.len() != self.coefficients.len() {
            return Err(InterpolationError::WrongSampleCount);
        } else if y.is_empty() {
            return Err(InterpolationError::NoSamples);
        }

        Ok(G1Projective::muln_affine_vartime(y, &self.coefficients).to_affine())
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_g2(&self, y: &[G2Affine]) -> Result<G2Affine, InterpolationError> {
        if y.len() != self.coefficients.len() {
            return Err(InterpolationError::WrongSampleCount);
        } else if y.is_empty() {
            return Err(InterpolationError::NoSamples);
        }

        Ok(G2Projective::muln_affine_vartime(y, &self.coefficients).to_affine())
    }
}
