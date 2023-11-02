use crate::{G1Affine, G1Projective, G2Affine, G2Projective, NodeIndex, Scalar};

#[derive(Copy, Clone, Debug)]
/// Error during interpolation
pub enum InterpolationError {
    /// The coefficients were empty
    NoCoefficients,
    /// A node index was duplicated
    DuplicatedNodeIndex,
    /// No samples were provided for interpolation
    NoSamples,
    /// The set of samples did not match the coefficient count
    WrongSampleCount,
}

/// Lagrange interpolation
pub struct LagrangeCoefficients {
    coefficients: Vec<Scalar>,
}

impl LagrangeCoefficients {
    fn new(coefficients: Vec<Scalar>) -> Result<Self, InterpolationError> {
        if coefficients.is_empty() {
            return Err(InterpolationError::NoCoefficients);
        }

        Ok(Self { coefficients })
    }

    /// Computes Lagrange polynomials evaluated at zero
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0) * (x_1) * ... * (x_(i-1)) *(x_(i+1)) * ... *(x_n)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_zero(samples: &[NodeIndex]) -> Result<Self, InterpolationError> {
        Self::at_value(Scalar::zero_ref(), samples)
    }

    /// Computes Lagrange polynomials evaluated at a given value.
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0-value) * (x_1-value) * ... * (x_(i-1)-value) *(x_(i+1)-value) * ... *(x_n-value)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_value(value: &Scalar, samples: &[NodeIndex]) -> Result<Self, InterpolationError> {
        // This is not strictly required but for our usage it simplifies matters
        if samples.is_empty() {
            return Err(InterpolationError::NoSamples);
        }

        if samples.len() == 1 {
            return Self::new(vec![Scalar::one()]);
        }

        Self::check_for_duplicates(samples)?;

        let samples: Vec<Scalar> = samples
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

        for (lagrange_i, x_i) in numerator.iter_mut().zip(&samples) {
            // Compute the value at 0 of the i-th Lagrange polynomial that is `0` at the
            // other data points but `1` at `x_i`.
            let mut denom = Scalar::one();
            for x_j in samples.iter().filter(|x_j| *x_j != x_i) {
                denom *= x_j - x_i;
            }

            let inv = match denom.inverse() {
                None => return Err(InterpolationError::DuplicatedNodeIndex),
                Some(inv) => inv,
            };

            *lagrange_i *= inv;
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
        }

        Ok(Scalar::muln_vartime(y, &self.coefficients))
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_g1<T: AsRef<G1Affine>>(
        &self,
        y: &[T],
    ) -> Result<G1Affine, InterpolationError> {
        if y.len() != self.coefficients.len() {
            return Err(InterpolationError::WrongSampleCount);
        }

        Ok(G1Projective::muln_affine_vartime(y, &self.coefficients).to_affine())
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_g2<T: AsRef<G2Affine>>(
        &self,
        y: &[T],
    ) -> Result<G2Affine, InterpolationError> {
        if y.len() != self.coefficients.len() {
            return Err(InterpolationError::WrongSampleCount);
        }

        Ok(G2Projective::muln_affine_vartime(y, &self.coefficients).to_affine())
    }

    /// Check for duplicate dealer indexes
    ///
    /// Since these are public we don't need to worry about the lack of constant
    /// time behavior from HashSet
    fn check_for_duplicates(node_index: &[NodeIndex]) -> Result<(), InterpolationError> {
        let mut set = std::collections::HashSet::new();

        for i in node_index {
            if !set.insert(i) {
                return Err(InterpolationError::DuplicatedNodeIndex);
            }
        }

        Ok(())
    }
}
