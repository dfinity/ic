use crate::*;
use std::collections::BTreeMap;

/// A Random Oracle (based on XMD)
///
/// Consumes inputs of various types and constructs an unambigious
/// input which is provided to a random oracle, producing an output of
/// the desired type: an elliptic curve point, an elliptic curve
/// scalar, or a bytestring.
///
/// Inputs are tagged by a name string, and these names are included
/// in the RO input along with the data. Names can be at most 255
/// bytes long, and should be literal constants.
///
/// The RO sorts the inputs by name so the insertion order of data
/// does not affect the output.
pub struct RandomOracle {
    domain_separator: String,
    input_size: usize,
    inputs: BTreeMap<String, Vec<u8>>,
}

enum RandomOracleInputType {
    Bytestring,
    Integer,
    Point,
    Scalar,
}

impl RandomOracleInputType {
    fn tag(&self) -> u8 {
        match self {
            Self::Bytestring => 1,
            Self::Integer => 2,
            Self::Point => 3,
            Self::Scalar => 4,
        }
    }
}

impl RandomOracle {
    /// Create a new RandomOracle instance
    ///
    /// The domain separator should be unique for this usage. The
    /// &'static annotation is to help ensure that this value is a
    /// constant and not generated dynamically.
    pub fn new(domain_separator: &'static str) -> Self {
        Self {
            domain_separator: domain_separator.to_string(),
            input_size: 0,
            inputs: BTreeMap::new(),
        }
    }

    /// Add input to the random oracle (internal function)
    ///
    /// The inputs are encoded using a standard format:
    /// * Type identifier - 1 byte
    /// * Curve identifier - 1 byte, only if needed for points/scalars; this
    ///   is the return value of EccCurveType::tag()
    /// * Data length - 4 bytes
    /// * The data itself
    ///
    /// Since the input length must be encodable into 4 bytes, inputs larger
    /// than 2**32-1 bytes are rejected.
    ///
    /// Names are encoded by prefixing with a 1 byte length field; as
    /// a result names can be at most 255 bytes. To avoid confusion,
    /// empty names are also prohibited.
    fn add_input(
        &mut self,
        name: &str,
        input: &[u8],
        ty: RandomOracleInputType,
        curve_tag: Option<u8>,
    ) -> ThresholdEcdsaResult<()> {
        if self.inputs.contains_key(name) {
            return Err(ThresholdEcdsaError::InvalidRandomOracleInput);
        }

        if name.is_empty() || name.len() != (name.len() as u8) as usize {
            return Err(ThresholdEcdsaError::InvalidRandomOracleInput);
        }

        if input.len() != (input.len() as u32) as usize {
            return Err(ThresholdEcdsaError::InvalidRandomOracleInput);
        }

        let curve_tag_len = if curve_tag.is_some() { 1 } else { 0 };
        let mut encoded_input = Vec::with_capacity(1 + 4 + curve_tag_len + input.len());

        encoded_input.extend_from_slice(&[ty.tag()]);
        if let Some(curve_tag) = curve_tag {
            encoded_input.extend_from_slice(&[curve_tag]);
        }
        encoded_input.extend_from_slice(&(input.len() as u32).to_be_bytes());
        encoded_input.extend_from_slice(input);

        self.input_size += 1 + name.len() + encoded_input.len();

        self.inputs.insert(name.to_string(), encoded_input);

        Ok(())
    }

    /// Add a point to the input
    ///
    /// The name must be a unique identifier for this random oracle invocation
    pub fn add_point(&mut self, name: &'static str, pt: &EccPoint) -> ThresholdEcdsaResult<()> {
        self.add_input(
            name,
            &pt.serialize(),
            RandomOracleInputType::Point,
            Some(pt.curve_type().tag()),
        )
    }

    /// Add several points to the input
    ///
    /// The name must be a unique identifier for this random oracle invocation
    pub fn add_points(&mut self, name: &'static str, pts: &[EccPoint]) -> ThresholdEcdsaResult<()> {
        for (i, pt) in pts.iter().enumerate() {
            self.add_input(
                &format!("{}[{}]", name, i),
                &pt.serialize(),
                RandomOracleInputType::Point,
                Some(pt.curve_type().tag()),
            )?;
        }

        Ok(())
    }

    /// Add a scalar to the input
    ///
    /// The name must be a unique identifier for this random oracle invocation
    pub fn add_scalar(&mut self, name: &'static str, s: &EccScalar) -> ThresholdEcdsaResult<()> {
        self.add_input(
            name,
            &s.serialize(),
            RandomOracleInputType::Scalar,
            Some(s.curve_type().tag()),
        )
    }

    /// Add a byte string to the input
    ///
    /// The name must be a unique identifier for this random oracle invocation
    /// The byte string can be at most 2**32-1 bytes
    pub fn add_bytestring(&mut self, name: &'static str, v: &[u8]) -> ThresholdEcdsaResult<()> {
        self.add_input(name, v, RandomOracleInputType::Bytestring, None)
    }

    /// Add an integer to the input
    ///
    /// The name must be a unique identifier for this random oracle invocation
    pub fn add_u64(&mut self, name: &'static str, i: u64) -> ThresholdEcdsaResult<()> {
        self.add_input(name, &i.to_be_bytes(), RandomOracleInputType::Integer, None)
    }

    /// Add an integer to the input
    ///
    /// The name must be a unique identifier for this random oracle invocation
    pub fn add_usize(&mut self, name: &'static str, i: usize) -> ThresholdEcdsaResult<()> {
        self.add_u64(name, i as u64)
    }

    fn form_ro_input(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        if self.inputs.is_empty() {
            return Err(ThresholdEcdsaError::InvalidRandomOracleInput);
        }

        let mut input = Vec::with_capacity(self.input_size);

        // We rely on BTreeMap to produce the inputs in an ordered/deterministic way
        for (name, data) in &self.inputs {
            input.extend_from_slice(&(name.len() as u8).to_be_bytes());
            input.extend_from_slice(name.as_bytes());

            input.extend_from_slice(data); // already prefixed with length/tag
        }

        assert_eq!(input.len(), self.input_size);

        Ok(input)
    }

    /// Consume the random oracle and generate a bytestring as output
    ///
    /// Due to limitations of XMD this can produce only a limited amount of data,
    /// at most 8160 bytes.
    pub fn output_bytestring(self, output_length: usize) -> ThresholdEcdsaResult<Vec<u8>> {
        let ro_input = self.form_ro_input()?;

        xmd::expand_message_xmd(&ro_input, self.domain_separator.as_bytes(), output_length)
    }

    /// Consume the random oracle and generate a point as output
    pub fn output_point(self, curve_type: EccCurveType) -> ThresholdEcdsaResult<EccPoint> {
        let ro_input = self.form_ro_input()?;

        EccPoint::hash_to_point(
            curve_type,
            &ro_input,
            format!("{}-{}", self.domain_separator, curve_type).as_bytes(),
        )
    }

    /// Consume the random oracle and generate a scalar output
    pub fn output_scalar(self, curve_type: EccCurveType) -> ThresholdEcdsaResult<EccScalar> {
        Ok(self.output_scalars(curve_type, 1)?[0])
    }

    /// Consume the random oracle and generate several scalar outputs
    ///
    /// Due to limitations of XMD this can produce only a limited number of
    /// outputs - 170 in the case of secp256k1.
    pub fn output_scalars(
        self,
        curve_type: EccCurveType,
        cnt: usize,
    ) -> ThresholdEcdsaResult<Vec<EccScalar>> {
        let ro_input = self.form_ro_input()?;

        EccScalar::hash_to_several_scalars(
            curve_type,
            cnt,
            &ro_input,
            format!("{}-{}", self.domain_separator, curve_type).as_bytes(),
        )
    }
}
