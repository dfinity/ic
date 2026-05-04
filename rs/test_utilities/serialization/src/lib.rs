#[cfg(test)]
mod prost {
    use ic_protobuf::messaging::xnet::v1::{
        Witness,
        witness::{Fork, Known, WitnessEnum},
    };
    use prost::{DecodeError, Message};

    /// Produces a recursive `Witness` of the requested height.
    fn recursive_witness(height: usize) -> Witness {
        let known = Witness {
            witness_enum: Some(WitnessEnum::Known(Known {})),
        };
        let mut witness = known.clone();

        for _ in 0..height {
            witness = Witness {
                witness_enum: Some(WitnessEnum::Fork(
                    Fork {
                        left_tree: Some(witness.into()),
                        right_tree: Some(known.clone().into()),
                    }
                    .into(),
                )),
            }
        }

        witness
    }

    /// Does an encode-decode roundtrip of the provided `Witness`, returning the result.
    fn encoding_roundtrip(witness: &Witness) -> Result<Witness, DecodeError> {
        let mut buf = vec![];
        witness.encode(&mut buf).expect("failed to serialize");
        Witness::decode(buf.as_slice())
    }

    #[test]
    fn decode_recursion_limit() {
        // A `Witness` of height 49 results in a struct of depth 49 * 2 + 1 = 99
        // (because there's a `WitnessEnum` wrapped inside a `Witness` struct at every
        // level).
        let witness = recursive_witness(49);
        let result = encoding_roundtrip(&witness);
        assert_eq!(Ok(witness), result);

        // A `Witness` of height 50 results in a struct of depth 101. `prost` should
        // refuse to decode it.
        let witness = recursive_witness(50);
        let result = encoding_roundtrip(&witness);
        assert!(
            result
                .expect_err("recursion limit not reached")
                .to_string()
                .contains("recursion limit reached")
        );
    }
}

#[cfg(test)]
mod serde_cbor {
    use assert_matches::assert_matches;
    use serde_cbor::{Value, from_slice};

    /// Returns a CBOR encoded vector containing a vector, containing a vector, etc.
    /// recursively to the requested depth.
    fn recursive_vec(depth: usize) -> Vec<u8> {
        // 81             # array(1)
        //    81          # array(1)
        //       81       # array(1)
        //          ...
        //             01 # unsigned(1)
        let mut buf = vec![0x81; depth];
        buf.push(0x01);
        buf
    }

    #[test]
    fn decode_recursion_limit() {
        // Can decode a recursive array of depth 127.
        let buf = recursive_vec(127);
        assert_matches!(
            from_slice::<Value>(&buf),
            Ok(Value::Array(v)) if v.len() == 1
        );

        // But not a recursive array of depth 128.
        let buf = recursive_vec(128);
        assert!(
            from_slice::<Value>(&buf)
                .expect_err("recursion limit not reached")
                .to_string()
                .contains("recursion limit exceeded")
        );
    }
}

#[cfg(test)]
mod serde_json {
    use assert_matches::assert_matches;
    use serde_json::{Value, from_slice};

    /// Returns a JSON encoded vector containing a vector, containing a vector, etc.
    /// recursively to the requested depth.
    fn recursive_vec(depth: usize) -> Vec<u8> {
        let mut buf = vec![b'['; depth];
        buf.push(b'1');
        buf.append(&mut vec![b']'; depth]);
        buf
    }

    #[test]
    fn decode_recursion_limit() {
        // Can decode a recursive array of depth 127.
        let buf = recursive_vec(127);
        assert_matches!(
            from_slice::<Value>(&buf),
            Ok(Value::Array(v)) if v.len() == 1
        );

        // But not a recursive array of depth 128.
        let buf = recursive_vec(128);
        assert!(
            from_slice::<Value>(&buf)
                .expect_err("recursion limit not reached")
                .to_string()
                .contains("recursion limit exceeded")
        );
    }
}
