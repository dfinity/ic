pub mod v1 {
    use crate::proxy::ProxyDecodeError;
    use ic_error_types::RejectCode as RejectCodePublic;
    use prost::Message;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    include!("gen/types/types.v1.rs");

    impl CatchUpPackage {
        /// Read and deserialize a protobuf CatchUpPackage from the provided
        /// file.
        pub fn read_from_file<P: AsRef<Path> + std::fmt::Debug>(
            filepath: P,
        ) -> Result<Self, String> {
            let cup_file =
                File::open(&filepath).map_err(|e| format!("open failed: {filepath:?}: {e:?}"))?;
            Self::read_from_reader(cup_file)
        }

        /// Deserialize a protobuf CatchUpPackage from the provided reader
        pub fn read_from_reader<R: Read>(mut reader: R) -> Result<Self, String> {
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .map_err(|e| format!("read failed: {e:?}"))?;
            Self::decode(&buf[..]).map_err(|e| format!("protobuf decode failed: {e:?}"))
        }
    }

    impl CatchUpContent {
        pub fn as_protobuf_vec(&self) -> Vec<u8> {
            let mut buf = Vec::<u8>::new();
            self.encode(&mut buf)
                .expect("CatchUpContent should serialize");
            buf
        }
    }

    impl From<RejectCodePublic> for RejectCode {
        fn from(value: RejectCodePublic) -> Self {
            match value {
                RejectCodePublic::SysFatal => RejectCode::SysFatal,
                RejectCodePublic::SysTransient => RejectCode::SysTransient,
                RejectCodePublic::DestinationInvalid => RejectCode::DestinationInvalid,
                RejectCodePublic::CanisterReject => RejectCode::CanisterReject,
                RejectCodePublic::CanisterError => RejectCode::CanisterError,
                RejectCodePublic::SysUnknown => RejectCode::SysUnknown,
            }
        }
    }

    impl TryFrom<RejectCode> for RejectCodePublic {
        type Error = ProxyDecodeError;

        fn try_from(value: RejectCode) -> Result<Self, Self::Error> {
            match value {
                RejectCode::Unspecified => Err(ProxyDecodeError::ValueOutOfRange {
                    typ: "RejectCode",
                    err: format!("Unexpected value for reject code {value:?}"),
                }),
                RejectCode::SysFatal => Ok(RejectCodePublic::SysFatal),
                RejectCode::SysTransient => Ok(RejectCodePublic::SysTransient),
                RejectCode::DestinationInvalid => Ok(RejectCodePublic::DestinationInvalid),
                RejectCode::CanisterReject => Ok(RejectCodePublic::CanisterReject),
                RejectCode::CanisterError => Ok(RejectCodePublic::CanisterError),
                RejectCode::SysUnknown => Ok(RejectCodePublic::SysUnknown),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::RejectCode as RejectCodeProto;
        use ic_error_types::RejectCode;
        use strum::IntoEnumIterator;

        #[test]
        fn reject_code_round_trip() {
            for initial in RejectCode::iter() {
                let encoded = RejectCodeProto::from(initial);
                let round_trip = RejectCode::try_from(encoded).unwrap();
                assert_eq!(initial, round_trip);
            }
        }
    }
}
