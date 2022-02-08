pub mod v1 {
    use prost::Message;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    include!(std::concat!("../gen/types/types.v1.rs"));

    impl CatchUpPackage {
        /// Read and deserialize a protobuf CatchUpPackage from the provided
        /// file.
        pub fn read_from_file<P: AsRef<Path> + std::fmt::Debug>(
            filepath: P,
        ) -> Result<Self, String> {
            let cup_file = File::open(&filepath)
                .map_err(|e| format!("open failed: {:?}: {:?}", filepath, e))?;
            Self::read_from_reader(cup_file)
        }

        /// Deserialize a protobuf CatchUpPackage from the provided reader
        pub fn read_from_reader<R: Read>(mut reader: R) -> Result<Self, String> {
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .map_err(|e| format!("read failed: {:?}", e))?;
            Self::decode(&buf[..]).map_err(|e| format!("protobuf decode failed: {:?}", e))
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
}
