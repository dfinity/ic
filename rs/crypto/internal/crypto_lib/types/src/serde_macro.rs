//! Macros for serialization and deserialization.

/// A custom macro to serialize from and to bytes.
#[macro_export]
macro_rules! derive_serde {
    ($name:ident, $size:expr) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::ser::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }

        impl<'a> serde::Deserialize<'a> for $name {
            fn deserialize<D: serde::de::Deserializer<'a>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                struct Visitor;

                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        write!(formatter, "a blob with with {} bytes", $size)
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        let mut bytes: [u8; $size] = [0; $size];
                        bytes.copy_from_slice(v);
                        Ok($name(bytes))
                    }
                }

                deserializer.deserialize_bytes(Visitor)
            }
        }
    };
}
