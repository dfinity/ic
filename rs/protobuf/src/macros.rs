/// Declare a sub-module of the `log` module
#[macro_export]
macro_rules! import_mod {
    // "block" variant to support additional code in the module, e.g., to
    // implement conversion methods
    ($prefix:literal, $module:ident, $version:ident, $file_part:literal, $body:tt) => {
        pub mod $module {
            pub mod $version {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/", $prefix, "/", $prefix, ".", $file_part, ".rs"
                ));

                pub mod body $body
            }
        }
    };

    ($prefix:literal, $module:ident, $version:ident, $file_part:literal) => {
        pub mod $module {
            pub mod $version {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/", $prefix, "/", $prefix, ".", $file_part, ".rs"
                ));
            }
        }
    };
}

/// Emit the given `LogEntry` field in `LogEntry.serialize_fallback`
#[macro_export(local_inner_macros)]
macro_rules! serialize_fallback_for {
    ($log_entry:expr, $serializer:expr, $field:ident) => {
        match &$log_entry.$field {
            Some(ctx) => {
                let json = serde_json::to_string(&ctx).map_err(|e| {
                    slog::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        std::format!("Serialization error: {}", e),
                    ))
                })?;
                let key = std::stringify!($field);
                $serializer.emit_str(key, json.as_str())?;
            }
            None => (),
        }
    };
}
