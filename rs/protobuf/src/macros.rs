/// Declare a sub-module of the `log` module
#[macro_export]
macro_rules! import_mod {
    ($prefix:literal, $module:ident, $version:ident $(, { $($it:item)+ })?) => {
        pub mod $module {
            pub mod $version {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/",
                    $prefix,
                    "/",
                    $prefix,
                    ".",
                    stringify!($module),
                    ".",
                    stringify!($version),
                    ".rs"
                ));

                $($($it)+)?
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
