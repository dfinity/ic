use crate::import_mod;

import_mod!("log", replica_config, v1, "replica_config.v1");
import_mod!("log", consensus_log_entry, v1, "consensus_log_entry.v1");
import_mod!("log", crypto_log_entry, v1, "crypto_log_entry.v1");
import_mod!("log", p2p_log_entry, v1, "p2p_log_entry.v1");
import_mod!("log", messaging_log_entry, v1, "messaging_log_entry.v1");
import_mod!(
    "log",
    ingress_message_log_entry,
    v1,
    "ingress_message_log_entry.v1"
);
import_mod!("log", block_log_entry, v1, "block_log_entry.v1");
import_mod!(
    "log",
    malicious_behaviour_log_entry,
    v1,
    "malicious_behaviour_log_entry.v1"
);

pub mod log_entry {
    pub mod v1 {
        include!(std::concat!("../gen/log/log.log_entry.v1.rs"));

        impl slog::Value for LogEntry {
            fn serialize(
                &self,
                _record: &slog::Record<'_>,
                key: slog::Key,
                serializer: &mut dyn slog::Serializer,
            ) -> slog::Result {
                serializer.emit_serde(&key, self)
            }
        }

        impl slog::SerdeValue for LogEntry {
            fn serialize_fallback(
                &self,
                _key: slog::Key,
                ser: &mut dyn slog::Serializer,
            ) -> slog::Result<()> {
                crate::serialize_fallback_for!(self, ser, consensus);
                crate::serialize_fallback_for!(self, ser, crypto);
                crate::serialize_fallback_for!(self, ser, p2p);
                crate::serialize_fallback_for!(self, ser, messaging);
                crate::serialize_fallback_for!(self, ser, ingress_message);
                crate::serialize_fallback_for!(self, ser, block);
                crate::serialize_fallback_for!(self, ser, malicious_behaviour);
                Ok(())
            }

            fn as_serde(&self) -> &dyn erased_serde::Serialize {
                self
            }

            fn to_sendable(&self) -> Box<dyn slog::SerdeValue + Send + 'static> {
                Box::new(self.clone())
            }
        }
    }
}
