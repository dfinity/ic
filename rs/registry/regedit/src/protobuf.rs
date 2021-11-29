use prost::Message;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use ic_protobuf::{
    registry::{
        conversion_rate::v1::IcpXdrConversionRateRecord,
        crypto::v1::{PublicKey, X509PublicKeyCert},
        firewall::v1::FirewallConfig,
        nns::v1::NnsCanisterRecords,
        node_operator::v1::NodeOperatorRecord,
        provisional_whitelist::v1::ProvisionalWhitelist,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
        routing_table::v1::RoutingTable,
        subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord},
    },
    types::v1::SubnetId as SubnetIdProto,
};
use ic_registry_client::helper::node::NodeRecord;
use ic_registry_keys::{
    make_blessed_replica_version_key, make_firewall_config_record_key,
    make_icp_xdr_conversion_rate_record_key, make_nns_canister_records_key,
    make_provisional_whitelist_record_key, make_routing_table_record_key,
    make_subnet_list_record_key, CRYPTO_RECORD_KEY_PREFIX, CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX,
    CRYPTO_TLS_CERT_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
    REPLICA_VERSION_KEY_PREFIX, ROOT_SUBNET_ID_KEY, SUBNET_RECORD_KEY_PREFIX,
};
pub(crate) trait Transformable {
    fn pb_to_value(data: &[u8]) -> Value;
    fn value_to_pb(value: Value) -> Vec<u8>;

    fn transformers() -> Transformers {
        Transformers {
            d: Self::pb_to_value,
            s: Self::value_to_pb,
        }
    }
}

impl<T> Transformable for T
where
    T: Serialize + DeserializeOwned + Message + Default,
{
    fn pb_to_value(data: &[u8]) -> Value {
        let t = Self::decode(data).expect("Could not deserialize protobuf.");
        serde_json::to_value(&t).expect("Failed to serialize struct to json Value.")
    }

    fn value_to_pb(value: Value) -> Vec<u8> {
        let t = serde_json::from_value::<Self>(value).expect("Could not deserialize json Value.");
        let mut buf = Vec::new();
        t.encode(&mut buf).expect("Could not encode as protobuf.");
        buf
    }
}
pub(crate) struct Transformers {
    pub d: fn(&[u8]) -> Value,
    pub s: fn(Value) -> Vec<u8>,
}

pub(crate) fn raw_data_to_value(key: &str, data: &[u8]) -> Value {
    (get_transformer(key).d)(data)
}

pub(crate) fn value_to_raw_data(key: &str, value: Value) -> Vec<u8> {
    (get_transformer(key).s)(value)
}

/// Translates the protobuf encoded values (of a key/value pair) into a
/// self-describing structure. The semantics of JSON are used for the latter.
fn get_transformer(key: &str) -> Transformers {
    if key == ROOT_SUBNET_ID_KEY {
        SubnetIdProto::transformers()
    } else if key == make_subnet_list_record_key() {
        SubnetListRecord::transformers()
    } else if key == make_icp_xdr_conversion_rate_record_key() {
        IcpXdrConversionRateRecord::transformers()
    } else if key.starts_with(NODE_RECORD_KEY_PREFIX) {
        NodeRecord::transformers()
    } else if key.starts_with(NODE_OPERATOR_RECORD_KEY_PREFIX) {
        NodeOperatorRecord::transformers()
    } else if key.starts_with(REPLICA_VERSION_KEY_PREFIX) {
        ReplicaVersionRecord::transformers()
    } else if key.starts_with(SUBNET_RECORD_KEY_PREFIX) {
        SubnetRecord::transformers()
    } else if key.starts_with(CRYPTO_RECORD_KEY_PREFIX) {
        PublicKey::transformers()
    } else if key.starts_with(CRYPTO_TLS_CERT_KEY_PREFIX) {
        X509PublicKeyCert::transformers()
    } else if key.starts_with(CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX) {
        PublicKey::transformers()
    } else if key.starts_with(&make_firewall_config_record_key()) {
        FirewallConfig::transformers()
    } else if key.starts_with(&make_blessed_replica_version_key()) {
        BlessedReplicaVersions::transformers()
    } else if key.starts_with(&make_routing_table_record_key()) {
        RoutingTable::transformers()
    } else if key.starts_with(&make_provisional_whitelist_record_key()) {
        ProvisionalWhitelist::transformers()
    } else if key.starts_with("catch_up_package_contents_") {
        CatchUpPackageContents::transformers()
    } else if key.starts_with(&make_nns_canister_records_key()) {
        NnsCanisterRecords::transformers()
    } else {
        Transformers {
            d: unknown_message_to_value,
            s: value_to_bytes,
        }
    }
}

fn unknown_message_to_value(data: &[u8]) -> Value {
    serde_json::to_value(&data).expect("Could not serialize byte array to json Value.")
}

fn value_to_bytes(value: Value) -> Vec<u8> {
    value
        .as_array()
        .expect("Value is not an Object.")
        .iter()
        .map(|v| {
            let b = v.as_u64().expect("Entry in byte array is not a number.");
            if b > 0xff {
                panic!("Number in byte array is greater than 0xff.")
            }
            b as u8
        })
        .collect()
}
