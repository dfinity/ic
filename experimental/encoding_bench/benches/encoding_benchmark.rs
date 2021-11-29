use capnp::message;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use encoding_bench::capnproto;
use encoding_bench::vanilla;
use prost::Message;
use rmp_serde;
use serde_cbor::ser;
use serde_json;
use std::iter::repeat;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PATH_KEY: &str = "PATH";
const LOCAL_PATH: &str = "/usr/local/bin";

// Include the prost-build generated IngressWire struct
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/encoding_bench.proto.rs"));
}

// ingress_generated.rs is generated via flatc-compiler that translates flatbuffer-IDL files into
// rust-files. The imported file was generated using the following command
//
//  $ flatc --rust ingress.fbs
//
// (flatc version 1.11.0)
//
// On OS X, you can install flatc with `brew install flatbuffers`.
#[path = "./../flatbuffers/ingress_generated.rs"]
mod ingress_generated;
#[allow(unused_imports)]
use flatbuffers::{Vector as FlatVector, WIPOffset};
#[allow(unused_imports)]
use ingress_generated::encoding_bench::ingress::{
    get_root_as_ingress, Ingress as FlatIngress, IngressArgs as FlatIngressArgs,
};

#[path = "./../thrift/ingress.rs"]
mod ingress_thrift;

// we test different payload sizes. The expectation is that with larger (binary) payloads, the
// differences between the encodings get smaller.
const SMALL_PAYLOAD_SIZE: usize = 16; // 16 bytes
const MEDIUM_PAYLOAD_SIZE: usize = 128; // 128 bytes
const LARGE_PAYLOAD_SIZE: usize = 512 * 1024; // 512 KiBytes

pub fn benchmark_all_payload_sizes(c: &mut Criterion) {
    criterion_benchmark(c, SMALL_PAYLOAD_SIZE);
    criterion_benchmark(c, MEDIUM_PAYLOAD_SIZE);
    criterion_benchmark(c, LARGE_PAYLOAD_SIZE);
}

pub fn criterion_benchmark(c: &mut Criterion, ingress_payload_size: usize) {
    // we want some diversity wrt. to the numbers that we use in order to force different lengths
    // of varint encodings.
    let source: u64 = 42;
    let receiver: u64 = 1025;
    let method_name = "query test".to_string();
    let method_payload: Vec<u8> = repeat(0x32).take(ingress_payload_size).collect::<Vec<u8>>();
    let message_id: u64 = i64::max_value() as u64;
    let message_time = SystemTime::now();

    // the buffer that we are going to serialize to/deserialize from
    let mut buf = Vec::new();

    // Setup vanilla struct for all encodings that are supported by serde.
    let ingress_msg = vanilla::Ingress {
        source,
        receiver,
        method_name: method_name.clone(),
        method_payload: method_payload.clone(),
        message_id,
        message_time: message_time,
    };

    let mut group = c.benchmark_group(&format!("Ingress Encode/Decode/{}", ingress_payload_size));
    group.throughput(Throughput::Bytes(ingress_msg.payload_size() as u64));

    // Prepare the FlatBufferBuilder outside the benchmark loop, to be realistic
    // with expected real-world use.
    let mut flat_buffer_builder = flatbuffers::FlatBufferBuilder::new();
    group.bench_function("flatbuffers", |b| {
        b.iter(|| {
            flat_buffer_builder.reset();
            let flat_method_name = Some(flat_buffer_builder.create_string(&method_name));
            let flat_method_payload = Some(flat_buffer_builder.create_vector(&method_payload));
            let flat_ingress_args = &FlatIngressArgs {
                source,
                receiver,
                method_name: flat_method_name,
                method_payload: flat_method_payload,
                message_id,
                message_time_ns: message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            };
            let flat_ingress = FlatIngress::create(&mut flat_buffer_builder, &flat_ingress_args);
            flat_buffer_builder.finish(flat_ingress, None);
            let decoded = get_root_as_ingress(flat_buffer_builder.finished_data());
            assert_eq!(source, decoded.source());
            assert_eq!(receiver, decoded.receiver());
            assert_eq!(method_name, decoded.method_name().unwrap());
            assert_eq!(method_payload, decoded.method_payload().unwrap());
            assert_eq!(message_id, decoded.message_id());
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns()))
                    .unwrap()
            );
        });
    });
    println!("flatbuffers size: {}", flat_buffer_builder.finished_data().len());

    group.bench_function("bincode", |b| {
        b.iter(|| {
            buf.clear();
            let msg_wire = vanilla::IngressWire {
                source: source,
                receiver: receiver,
                method_name: method_name.clone(),
                method_payload: method_payload.clone(),
                message_id: message_id,
                message_time_ns: message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            };
            buf = bincode::serialize(&msg_wire).unwrap();
            let decoded: vanilla::IngressWire = bincode::deserialize(&buf[..]).unwrap();
            assert_eq!(source, decoded.source);
            assert_eq!(receiver, decoded.receiver);
            assert_eq!(method_name, decoded.method_name);
            assert_eq!(method_payload, decoded.method_payload);
            assert_eq!(message_id, decoded.message_id);
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns))
                    .unwrap()
            );
        });
    });
    println!("bincode size: {}", buf.len());

    // build.rs executes the capnc compiler, which must be installed on the system separately. On
    // OS X, you can `brew install capnp`.
    //
    // As the build path is different for the benchmark than for running the main binary, the
    // genereated rust-file was manually copied into the src/ directory.
    //
    // e.g., cp ./target/release/build/encoding_bench/out/capnproto/ingress_capnp.rs src/capnproto.rs
    group.bench_function("capnproto", |b| {
        b.iter(|| {
            buf.clear();
            let mut msg_capnp = message::Builder::new_default();
            let mut ingress_capnp = msg_capnp.init_root::<capnproto::ingress::Builder>();
            ingress_capnp.set_source(source);
            ingress_capnp.set_receiver(receiver);
            ingress_capnp.set_method_name(&method_name);
            ingress_capnp.set_method_payload(&method_payload[..]);
            ingress_capnp.set_message_id(message_id);
            ingress_capnp.set_message_time_ns(
                message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            );
            capnp::serialize::write_message(&mut buf, &msg_capnp).unwrap();
            let msg = capnp::serialize::read_message(&mut &buf[..], message::ReaderOptions::new())
                .unwrap();
            let decoded = msg.get_root::<capnproto::ingress::Reader>().unwrap();
            assert_eq!(source, decoded.get_source());
            assert_eq!(receiver, decoded.get_receiver());
            assert_eq!(method_name, decoded.get_method_name().unwrap());
            assert_eq!(method_payload, decoded.get_method_payload().unwrap());
            assert_eq!(message_id, decoded.get_message_id());
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.get_message_time_ns()))
                    .unwrap()
            );
        });
    });
    println!("capnproto size: {}", buf.len());

    use avro_rs::{from_value, types::Record, Reader, Schema, Writer};
    let avro_raw_schema = include_str!("../avro/ingress_wire.json");
    let avro_schema = Schema::parse_str(avro_raw_schema).unwrap();
    group.bench_function("avro", |b| {
        b.iter(|| {
            buf.clear();
            let mut record = Record::new(&avro_schema).unwrap();
            record.put("source", source as i64);
            record.put("receiver", receiver as i64);
            record.put("method_name", method_name.to_owned());
            record.put("method_payload", &method_payload[..]);
            record.put("message_id", message_id as i64);
            record.put(
                "message_time_ns",
                message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64,
            );
            let mut writer = Writer::new(&avro_schema, &mut buf);
            writer.append(record).unwrap();
            writer.flush().unwrap();
            let mut reader = Reader::with_schema(&avro_schema, &buf[..]).unwrap();
            let value = reader.next().unwrap();
            let decoded = from_value::<vanilla::IngressWire>(&value.unwrap()).unwrap();
            assert_eq!(source, decoded.source as u64);
            assert_eq!(receiver, decoded.receiver as u64);
            assert_eq!(method_name, decoded.method_name);
            assert_eq!(method_payload, decoded.method_payload);
            assert_eq!(message_id, decoded.message_id as u64);
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns as u64))
                    .unwrap()
            );
        });
    });
    println!("avro size: {}", buf.len());

    group.bench_function("thrift", |b| {
        use std::time::Instant;
        use thrift::protocol::{TCompactInputProtocol, TCompactOutputProtocol};

        // Thrift requires additional setup work that would ordinarily be done
        // once but needs to be repeated in each loop. Use a custom iterator to
        // perform more accurate timing, ignoring the time taken to construct
        // the TCompactOutputProtocol / TCompactInputProtocol objects.
        b.iter_custom(|iters| {
            let mut elapsed = std::time::Duration::new(0, 0);

            for _i in 0..iters {
                buf.clear();
                let mut out_protocol = TCompactOutputProtocol::new(&mut buf);

                let encoding_start = Instant::now();
                let msg_wire = ingress_thrift::Ingress {
                    source: Some(source as i64),
                    receiver: Some(receiver as i64),
                    method_name: Some(method_name.clone()),
                    method_payload: Some(method_payload.clone()),
                    message_id: Some(message_id as i64),
                    message_time_ns: Some(
                        message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64,
                    ),
                };
                msg_wire.write_to_out_protocol(&mut out_protocol).unwrap();
                elapsed += encoding_start.elapsed();

                let mut in_protocol = TCompactInputProtocol::new(&buf[..]);

                let decoding_start = Instant::now();
                let decoded =
                    ingress_thrift::Ingress::read_from_in_protocol(&mut in_protocol).unwrap();

                assert_eq!(source, decoded.source.unwrap() as u64);
                assert_eq!(receiver, decoded.receiver.unwrap() as u64);
                assert_eq!(method_name, decoded.method_name.unwrap());
                assert_eq!(method_payload, decoded.method_payload.unwrap());
                assert_eq!(message_id, decoded.message_id.unwrap() as u64);
                assert_eq!(
                    message_time,
                    UNIX_EPOCH
                        .checked_add(Duration::from_nanos(decoded.message_time_ns.unwrap() as u64))
                        .unwrap()
                );
                elapsed += decoding_start.elapsed()
            }
            elapsed
        });
    });
    println!("thrift size: {}", buf.len());

    group.bench_function("protobuf", |b| {
        b.iter(|| {
            buf.clear();
            let msg_wire = proto::IngressWire {
                source: source,
                receiver: receiver,
                method_name: method_name.clone(),
                method_payload: method_payload.clone(),
                message_id: message_id,
                message_time_ns: message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            };
            msg_wire.encode(&mut buf).unwrap();
            let decoded = proto::IngressWire::decode(&buf[..]).unwrap();
            assert_eq!(source, decoded.source);
            assert_eq!(receiver, decoded.receiver);
            assert_eq!(method_name, decoded.method_name);
            assert_eq!(method_payload, decoded.method_payload);
            assert_eq!(message_id, decoded.message_id);
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns))
                    .unwrap()
            );
        });
    });
    println!("protobuf size: {}", buf.len());

    group.bench_function("json", |b| {
        b.iter(|| {
            buf.clear();
            let msg_wire = vanilla::IngressWire {
                source: source,
                receiver: receiver,
                method_name: method_name.clone(),
                method_payload: method_payload.clone(),
                message_id: message_id,
                message_time_ns: message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            };
            serde_json::to_writer(&mut buf, &msg_wire).unwrap();
            let decoded: vanilla::IngressWire = serde_json::from_reader(&buf[..]).unwrap();
            assert_eq!(source, decoded.source);
            assert_eq!(receiver, decoded.receiver);
            assert_eq!(method_name, decoded.method_name);
            assert_eq!(method_payload, decoded.method_payload);
            assert_eq!(message_id, decoded.message_id);
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns))
                    .unwrap()
            );
        });
    });
    println!("json size: {}", buf.len());

    group.bench_function("cbor", |b| {
        b.iter(|| {
            buf.clear();
            let msg_wire = vanilla::IngressWire {
                source: source,
                receiver: receiver,
                method_name: method_name.clone(),
                method_payload: method_payload.clone(),
                message_id: message_id,
                message_time_ns: message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            };
            ser::to_writer(&mut buf, &msg_wire).unwrap();
            let decoded: vanilla::IngressWire = serde_cbor::from_reader(&buf[..]).unwrap();
            assert_eq!(source, decoded.source);
            assert_eq!(receiver, decoded.receiver);
            assert_eq!(method_name, decoded.method_name);
            assert_eq!(method_payload, decoded.method_payload);
            assert_eq!(message_id, decoded.message_id);
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns))
                    .unwrap()
            );
        });
    });
    println!("cbor size: {}", buf.len());

    group.bench_function("msgpack", |b| {
        b.iter(|| {
            buf.clear();
            let msg_wire = vanilla::IngressWire {
                source: source,
                receiver: receiver,
                method_name: method_name.clone(),
                method_payload: method_payload.clone(),
                message_id: message_id,
                message_time_ns: message_time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            };
            buf = rmp_serde::encode::to_vec(&msg_wire).unwrap();
            let decoded: vanilla::IngressWire = rmp_serde::decode::from_read_ref(&buf).unwrap();
            assert_eq!(source, decoded.source);
            assert_eq!(receiver, decoded.receiver);
            assert_eq!(method_name, decoded.method_name);
            assert_eq!(method_payload, decoded.method_payload);
            assert_eq!(message_id, decoded.message_id);
            assert_eq!(
                message_time,
                UNIX_EPOCH
                    .checked_add(Duration::from_nanos(decoded.message_time_ns))
                    .unwrap()
            );
        });
    });
    println!("msgpack size: {}", buf.len());

    group.finish();
}

trait PayloadSize {
    /// Returns payload size of this struct in bytes. The payload size is the number of bytes of
    /// useful information stored in the struct--not the size of the reserved memory, e.g.
    fn payload_size(&self) -> usize;
}

impl PayloadSize for vanilla::Ingress {
    fn payload_size(&self) -> usize {
        let int_sizes = 4 * 8;
        self.method_name.len() + self.method_payload.len() + int_sizes
    }
}

fn add_path() {
    // Install gnuplot if you want to have criterion to produce plots.
    // XXX: Explicitly add path to work around missing gnuplot in nix-environment.
    let path = std::env::vars().find(|(k, _)| k == PATH_KEY).unwrap();
    std::env::set_var(PATH_KEY, format!("{}:{}", path.1, LOCAL_PATH));
}

criterion_group!(benches, benchmark_all_payload_sizes);
criterion_main!(add_path, benches);
