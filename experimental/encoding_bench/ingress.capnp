@0xb7ef89601eedef15

struct Ingress {
    source: @1 :UInt64;
    receiver: @2 :UInt64;
    method_name: @3 :Text;
    method_payload: @4 :Data;
    message_id: @5 :UInt64;
    message_time_ns: @6 :UInt64;
}
