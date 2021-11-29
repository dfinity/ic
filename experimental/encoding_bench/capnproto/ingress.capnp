@0xb7ef89601eedef15;

struct Ingress {
    source @0 :UInt64;
    receiver @1 :UInt64;
    methodName @2 :Text;
    methodPayload @3 :Data;
    messageId @4 :UInt64;
    messageTimeNs @5 :UInt64;
}
