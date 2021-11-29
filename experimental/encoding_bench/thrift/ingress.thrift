struct Ingress {
	1: i64 source,
	2: i64 receiver,
	3: string method_name,
	4: binary method_payload,
	5: i64 message_id,
	6: i64 message_time_ns
}