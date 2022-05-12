p2p__node_added(node_id:string, subnet_id:string)
move_block_proposal(node_id:string,
                    subnet_id:string,
                    block_hash:string,
                    signer:string)
deliver_batch(node_id:string, subnet_id:string, block_hash:string)
reboot(ip_addr:string, data_center_prefix:string)
consensus_finalized(node_id:string,
                    subnet_id:string,
                    state_avail:int,
                    key_avail:int)
finalized(node_id:string, subnet_id:string, height:int, hash:string)
ControlPlane_tls_server_handshake_failed(local_addr:string,
                                         node_id:string,
                                         peer_addr:string,
                                         error:string)
