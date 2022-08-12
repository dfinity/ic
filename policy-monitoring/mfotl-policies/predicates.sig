log(internal_host_id:string, node_id:string, subnet_id:string, component:string, level:string, message:string)
log1(node:string, val:float)

originally_in_ic(node_id:string, node_addr:string)
original_subnet_type(subnet_id:string, subnet_type:string)
originally_in_subnet(node_id:string, node_addr:string, subnet_id:string)

p2p__node_added(node_id:string, subnet_id:string, added_node_id:string)
p2p__node_removed(node_id:string, subnet_id:string, removed_node_id:string)

registry__node_added_to_ic(node_id:string, node_addr:string)
registry__node_removed_from_ic(node_id:string, node_addr:string)
registry__subnet_created(subnet_id:string, subnet_type:string)
registry__subnet_updated(subnet_id:string, subnet_type:string)
registry__node_added_to_subnet(node_id:string, node_addr:string, subnet_id:string)
registry__node_removed_from_subnet(node_id:string, node_addr:string)

consensus_finalized(node_id:string,
                    subnet_id:string,
                    state_avail:int,
                    key_avail:int)
move_block_proposal(node_id:string,
                    subnet_id:string,
                    block_hash:string,
                    signer:string)

validated_BlockProposal_Added(node_id:string, subnet_id:string, hash:string)
validated_BlockProposal_Moved(node_id:string, subnet_id:string, hash:string)

deliver_batch(node_id:string, subnet_id:string, block_hash:string)

ControlPlane__spawn_accept_task__tls_server_handshake_failed(
    local_addr:string,
    peer_addr:string
)

reboot(ip_addr:string, data_center_prefix:string)
reboot_intent(ip_addr:string, data_center_prefix:string)

finalized(node_id:string, subnet_id:string, height:int, hash:string, replica_version:string)

replica_diverged(node_id:string, subnet_id:string, height:int)

CUP_share_proposed(node_id:string, subnet_id:string)

Exited(process:string, status:int)

end_test()
