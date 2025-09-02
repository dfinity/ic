use ic_logger::{error, info, warn, ReplicaLogger};
use ic_protobuf::registry::node::v1::ConnectionEndpoint;
use ic_sys::utility_command::UtilityCommand;
use ic_types::{NodeId, SubnetId};
use std::{net::IpAddr, str::FromStr};
use url::Url;

use crate::upgrade::OrchestratorControlFlow;

pub(crate) fn http_endpoint_to_url(http: &ConnectionEndpoint, log: &ReplicaLogger) -> Option<Url> {
    endpoint_to_url("http", http, log)
}

pub(crate) fn https_endpoint_to_url(http: &ConnectionEndpoint, log: &ReplicaLogger) -> Option<Url> {
    endpoint_to_url("https", http, log)
}

fn endpoint_to_url(protocol: &str, http: &ConnectionEndpoint, log: &ReplicaLogger) -> Option<Url> {
    let host_str = match IpAddr::from_str(&http.ip_addr.clone()) {
        Ok(v) => {
            if v.is_ipv6() {
                format!("[{}]", v)
            } else {
                v.to_string()
            }
        }
        Err(_) => {
            // assume hostname
            http.ip_addr.clone()
        }
    };

    let url = format!("{}://{}:{}/", protocol, host_str, http.port);
    match Url::parse(&url) {
        Ok(v) => Some(v),
        Err(e) => {
            warn!(log, "Invalid url: {}: {:?}", url, e);
            None
        }
    }
}

/// Enum for tracking the node assignment states that can happen on the
/// network.
#[derive(PartialEq, Eq, Debug)]
pub(crate) enum NodeAssignationState {
    /// The node is unassigned in the registry and the node thinks it is unassigned.
    Unassigned,
    /// The node is unassigned in the registry but still participates in consensus.
    Leaving { subnet_id: SubnetId },
    /// The node is assigned in the registry but the node still hasn't synced the state.
    Joining { subnet_id: SubnetId },
    /// The node is assigned in the registry and the node is participating in conseusns.
    Assigned { subnet_id: SubnetId },
    /// The node is assigned to subnet A in the registry but the node is participating
    /// in consensus of subnet B.
    Moving { from: SubnetId, to: SubnetId },
    /// Initial state
    Unknown,
}

pub(crate) fn maybe_notify_control_flow_change(
    previous_state: NodeAssignationState,
    reported_flow: OrchestratorControlFlow,
    node_id: NodeId,
    maybe_subnet_from_registry: Option<SubnetId>,
    log: &ReplicaLogger,
) -> NodeAssignationState {
    // Based on the registry view of the node and self view figure out the next state
    let new_state = match (reported_flow, maybe_subnet_from_registry) {
        (OrchestratorControlFlow::Unassigned, None) => NodeAssignationState::Unassigned,
        (OrchestratorControlFlow::Unassigned, Some(s)) => {
            NodeAssignationState::Joining { subnet_id: s }
        }
        (OrchestratorControlFlow::Assigned(s), None) => {
            NodeAssignationState::Leaving { subnet_id: s }
        }
        (OrchestratorControlFlow::Assigned(s_node), Some(s_reg)) => {
            if s_node == s_reg {
                NodeAssignationState::Assigned { subnet_id: s_node }
            } else {
                NodeAssignationState::Moving {
                    from: s_node,
                    to: s_reg,
                }
            }
        }
        (OrchestratorControlFlow::Stop, _) => {
            // Not important as the node is gracefully being shutdown in order to upgrade.
            return previous_state;
        }
    };

    // Based on the transition from previous_state -> new_state
    // figure out what to do.
    match (&previous_state, &new_state) {
        (NodeAssignationState::Unknown, s) if s != &NodeAssignationState::Unknown => {
            // Maybe log the inital thing...
        }
        (NodeAssignationState::Unassigned, NodeAssignationState::Joining { subnet_id }) => {
            // Maybe log node joining subnet...
            info!(log, "Detected node joining a subnet {subnet_id}");
        }
        (NodeAssignationState::Unassigned, NodeAssignationState::Assigned { subnet_id }) => {
            // Maybe log instant transition...
            info!(
                log,
                "Node instantly changed from Unassigned to Assigned to a subnet {subnet_id}"
            );
        }
        (NodeAssignationState::Leaving { subnet_id }, NodeAssignationState::Unassigned) => {
            // Maybe log node left subnet...
            info!(log, "Node gracefully left a subnet {subnet_id}");
            UtilityCommand::notify_host(&format!("The node {node_id} has gracefully left subnet {subnet_id}. The node can be turned off now."), 1);
        }
        (
            NodeAssignationState::Joining {
                subnet_id: joining_subnet,
            },
            NodeAssignationState::Assigned {
                subnet_id: joined_subnet,
            },
        ) => {
            if joining_subnet == joined_subnet {
                // Maybe log node joined subnet...
                info!(log, "Node joined subnet {joined_subnet}");
            }
        }
        (NodeAssignationState::Assigned { subnet_id }, NodeAssignationState::Unassigned) => {
            // Maybe log instant transition...
            info!(
                log,
                "Node instantly changed from Assigned {subnet_id} to Unassigned"
            );
        }
        (
            NodeAssignationState::Assigned {
                subnet_id: assinged_subnet,
            },
            NodeAssignationState::Leaving {
                subnet_id: leaving_subnet,
            },
        ) if assinged_subnet == leaving_subnet => {
            // Maybe log leaving subnet...
            info!(log, "Node started leaving subnet {assinged_subnet}");
            UtilityCommand::notify_host(&format!("The node {node_id} has been unassigned from the subnet {assinged_subnet} in the registry. Please do not turn off the machine while it completes its graceful removal from the subnet. This process can take up to 15 minutes. A new message will be displayed here when the node has been successfully removed."), 1);
        }
        // TODO: ATM this is not possible but it may be in the future
        (
            NodeAssignationState::Assigned {
                subnet_id: assigned_subnet,
            },
            NodeAssignationState::Moving { from, to: _ },
        ) if assigned_subnet == from => {
            // Maybe log moving subnet started...
        }
        // TODO: ATM this is not possible but it may be in the future
        (
            NodeAssignationState::Moving { from: _, to },
            NodeAssignationState::Assigned {
                subnet_id: assigned_subnet,
            },
        ) if to == assigned_subnet => {
            // Maybe log moving subnet completed...
        }
        (previous, new) if previous == new => {
            // Same old and new state, do nothing
        }
        (previous, new) => {
            error!(
                log,
                "Detected transition {previous:?} => {new:?} which should not be possible!"
            );
        }
    }

    new_state
}
