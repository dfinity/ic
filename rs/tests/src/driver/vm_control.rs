use super::farm;
use ic_fondue::ic_manager::{IcEndpoint, RuntimeDescriptor};
use slog::Logger;
use std::time::Instant;

/// A set of operations on an IC node. Note that all calls are blocking.
pub trait IcControl {
    fn start_node(&self, logger: Logger) -> IcEndpoint;
    fn kill_node(&self, logger: Logger);
    fn restart_node(&self, logger: Logger) -> IcEndpoint;
}

impl IcControl for IcEndpoint {
    fn start_node(&self, logger: Logger) -> Self {
        if let RuntimeDescriptor::Vm(info) = &self.runtime_descriptor {
            let farm = farm::Farm::new(info.url.clone(), logger);
            if let Err(e) = farm.start_vm(&info.group_name, &info.vm_name) {
                panic!("failed to start VM: {:?}", e);
            }
            Self {
                started_at: Instant::now(),
                ..self.clone()
            }
        } else {
            panic!("Cannot start a node with IcControl that is not hosted by farm.");
        }
    }

    fn kill_node(&self, logger: Logger) {
        if let RuntimeDescriptor::Vm(info) = &self.runtime_descriptor {
            let farm = farm::Farm::new(info.url.clone(), logger);
            if let Err(e) = farm.destroy_vm(&info.group_name, &info.vm_name) {
                panic!("failed to destroy VM: {:?}", e);
            }
        } else {
            panic!("Cannot kill a node with IcControl that is not hosted by farm.");
        }
    }

    fn restart_node(&self, logger: Logger) -> Self {
        if let RuntimeDescriptor::Vm(info) = &self.runtime_descriptor {
            let farm = farm::Farm::new(info.url.clone(), logger);
            if let Err(e) = farm.reboot_vm(&info.group_name, &info.vm_name) {
                panic!("failed to reboot VM: {:?}", e);
            }
            Self {
                started_at: Instant::now(),
                ..self.clone()
            }
        } else {
            panic!("Cannot restart a node with IcControl that is not hosted by farm.");
        }
    }
}
