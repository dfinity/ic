// basic port allocator for running tests on a single node.
// Concurrent allocations are handled using the Atomic file create
// primitive provided by POSIX
use socket2::Socket;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};

#[allow(dead_code)]
pub struct NodePort {
    socket: Socket,
    pub port: u16,
}

/// Allocates the requested number of ports on a given IP address.
pub fn allocate_ports(ip_address: &str, num_ports: u16) -> Result<Vec<NodePort>, Box<dyn Error>> {
    let ip_address: IpAddr = ip_address.parse()?;
    let mut node_port_allocation = Vec::new();
    for _ in 0..num_ports {
        let socket = bind_tcp_socket_with_reuse(SocketAddr::from((ip_address, 0)))?;
        let local_addr = socket.local_addr()?.as_std().unwrap();
        node_port_allocation.push(NodePort {
            socket,
            port: local_addr.port(),
        });
        println!("Allocated Port {}", local_addr.port());
    }
    Ok(node_port_allocation)
}

/// Binds a TCP socket on the given address after having set the `SO_REUSEADDR`
/// and `SO_REUSEPORT` flags.
///
/// Setting the flags after binding to the port has no effect.
fn bind_tcp_socket_with_reuse(addr: SocketAddr) -> Result<Socket, Box<dyn Error>> {
    use socket2::{Domain, Protocol, SockAddr, Type};
    let domain = match &addr {
        SocketAddr::V4(_) => Domain::ipv4(),
        SocketAddr::V6(_) => Domain::ipv6(),
    };
    let socket = socket2::Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;

    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    {
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
    }
    socket.bind(&SockAddr::from(addr))?;

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use rusty_fork::rusty_fork_test;
    use std::process;

    fn listen_helper(port_allocation: &NodePort) -> Result<(), Box<dyn Error>> {
        let socket =
            bind_tcp_socket_with_reuse(SocketAddr::from(([127, 0, 0, 1], port_allocation.port)))?;
        let _ = socket.listen(1)?;
        Ok(())
    }

    #[test]
    // Allocate 10 ports from the allocator
    // listen on the ports in the same process
    fn allocate_and_use_10_ports() {
        let listen_errors: Vec<Result<(), Box<dyn Error>>> = allocate_ports("127.0.0.1", 10)
            .unwrap()
            .iter()
            .map(listen_helper)
            .filter(|listen_result| listen_result.is_err())
            .collect();
        assert_eq!(listen_errors.len(), 0)
    }

    rusty_fork_test! {
        #[test]
        // Allocate 10 ports from the allocator
        // listen on those ports from child processes
        fn allocate_and_use_in_child() {
            let child_count = 10;
            let listen_ports = allocate_ports("127.0.0.1", child_count).unwrap();
            let mut children = Vec::new();
            for port in listen_ports {
                let child_port = port;
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child, .. }) => {
                        println!("Child Forked with Pid {}, port {}", child, child_port.port);
                        children.push(child)
                    }
                    Ok(ForkResult::Child) => {
                        listen_helper(&child_port).unwrap_or_else(|_| {
                            panic!(
                                "Child Couldn't listen of parent Provided Port  {}",
                                child_port.port
                            )
                        });
                        process::exit(0);
                    }
                    Err(_) => {
                        std::unreachable!();
                    }
                }
            }

            // Wait on children
            let success_child_count: Vec<Result<(), i32>> = children
                .iter()
                .map(|pid| match waitpid(*pid, None) {
                    Ok(WaitStatus::Exited(_, 0)) => Ok(()),
                    _ => Err(-1),
                })
                .filter(|r| r.is_ok())
                .collect();
            assert_eq!(success_child_count.len(), child_count as usize);
        }
    }
}
