use anyhow::{Error, Result};
use arc_swap::ArcSwapOption;
use std::fmt::Debug;
use std::sync::Arc;
use virt::sys::virDomainState;

/// Facade trait for operations on a libvirt domain.
///
/// Abstracts the `virt::domain::Domain` API so that callers can be tested
/// without a real hypervisor by injecting a [`MockLibvirtDomain`].
#[mockall::automock]
pub trait LibvirtDomain: Send + Sync + Debug {
    /// Returns the numeric id of the domain, or `None` if the domain has no id.
    fn get_id(&self) -> Option<u32>;
    /// Returns whether the domain is currently active (running).
    fn is_active(&self) -> Result<bool>;
    /// Returns the current `(state, reason)` pair of the domain.
    fn get_state(&self) -> Result<(virDomainState, i32)>;
    /// Destroys the domain using the provided flags (e.g. `VIR_DOMAIN_DESTROY_GRACEFUL`).
    fn destroy_flags(&self, flags: u32) -> Result<()>;
    /// Returns the XML config of the domain.
    fn get_xml_desc(&self, flags: u32) -> Result<String>;
}

/// Facade trait for a libvirt hypervisor connection.
///
/// Encapsulates all interactions that go through a `virt::connect::Connect`
/// so that callers can be tested without a real libvirt daemon by injecting a
/// [`MockLibvirtConnection`].
#[mockall::automock]
pub trait LibvirtConnection: Send + Sync {
    /// Creates and starts a new domain from the given XML description.
    fn create_domain_xml(&self, xml: &str, flags: u32) -> Result<Box<dyn LibvirtDomain>>;
    /// Looks up a domain by its human-readable name.
    fn lookup_domain_by_name(&self, name: &str) -> Result<Box<dyn LibvirtDomain>>;
    /// Looks up a domain by its numeric id.
    fn lookup_domain_by_id(&self, id: u32) -> Result<Box<dyn LibvirtDomain>>;
}

/// Wraps a real `virt::domain::Domain` and implements [`LibvirtDomain`].
#[cfg(target_os = "linux")]
pub struct VirtDomainImpl(virt::domain::Domain);

#[cfg(target_os = "linux")]
impl LibvirtDomain for VirtDomainImpl {
    fn get_id(&self) -> Option<u32> {
        self.0.get_id()
    }

    fn is_active(&self) -> Result<bool> {
        self.0.is_active().map_err(Error::from)
    }

    fn get_state(&self) -> Result<(virDomainState, i32)> {
        let (state, reason) = self.0.get_state().map_err(Error::from)?;
        Ok((state, reason))
    }

    fn destroy_flags(&self, flags: u32) -> Result<()> {
        self.0.destroy_flags(flags).map(|_| ()).map_err(Error::from)
    }

    fn get_xml_desc(&self, flags: u32) -> Result<String> {
        self.0.get_xml_desc(flags).map_err(Error::from)
    }
}

impl Debug for VirtDomainImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Wraps a real `virt::connect::Connect` and implements [`LibvirtConnection`].
pub struct LibvirtConnectionImpl(pub virt::connect::Connect);

#[cfg(target_os = "linux")]
impl LibvirtConnection for LibvirtConnectionImpl {
    fn create_domain_xml(&self, xml: &str, flags: u32) -> Result<Box<dyn LibvirtDomain>> {
        virt::domain::Domain::create_xml(&self.0, xml, flags)
            .map(|d| Box::new(VirtDomainImpl(d)) as Box<dyn LibvirtDomain>)
            .map_err(Error::from)
    }

    fn lookup_domain_by_name(&self, name: &str) -> Result<Box<dyn LibvirtDomain>> {
        virt::domain::Domain::lookup_by_name(&self.0, name)
            .map(|d| Box::new(VirtDomainImpl(d)) as Box<dyn LibvirtDomain>)
            .map_err(Error::from)
    }

    fn lookup_domain_by_id(&self, id: u32) -> Result<Box<dyn LibvirtDomain>> {
        virt::domain::Domain::lookup_by_id(&self.0, id)
            .map(|d| Box::new(VirtDomainImpl(d)) as Box<dyn LibvirtDomain>)
            .map_err(Error::from)
    }
}

impl Drop for LibvirtConnectionImpl {
    fn drop(&mut self) {
        if let Err(e) = self.0.close() {
            eprintln!("Failed to close libvirt connection: {e}");
        }
    }
}

pub type LibvirtConnectionFactory = dyn Fn() -> Result<Box<dyn LibvirtConnection>> + Send + Sync;

/// Caching wrapper around a libvirt connection factory.
///
/// The connection is created lazily on first use and then reused for subsequent
/// calls. If a call fails with connection error, the cached connection is discarded, a fresh one
/// is obtained from the factory, and the failing call is retried once with the new connection.
pub struct LibvirtConnectionWithReconnect {
    factory: Arc<LibvirtConnectionFactory>,
    // ArcSwapOption requires Sized for the inner type, so dyn LibvirtConnection must be
    // wrapped in a Box.
    connection: ArcSwapOption<Box<dyn LibvirtConnection>>,
}

impl LibvirtConnectionWithReconnect {
    pub fn new(factory: Arc<LibvirtConnectionFactory>) -> Self {
        Self {
            factory,
            connection: ArcSwapOption::empty(),
        }
    }

    fn call_with_conn<T>(&self, f: impl Fn(&dyn LibvirtConnection) -> Result<T>) -> Result<T> {
        let guard = self.connection.load();
        if let Some(conn) = guard.as_ref() {
            return f(conn.as_ref().as_ref());
        }
        // Note that if the function is called from multiple threads, multiple connections
        // will be created. This is fine, connections are cheap and the code is not highly
        // concurrent.
        let conn = Arc::new((self.factory)()?);
        self.connection.store(Some(conn.clone()));
        f(conn.as_ref().as_ref())
    }

    fn call_with_reconnect<T>(&self, f: impl Fn(&dyn LibvirtConnection) -> Result<T>) -> Result<T> {
        let result = self.call_with_conn(&f);
        match result {
            Err(ref e) if Self::is_connection_error(e) => {
                eprintln!("Libvirt connection is invalid, recreating and retrying");
                // Discard the cached connection so the next call will invoke the factory.
                self.connection.store(None);
                self.call_with_conn(f)
            }
            other => other,
        }
    }

    fn is_connection_error(err: &Error) -> bool {
        err.downcast_ref::<virt::error::Error>()
            .is_some_and(|e| e.domain() == virt::error::ErrorDomain::Rpc)
    }
}

impl LibvirtConnection for LibvirtConnectionWithReconnect {
    fn create_domain_xml(&self, xml: &str, flags: u32) -> Result<Box<dyn LibvirtDomain>> {
        self.call_with_reconnect(|conn| conn.create_domain_xml(xml, flags))
    }

    fn lookup_domain_by_name(&self, name: &str) -> Result<Box<dyn LibvirtDomain>> {
        self.call_with_reconnect(|conn| conn.lookup_domain_by_name(name))
    }

    fn lookup_domain_by_id(&self, id: u32) -> Result<Box<dyn LibvirtDomain>> {
        self.call_with_reconnect(|conn| conn.lookup_domain_by_id(id))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    pub fn libvirt_connect_error() -> virt::error::Error {
        // virt::error::Error does not have a constructor. Workaround: construct a struct with
        // the same layout and use transmute. It's only used in tests.
        #[allow(unused)]
        pub struct Error {
            code: virt::sys::virErrorNumber,
            domain: virt::sys::virErrorDomain,
            message: String,
            level: virt::sys::virErrorLevel,
        }
        let error = Error {
            code: virt::sys::VIR_ERR_INTERNAL_ERROR,
            domain: virt::sys::VIR_FROM_RPC,
            message: "XML-RPC error : internal error: client socket is closed".into(),
            level: virt::sys::VIR_ERR_ERROR,
        };
        unsafe { std::mem::transmute(error) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[test]
    fn test_reconnect_on_error() {
        use super::testing::libvirt_connect_error;

        // First connection: fails with a connection error on lookup.
        let mut conn1 = MockLibvirtConnection::new();
        conn1
            .expect_lookup_domain_by_name()
            .returning(|_| Err(Error::from(libvirt_connect_error())));

        // Second connection: succeeds on lookup.
        let mut conn2 = MockLibvirtConnection::new();
        conn2.expect_lookup_domain_by_name().return_once(|_| {
            let mut domain = MockLibvirtDomain::new();
            domain.expect_get_id().returning(|| Some(42));
            Ok(Box::new(domain))
        });

        let connections: Arc<Mutex<VecDeque<Box<dyn LibvirtConnection>>>> =
            Arc::new(Mutex::new(VecDeque::from([
                Box::new(conn1) as Box<dyn LibvirtConnection>,
                Box::new(conn2) as Box<dyn LibvirtConnection>,
            ])));

        let factory = {
            let connections = connections.clone();
            Arc::new(move || -> Result<Box<dyn LibvirtConnection>> {
                Ok(connections.lock().unwrap().pop_front().unwrap())
            })
        };

        let wrapper = LibvirtConnectionWithReconnect::new(factory);
        let result = wrapper.lookup_domain_by_name("test-domain");

        assert!(
            result.is_ok(),
            "Expected success after reconnect, got: {result:?}"
        );
    }
}
