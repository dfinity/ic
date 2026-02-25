use anyhow::Result;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use virt::sys::{virDomainRunningReason, virDomainState};

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
/// [`MockLibvirtConnect`].
#[mockall::automock]
pub trait LibvirtConnect: Send + Sync {
    /// Creates and starts a new domain from the given XML description.
    fn create_domain_xml(&self, xml: &str, flags: u32) -> Result<Box<dyn LibvirtDomain>>;
    /// Looks up a domain by its human-readable name.
    fn lookup_domain_by_name(&self, name: &str) -> Result<Box<dyn LibvirtDomain>>;
    /// Looks up a domain by its numeric id.
    fn lookup_domain_by_id(&self, id: u32) -> Result<Box<dyn LibvirtDomain>>;
}

// ─── Production implementations ──────────────────────────────────────────────

/// Wraps a real `virt::domain::Domain` and implements [`LibvirtDomain`].
#[cfg(target_os = "linux")]
pub struct VirtDomainImpl(virt::domain::Domain);

#[cfg(target_os = "linux")]
impl LibvirtDomain for VirtDomainImpl {
    fn get_id(&self) -> Option<u32> {
        self.0.get_id()
    }

    fn is_active(&self) -> Result<bool> {
        self.0.is_active().map_err(anyhow::Error::from)
    }

    fn get_state(&self) -> Result<(virDomainState, i32)> {
        let (state, reason) = self.0.get_state().map_err(anyhow::Error::from)?;
        Ok((state, reason))
    }

    fn destroy_flags(&self, flags: u32) -> Result<()> {
        self.0
            .destroy_flags(flags)
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    fn get_xml_desc(&self, flags: u32) -> Result<String> {
        self.0.get_xml_desc(flags).map_err(anyhow::Error::from)
    }
}

impl Debug for VirtDomainImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Wraps a real `virt::connect::Connect` and implements [`LibvirtConnect`].
#[cfg(target_os = "linux")]
pub struct VirtConnectImpl(pub virt::connect::Connect);

#[cfg(target_os = "linux")]
impl LibvirtConnect for VirtConnectImpl {
    fn create_domain_xml(&self, xml: &str, flags: u32) -> Result<Box<dyn LibvirtDomain>> {
        virt::domain::Domain::create_xml(&self.0, xml, flags)
            .map(|d| Box::new(VirtDomainImpl(d)) as Box<dyn LibvirtDomain>)
            .map_err(anyhow::Error::from)
    }

    fn lookup_domain_by_name(&self, name: &str) -> Result<Box<dyn LibvirtDomain>> {
        virt::domain::Domain::lookup_by_name(&self.0, name)
            .map(|d| Box::new(VirtDomainImpl(d)) as Box<dyn LibvirtDomain>)
            .map_err(anyhow::Error::from)
    }

    fn lookup_domain_by_id(&self, id: u32) -> Result<Box<dyn LibvirtDomain>> {
        virt::domain::Domain::lookup_by_id(&self.0, id)
            .map(|d| Box::new(VirtDomainImpl(d)) as Box<dyn LibvirtDomain>)
            .map_err(anyhow::Error::from)
    }
}

/// Caching wrapper around a libvirt connection factory.
///
/// The connection is created lazily on first use and then reused for subsequent
/// calls. If a call fails with [`virt::error::ErrorNumber::InvalidConn`] the
/// cached connection is discarded, a fresh one is obtained from the factory,
/// and the failing call is retried once with the new connection.
pub struct LibvirtConnectionWithRetry {
    factory: Arc<dyn Fn() -> Result<Arc<dyn LibvirtConnect>> + Send + Sync>,
    connection: Mutex<Option<Arc<dyn LibvirtConnect>>>,
}

impl LibvirtConnectionWithRetry {
    pub fn new(factory: Arc<dyn Fn() -> Result<Arc<dyn LibvirtConnect>> + Send + Sync>) -> Self {
        Self {
            factory,
            connection: Mutex::new(None),
        }
    }

    fn get_or_connect(&self) -> Result<Arc<dyn LibvirtConnect>> {
        let mut guard = self.connection.lock().unwrap();
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let conn = (self.factory)()?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Discards the cached connection so the next call will invoke the factory.
    ///
    /// Call this whenever an external event (e.g. a libvirtd restart) has made
    /// the existing connection stale.
    pub fn invalidate(&self) {
        *self.connection.lock().unwrap() = None;
    }

    fn call_with_reconnect<T>(&self, f: impl Fn(&dyn LibvirtConnect) -> Result<T>) -> Result<T> {
        let conn = self.get_or_connect()?;
        let result = f(conn.as_ref());
        match result {
            Err(ref e) if is_invalid_conn_error(e) => {
                eprintln!("Libvirt connection is invalid, recreating and retrying");
                self.invalidate();
                let new_conn = self.get_or_connect()?;
                f(new_conn.as_ref())
            }
            other => other,
        }
    }
}

impl LibvirtConnect for LibvirtConnectionWithRetry {
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

/// Returns `true` when `err` wraps a `VIR_ERR_INVALID_CONN` libvirt error.
#[cfg(target_os = "linux")]
fn is_invalid_conn_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<virt::error::Error>()
        .map(|e| matches!(e.code(), virt::error::ErrorNumber::InvalidConn))
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn is_invalid_conn_error(_err: &anyhow::Error) -> bool {
    false
}
