use anyhow::Result;
use std::fmt::Debug;
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
/// [`MockLibvirtConnect`].
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

/// Wraps a real `virt::connect::Connect` and implements [`LibvirtConnection`].
#[cfg(target_os = "linux")]
pub struct LibvirtConnectionImpl(pub virt::connect::Connect);

#[cfg(target_os = "linux")]
impl LibvirtConnection for LibvirtConnectionImpl {
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

impl Drop for LibvirtConnectionImpl {
    fn drop(&mut self) {
        if let Err(e) = self.0.close() {
            eprintln!("Failed to close libvirt connection: {e}");
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use crate::libvirt::{LibvirtConnection, LibvirtDomain};
    use anyhow::Result;
    use std::sync::{Arc, Mutex};

    /// Wraps a `LibvirtConnect` and allows switching between different implementations.
    pub struct DelegatingLibvirtConnect(Mutex<Arc<dyn LibvirtConnection>>);

    impl DelegatingLibvirtConnect {
        pub fn new(connect: Arc<dyn LibvirtConnection>) -> Self {
            Self(Mutex::new(connect))
        }

        pub fn set(&self, connect: Arc<dyn LibvirtConnection>) {
            *self.0.lock().unwrap() = connect;
        }
    }

    impl LibvirtConnection for DelegatingLibvirtConnect {
        fn create_domain_xml(&self, xml: &str, flags: u32) -> Result<Box<dyn LibvirtDomain>> {
            self.0.lock().unwrap().create_domain_xml(xml, flags)
        }
        fn lookup_domain_by_name(&self, name: &str) -> Result<Box<dyn LibvirtDomain>> {
            self.0.lock().unwrap().lookup_domain_by_name(name)
        }
        fn lookup_domain_by_id(&self, id: u32) -> Result<Box<dyn LibvirtDomain>> {
            self.0.lock().unwrap().lookup_domain_by_id(id)
        }
    }
}
