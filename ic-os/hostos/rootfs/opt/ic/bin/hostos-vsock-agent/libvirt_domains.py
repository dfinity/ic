import logging
import sys
from xml.dom import minidom

import libvirt


class CidLibvirtDomain:
    """Maps the CID to LibVirt Domains."""

    def __init__(self):
        """Init the object."""
        try:
            self.conn = libvirt.openReadOnly(None)
        except libvirt.libvirtError:
            print("Failed to open connection to the hypervisor")
            sys.exit(1)

        self._domains = {}
        self.refresh_domains()

    def refresh_domains(self):
        """Get a list of domains. Then updates self.domains to have {cid: domain_name}."""
        self._domains = {}
        domain_ids = self.conn.listDomainsID()
        if domain_ids is None:
            logging.error("LibVirt: failed to get a list of domain IDs")
        else:
            for domain_id in domain_ids:
                domain = self.conn.lookupByID(domain_id)
                domain_raw_xml = domain.XMLDesc(0)
                domain_cids = self._extract_domain_cids(domain_raw_xml)
                for cid in domain_cids:
                    self._domains[cid] = domain.name()
        # logging.debug("LibVirt: refreshed VM domains %s", self._domains)
        if not self._domains:
            logging.warning("LibVirt: no domains with vsock and CIDs found")

    def _extract_domain_cids(self, raw_xml):
        """Extract the vsock CIDs in the provided XML description."""
        xml = minidom.parseString(raw_xml)
        cids = []
        for vsock in xml.getElementsByTagName("vsock"):
            if vsock.getAttribute("model") == "virtio":
                for cid_elem in vsock.getElementsByTagName("cid"):
                    cid = cid_elem.getAttribute("address")
                    if cid:
                        cids.append(cid)
        return cids

    def cid_to_domain(self, cid):
        """Translate the domain's CID to the domain name."""
        if cid not in self._domains:
            self.refresh_domains()
        return self._domains.get(cid)

    def list_cids(self):
        """List all found CIDs."""
        return list(self._domains.keys())

    def list_domain_names(self):
        """List all found domain names."""
        return sorted(list(self._domains.values()))
