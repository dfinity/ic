use sev::Generation;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;
use std::convert::TryInto;
use std::io::Result;

pub trait AttestationReportExt {
    fn generation(&self) -> Result<Generation>;

    fn launch_tcb_as_u64(&self) -> Result<u64>;

    fn reported_tcb_as_u64(&self) -> Result<u64>;

    fn committed_tcb_as_u64(&self) -> Result<u64>;

    fn current_tcb_as_u64(&self) -> Result<u64>;
}

impl AttestationReportExt for AttestationReport {
    fn generation(&self) -> Result<Generation> {
        Generation::identify_cpu(
            self.cpuid_fam_id.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "cpuid_fam_id is missing")
            })?,
            self.cpuid_mod_id.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "CPUID model ID is missing")
            })?,
        )
    }

    fn launch_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.launch_tcb, self.generation()?)
    }

    fn reported_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.reported_tcb, self.generation()?)
    }

    fn committed_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.committed_tcb, self.generation()?)
    }

    fn current_tcb_as_u64(&self) -> Result<u64> {
        tcb_version_to_u64(self.current_tcb, self.generation()?)
    }
}

/// Converts a `TcbVersion` to its raw `u64` representation (little-endian layout
/// matching the AMD SEV-SNP ABI).
pub fn tcb_version_to_u64(tcb: TcbVersion, generation: Generation) -> Result<u64> {
    let bytes: [u8; 8] = tcb.to_bytes_with(generation)?;
    Ok(u64::from_le_bytes(bytes))
}
