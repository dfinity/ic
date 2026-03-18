use sev::Generation;
use sev::error::AttestationReportError;
use sev::firmware::guest::{AttestationReport, ReportVariant};
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
        // FIXME
        Ok(Generation::Milan)
        // // Determine the variant based on version and CPUID step
        // let variant = match self.version {
        //     2 => ReportVariant::V2,
        //     3 | 4 => ReportVariant::V3,
        //     _ => ReportVariant::V5,
        // };
        //
        // let generation = match variant {
        //     ReportVariant::V2 => {
        //         if chip_id_is_turin_like(&self.chip_id)? {
        //             Generation::Turin
        //         } else {
        //             Generation::Genoa
        //         }
        //     }
        //     _ => {
        //         let family = self.cpuid_fam_id.unwrap_or(0);
        //         let model = self.cpuid_mod_id.unwrap_or(0);
        //         Generation::identify_cpu(family, model)?
        //     }
        // };
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

fn chip_id_is_turin_like(bytes: &[u8]) -> std::result::Result<bool, AttestationReportError> {
    // Chip ID -> 0x1A0-0x1E0
    if bytes == [0; 64] {
        return Err(AttestationReportError::MaskedChipId);
    }

    // Last 8 bytes of CHIP_ID are zero, then it is Turin Like.
    Ok(bytes[8..] == [0; 56])
}

/// Converts a `TcbVersion` to its raw `u64` representation (little-endian layout
/// matching the AMD SEV-SNP ABI).
pub fn tcb_version_to_u64(tcb: TcbVersion, generation: Generation) -> Result<u64> {
    let bytes: [u8; 8] = tcb.to_bytes_with(generation)?;
    Ok(u64::from_le_bytes(bytes))
}
