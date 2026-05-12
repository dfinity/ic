//! Linux device-mapper and partition mounting abstractions for IC-OS. Provides
//! RAII-managed loop devices, linear mappings, and snapshots (`device_mapping`),
//! plus GPT-aware partition access by UUID or label (`mount`).

#[cfg(target_os = "linux")]
pub mod device_mapping;
mod io;
pub mod mount;
