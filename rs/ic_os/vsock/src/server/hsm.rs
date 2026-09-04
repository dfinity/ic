use std::io::Write;

use super::VsockServerError;
use crate::protocol::Payload;

use rusb::{Context, Device, UsbContext};
use tempfile::NamedTempFile;

// nitrokey:
const HSM_VENDOR: u16 = 8352;
const HSM_PRODUCT: u16 = 16944;

// the hard-coded domain name defined in the xml file for starting guestOS in virsh
const DOMAIN_NAME: &str = "guestos";

#[derive(Debug)]
struct HSMInfo {
    hsm_bus_num: u8,
    hsm_address: u8,
}

impl std::fmt::Display for HSMInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "HSMInfo {{ bus: {}, address: {} }}",
            self.hsm_bus_num, self.hsm_address
        )
    }
}

pub(crate) fn attach_hsm() -> Result<Payload, VsockServerError> {
    hsm_helper("attach-device")
}

pub(crate) fn detach_hsm() -> Result<Payload, VsockServerError> {
    hsm_helper("detach-device")
}

fn hsm_helper(command: &str) -> Result<Payload, VsockServerError> {
    let hsm_xml_file = create_hsm_xml_file()?;

    println!("Sending virsh command: {command}");
    let command_output = std::process::Command::new("virsh")
        .arg(command)
        .arg(DOMAIN_NAME)
        .arg("--file")
        .arg(hsm_xml_file.path())
        .output()
        .map_err(VsockServerError::io(format!(
            "running command 'virsh {command}'"
        )))?;

    if command_output.status.success() {
        Ok(Payload::NoPayload)
    } else {
        Err(VsockServerError::CommandFailed {
            command: format!("virsh {command}"),
            stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
        })
    }
}

fn create_hsm_xml_file() -> Result<NamedTempFile, VsockServerError> {
    let hsm_info = get_hsm_info()?;

    println!("HSM found: {hsm_info}");

    let xml: String = get_hsm_xml_string(&hsm_info);

    let mut file = NamedTempFile::with_prefix("hsm").map_err(VsockServerError::io(
        "opening temp hsm xml file".to_string(),
    ))?;
    file.write_all(xml.as_bytes())
        .map_err(VsockServerError::io(
            "writing temp hsm xml file".to_string(),
        ))?;

    Ok(file)
}

fn get_hsm_info() -> Result<HSMInfo, VsockServerError> {
    let usb_devices = rusb::Context::new()?.devices()?;

    println!("Iterating over attached devices to find HSM");
    // return the first usb device that satisfies the is_hsm_device filter
    usb_devices
        .iter()
        .find(is_hsm_device)
        .map(|hsm_device| HSMInfo {
            hsm_bus_num: hsm_device.bus_number(),
            hsm_address: hsm_device.address(),
        })
        .ok_or_else(|| VsockServerError::HsmNotFound)
}

fn is_hsm_device(device: &Device<Context>) -> bool {
    match device.device_descriptor() {
        Ok(device_descriptor) => {
            println!(
                "Bus {:03} Device {:03} ID {:04x}:{:04x}",
                device.bus_number(),
                device.address(),
                device_descriptor.vendor_id(),
                device_descriptor.product_id()
            );

            device_descriptor.vendor_id() == HSM_VENDOR
                && device_descriptor.product_id() == HSM_PRODUCT
        }
        Err(_) => {
            println!("Error: device.device_descriptor() returned error");

            false
        }
    }
}

// HSM_VENDOR and HSM_PRODUCT must be converted to hexadecimal for the attach/detach hsm virsh commands
fn get_hsm_xml_string(hsm_info: &HSMInfo) -> String {
    format!(
        "
<hostdev mode='subsystem' type='usb' managed='yes'>
    <source>
        <vendor id='{0:#06x}'/>
        <product id='{1:#06x}'/>
        <address bus='{2}' port='1' device='{3}'/>
    </source>
    <address type='usb' bus='0' port='2'/>
</hostdev>
",
        HSM_VENDOR, HSM_PRODUCT, hsm_info.hsm_bus_num, hsm_info.hsm_address
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn get_hsm_xml_string() {
        use super::*;

        let hsm_info = HSMInfo {
            hsm_bus_num: 11_u8,
            hsm_address: 12_u8,
        };
        let actual = get_hsm_xml_string(&hsm_info);

        let expected: String = "
<hostdev mode='subsystem' type='usb' managed='yes'>
    <source>
        <vendor id='0x20a0'/>
        <product id='0x4230'/>
        <address bus='11' port='1' device='12'/>
    </source>
    <address type='usb' bus='0' port='2'/>
</hostdev>
"
        .to_string();
        assert_eq!(actual, expected)
    }
}
