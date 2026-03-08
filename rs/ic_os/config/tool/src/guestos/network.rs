use anyhow::{Context, Result};
use network::interfaces::{get_interface_name, get_interface_paths};

/// Picks the best interface from the list
fn pick_best_interface(mut interfaces: Vec<String>) -> Option<String> {
    interfaces.sort();

    // Try to pick eth* interface first, then others.
    // On Azure both eth* and en* are created, but we should use eth* one.
    // In other environments we have only en* interfaces.
    interfaces
        .iter()
        .find(|x| x.starts_with("eth"))
        .or_else(|| interfaces.iter().find(|x| x.starts_with("en")))
        .cloned()
}

/// Returns the name of the best matching interface
pub fn get_best_interface_name() -> Result<String> {
    // Get a list of all network interfaces in the system
    let interfaces = get_interface_paths()
        .into_iter()
        .map(|x| get_interface_name(&x))
        .collect::<Result<Vec<_>>>()
        .context("unable to extract interface name")?;

    let valid_interface =
        pick_best_interface(interfaces).context("no valid network interfaces found")?;

    Ok(valid_interface)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pick_best_interface() {
        let interfaces = vec!["lo", "ens0", "eth1", "ens1", "eth0"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("eth0".to_string()));

        let interfaces = vec!["lo", "eth0", "eth1", "ens0", "ens1"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("eth0".to_string()));

        let interfaces = vec!["lo", "ens0"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("ens0".to_string()));

        let interfaces = vec!["lo", "enp0"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert_eq!(pick_best_interface(interfaces), Some("enp0".to_string()));

        let interfaces = vec!["lo"]
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>();
        assert!(pick_best_interface(interfaces).is_none());
    }
}
