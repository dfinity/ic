use sha2::{Digest, Sha256};

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

pub mod node_type;
use node_type::NodeType;

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("index must be between 0x00 and 0x0f")]
    InvalidIndex,
    #[error("the resulting address is invalid")]
    InvalidAddress,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct HwAddr {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
}

impl HwAddr {
    fn octets(&self) -> [u8; 6] {
        [self.a, self.b, self.c, self.d, self.e, self.f]
    }
}

impl AsRef<HwAddr> for HwAddr {
    fn as_ref(&self) -> &HwAddr {
        self
    }
}

impl fmt::Display for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a, self.b, self.c, self.d, self.e, self.f
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HwAddrParseError {
    #[error("invalid MAC address")]
    InvalidAddress,
    #[error("invalid MAC address length")]
    InvalidLength,
}

impl From<[u8; 6]> for HwAddr {
    fn from(octets: [u8; 6]) -> HwAddr {
        HwAddr {
            a: octets[0],
            b: octets[1],
            c: octets[2],
            d: octets[3],
            e: octets[4],
            f: octets[5],
        }
    }
}

impl FromStr for HwAddr {
    type Err = HwAddrParseError;
    fn from_str(s: &str) -> Result<HwAddr, HwAddrParseError> {
        let octets = match s.len() {
            17 => s
                .split(':')
                .map(|v| u8::from_str_radix(v, 16).map_err(|_| HwAddrParseError::InvalidAddress))
                .collect::<Result<Vec<u8>, HwAddrParseError>>(),

            12 => {
                let chars: Vec<char> = s.chars().collect();
                chars
                    .chunks(2)
                    .map(|v| {
                        v.iter().fold("".to_string(), |mut acc, v| {
                            acc.push(*v);
                            acc
                        })
                    })
                    .map(|v| {
                        u8::from_str_radix(&v, 16).map_err(|_| HwAddrParseError::InvalidAddress)
                    })
                    .collect::<Result<Vec<u8>, HwAddrParseError>>()
            }
            _ => Err(HwAddrParseError::InvalidLength),
        }?;

        if octets.len() != 6 {
            return Err(HwAddrParseError::InvalidAddress);
        }

        Ok([
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
        ]
        .into())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub enum Deployment {
    Mainnet,
    Testnet,
}

impl fmt::Display for Deployment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Deployment::Mainnet => write!(f, "mainnet"),
            Deployment::Testnet => write!(f, "testnet"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentParseError {
    #[error("invalid deployment variant")]
    InvalidVariant,
}

impl FromStr for Deployment {
    type Err = DeploymentParseError;
    fn from_str(s: &str) -> Result<Deployment, DeploymentParseError> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Deployment::Mainnet),
            "testnet" => Ok(Deployment::Testnet),
            _ => Err(DeploymentParseError::InvalidVariant),
        }
    }
}

/// Generate a deterministic MAC address based on the management MAC, deployment environment, and node type.
pub fn calculate_deterministic_mac(
    mgmt_mac: &HwAddr,
    deployment_environment: &str,
    node_type: &NodeType,
) -> Result<HwAddr, AddressError> {
    let seed = format!("{}{}\n", mgmt_mac, deployment_environment);
    let hash = Sha256::digest(seed.as_bytes());

    let version = 0x6a;
    let index = node_type.to_index();

    let mac_bytes = [version, index, hash[0], hash[1], hash[2], hash[3]];

    Ok(mac_bytes.into())
}

impl HwAddr {
    pub fn calculate_slaac(&self, prefix: &str) -> Result<Ipv6Addr, AddressError> {
        let mut octets = self.octets().to_vec();

        octets.insert(3, 0xff);
        octets.insert(4, 0xfe);

        octets[0] ^= 2;

        let octets = octets
            .chunks(2)
            .map(|v| {
                v.iter().fold("".to_string(), |mut acc, v| {
                    acc.push_str(&format!("{:02x}", v));
                    acc
                })
            })
            .reduce(|mut acc, v| {
                acc.push(':');
                acc.push_str(&v);
                acc
            })
            .unwrap(); // We know the length, so this unwrap is OK.

        let combined = format!("{}:{}", prefix, octets);

        combined.parse().map_err(|_| AddressError::InvalidAddress)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mac() {
        let mgmt_mac: HwAddr = "70:B5:E8:E8:25:DE".parse().unwrap();

        let expected_mac: HwAddr = "6a:00:f8:87:a4:8a".parse().unwrap();

        let mac = calculate_deterministic_mac(&mgmt_mac, "testnet", &NodeType::HostOS).unwrap();

        assert_eq!(mac, expected_mac);
    }

    #[test]
    fn invalid_mac_length() {
        let error: Result<HwAddr, _> = "11:22:33:44:55".parse();

        assert!(matches!(
            error,
            Result::Err(HwAddrParseError::InvalidLength)
        ));
    }

    #[test]
    fn invalid_mac_contents() {
        let error: Result<HwAddr, _> = "::::::::::::".parse();

        assert!(matches!(
            error,
            Result::Err(HwAddrParseError::InvalidAddress)
        ));
    }

    #[test]
    fn slaac() {
        let mac = "6a01e5962d49".parse::<HwAddr>().unwrap();
        let prefix = "2a04:9dc0:0:108";

        let expected_ip = "2a04:9dc0:0:108:6801:e5ff:fe96:2d49"
            .parse::<Ipv6Addr>()
            .unwrap();

        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }

    #[test]
    fn mac_to_slaac() {
        let mgmt_mac = "b0:7b:25:c8:f6:c0".parse::<HwAddr>().unwrap();
        let prefix = "2602:FFE4:801:17";

        let expected_ip = "2602:FFE4:801:17:6801:ff:feec:bd51"
            .parse::<Ipv6Addr>()
            .unwrap();

        let mac = calculate_deterministic_mac(&mgmt_mac, "mainnet", &NodeType::GuestOS).unwrap();
        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }

    #[test]
    // added unit tests from ipv6.rs
    fn ported_generate_ipv6_tests() {
        // Test case 1
        assert_eq!(
            "4a0ff7e0c684"
                .parse::<HwAddr>()
                .unwrap()
                .calculate_slaac("2a00:1111:1111:1111")
                .unwrap(),
            "2a00:1111:1111:1111:480f:f7ff:fee0:c684"
                .parse::<Ipv6Addr>()
                .unwrap()
        );

        // Test case 2
        assert_eq!(
            "111111111111"
                .parse::<HwAddr>()
                .unwrap()
                .calculate_slaac("1111:1111:1111:1111")
                .unwrap(),
            "1111:1111:1111:1111:1311:11ff:fe11:1111"
                .parse::<Ipv6Addr>()
                .unwrap()
        );

        // Test case 3
        assert_eq!(
            "a1b2c3d4e5f6"
                .parse::<HwAddr>()
                .unwrap()
                .calculate_slaac("2a00:fb01:400:100")
                .unwrap(),
            "2a00:fb01:400:100:a3b2:c3ff:fed4:e5f6"
                .parse::<Ipv6Addr>()
                .unwrap()
        );

        // Test case 4
        assert_eq!(
            "6a01f7e0c684"
                .parse::<HwAddr>()
                .unwrap()
                .calculate_slaac("2a00:fb01:400:100")
                .unwrap(),
            "2a00:fb01:400:100:6801:f7ff:fee0:c684"
                .parse::<Ipv6Addr>()
                .unwrap()
        );
    }

    // Added unit tests from mac_address.rs
    #[test]
    fn test_calculate_deterministic_mac() {
        // Test case 1
        let mgmt_mac: HwAddr = "de:ad:de:ad:de:ad".parse().unwrap();
        let deployment_environment = "mainnet";

        let expected_mac: HwAddr = "6a:01:f7:e0:c6:84".parse().unwrap();

        let mac =
            calculate_deterministic_mac(&mgmt_mac, deployment_environment, &NodeType::GuestOS)
                .unwrap();

        println!("{mac}");

        assert_eq!(mac, expected_mac);

        // Test case 2
        let mgmt_mac: HwAddr = "00:aa:bb:cc:dd:ee".parse().unwrap();
        let expected_mac: HwAddr = "6a:01:d9:ab:57:f2".parse().unwrap();

        let mac =
            calculate_deterministic_mac(&mgmt_mac, deployment_environment, &NodeType::GuestOS)
                .unwrap();

        println!("{mac}");

        assert_eq!(mac, expected_mac);
    }
}
