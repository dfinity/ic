use ic_crypto_sha2::Sha256;

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

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

#[derive(Copy, Clone)]
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

#[derive(Copy, Clone)]
pub enum IpVariant {
    V4,
    V6,
}

pub fn calculate_deterministic_mac<T: AsRef<HwAddr>>(
    mgmt_mac: T,
    deployment: Deployment,
    ip_version: IpVariant,
    index: u8,
) -> Result<HwAddr, AddressError> {
    if index > 0x0f {
        return Err(AddressError::InvalidIndex);
    }

    // NOTE: In order to be backwards compatible with existing scripts, this
    // **MUST** Have a newline.
    let seed = format!("{}{}\n", mgmt_mac.as_ref(), deployment);

    let hash = Sha256::hash(seed.as_bytes());

    let version = match ip_version {
        IpVariant::V4 => 0x4a,
        IpVariant::V6 => 0x6a,
    };

    Ok([version, index, hash[0], hash[1], hash[2], hash[3]].into())
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

        let expected_mac: HwAddr = "4a:00:f8:87:a4:8a".parse().unwrap();

        let mac =
            calculate_deterministic_mac(mgmt_mac, Deployment::Testnet, IpVariant::V4, 0).unwrap();

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

        let mac =
            calculate_deterministic_mac(mgmt_mac, Deployment::Mainnet, IpVariant::V6, 1).unwrap();
        let slaac = mac.calculate_slaac(prefix).unwrap();

        assert_eq!(slaac, expected_ip);
    }
}
