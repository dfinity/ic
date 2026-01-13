# Deterministic IPs

Each IC-OS node must have a unique but deterministic MAC address derived from its BMC MAC address, deployment type (mainnet vs testnet), and variant type (SetupOS, HostOS, GuestOS. This MAC address is then utilized to generate the node’s network configuration. To solve this, a schema has been devised.

## MAC Address Schema

- **The first 8-bits:**
  - IPv4 interfaces: 4a
  - IPv6 interfaces: 6a

- **The second 8-bits:**
  - Reserved hexadecimal numbers for each IC-OS:
    - SetupOS: `0f`
    - HostOS: `00`
    - GuestOS: `01`

- **The remaining 32-bits:**
  - Deterministically generated.

## Example MAC Addresses

- SetupOS: `6a:0f:<deterministically-generated-part>`
- HostOS: `6a:00:<deterministically-generated-part>`
- GuestOS: `6a:01:<deterministically-generated-part>`

## Deterministically Generated Part

The deterministically generated part is generated using the following inputs:

1. **IPMI MAC address** (the MAC address of the BMC):
   - Obtained via:
     ```bash
     ipmitool lan print | grep 'MAC Address'
     ```

2. **Deployment name**:
   - Example: `mainnet`

The concatenation of the IPMI MAC address and deployment name is hashed:

```bash
sha256sum "<IPMI MAC ADDRESS><DEPLOYMENT NAME>"
# Example:
sha256sum "3c:ec:ef:6b:37:99mainnet"
```

The first 32 bits of the SHA-256 checksum are then used as the deterministically generated part of the MAC address:

```bash
Checksum: 
f409d72aa8c98ea40a82ea5a0a437798a67d36e587b2cc49f9dabf2de1cedeeb

Deterministically Generated Part:
f409d72a
```

## Deployment Name
The deployment name is added to the MAC address generation to further increase its uniqueness. The deployment name mainnet is reserved for production. Testnets must use other names to avoid any chance of a MAC address collision in the same data center.

The deployment name is retrieved from the deployment.json configuration file, generated as part of the SetupOS:

json
Copy code
{
  "deployment": {
    "name": "mainnet"
  }
}
