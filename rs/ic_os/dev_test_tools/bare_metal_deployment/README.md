# bare_metal_deployment

Developer tool for quickly pushing HostOS or GuestOS images to a bare-metal
node without redeploying SetupOS.

## How it works
- Connects to the target over SSH when possible.
- Falls back to IPMI Serial-over-LAN to inject an SSH key when direct access is
  unavailable.
- Copies the requested images to the node and triggers a reload of the GuestOS and/or
  HostOS. This replaces the images directly, to avoid going through the slow SetupOS process.

The crate is split between `deploy.rs` for the deployment logic and `lib.rs`
for the IPMI session helper used to get the machine into a reachable state.

## Examples

### Inject SSH key into bare-metal instance

```sh
bazel run rs/ic_os/dev_test_tools/bare_metal_deployment:deploy -- --login-info zh2-dll01.ini
```

### Build and deploy HostOS dev variant

```sh
bazel run rs/ic_os/dev_test_tools/bare_metal_deployment:deploy -- --login-info zh2-dll01.ini --hostos dev
```

### Build and deploy HostOS and GuestOS dev variants

```sh
bazel run rs/ic_os/dev_test_tools/bare_metal_deployment:deploy -- --login-info zh2-dll01.ini --hostos dev --guestos dev
```
