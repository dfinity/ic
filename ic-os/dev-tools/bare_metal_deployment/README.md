# The Remote Image Deployer

Deploy SetupOS to bare metal remotely using BMC. 
Works only for iDRAC (currently). 
Reserve the target machine in Dee before deploying. 


## What do you need?

* A Dell machine with iDRAC version 6 or higher
* SSH key access to a file share, preferably close to the target machine
* A [yaml file](#whats-in-the-yaml-configuration-file) containing info to configure deployment
* A [csv file](#whats-in-the-csv-secrets-file) containing the BMC info and credentials


### Run it via bazel target 
    
Must be run inside the devenv container. Use `./ci/container/container-run.sh`.

The config files must be accessible from inside the container - e.g. anywhere inside the ic checkout, which the dev container mounts at the same path as on the host.

```bash
bazel run //ic-os/setupos/envs/dev:launch_bare_metal --config=local -- \
    --config_path $(realpath ./ic-os/dev-tools/bare_metal_deployment/zh2-dll01.yaml) \
    --ini_filename $(realpath ./zh2-dll01.csv)
```

If your current username does not match the username used to log into the file shares, you must specify it:
```bash
bazel run //ic-os/setupos/envs/dev:launch_bare_metal --config=local -- \
    --file_share_username <your username per infrasec> \
    # --file_share_ssh_key <custom ssh private key> # Specify if a special ssh key is needed \
    --config_path $(realpath ./ic-os/dev-tools/bare_metal_deployment/zh2-dll01.yaml) \
    --inject_image_pub_key "XXX" # Optional SSH key for access to the node after deploying, required for benchmarking \
    --ini_filename $(realpath ./zh2-dll01.csv)
```


### Performance Benchmarking

Once the desired image has been deployed to the node following the instructions above, benchmarking
can be started by passing the `--benchmark` flag to the original deployment command. Be sure to add
an SSH key when deploying for access to the node.


#### What's in the yaml configuration file? 

```
file_share_url: <NFS share on which to upload the file>
file_share_dir: <directory on NFS share which is exposed via NFS>
file_share_image_filename: <name of image file to appear over NFS>
file_share_username: <SSH username to log into file share> # NOTE SSH KEYS ARE ASSUMED TO BE FUNCTIONAL
inject_image_ipv6_prefix: <config.ini: ipv6_prefix>
inject_image_ipv6_gateway: <config.ini: ipv6_gateway>
```

These are CLI args submitted in yaml form. See [why](#why-two-config-files) or `./deploy.py --help` for detailed docs on the arguments.
See ./example_config.yaml for a functional example. 

#### What's in the csv secrets file? 

Per-machine BMC secrets. Each row represents a machine. The tool will deploy to each with the given information.

```
<ip_address>,<username>,<password>,<guestos ipv6 address>
```

See [CSV secrets file](#csv-secrets-file) for more info. 

##### Where can I find csv files for the bare metal test machines?

Next to each machine entry in 1Pass. Ask node team for details.

#### Why two config files?
    
`deploy.py` accepts many CLI arguments and can source a yaml configuration file for those same arguments. The file is a convenient way to manage these but all args can be specified on the command line.

The csv file contains secrets which should _not_ be submitted via the command line. It also supports an arbitrary number of rows to deploy to an arbitrary number of machines.
