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

The config files must be accessible from inside the container - e.g., at the root of the ic directory, which maps to `/ic` inside the container.

```bash
bazel run //ic-os/setupos/envs/dev:launch_bare_metal --config=local -- \
    --config_path $(realpath ./ic-os/dev-tools/bare_metal_deployment/zh2-dll01.yaml) \
    --csv_filename $(realpath ./zh2-dll01.csv)
```

If your current username does not match the username used to log into the file shares, you must specify it:
```bash
bazel run //ic-os/setupos/envs/dev:launch_bare_metal --config=local -- \
    --file_share_username <your username per infrasec> \
    # --file_share_ssh_key <custom ssh private key> # Specify if a special ssh key is needed \
    --config_path $(realpath ./ic-os/dev-tools/bare_metal_deployment/zh2-dll01.yaml) \
    --csv_filename $(realpath ./zh2-dll01.csv)
```


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

# To develop or use finer grained features, read on.

#### Why two config files?
    
`deploy.py` accepts many CLI arguments and can source a yaml configuration file for those same arguments. The file is a convenient way to manage these but all args can be specified on the command line.

The csv file contains secrets which should _not_ be submitted via the command line. It also supports an arbitrary number of rows to deploy to an arbitrary number of machines. 


### This is all you need for local usage. 

# To develop or use finer grained features, read on.

## Requirements

* Ignore if running via bazel + devenv container from the ic repo *

* Python 3.10 (maybe lower works)
* Poetry - `pip install poetry` 
  * For local development, LSP editor support. 

### Install prereq's

`git submodule update --init`

`poetry install`

### Prep + Review input data

#### CSV secrets file

deploy.py requires a CSV file with the information to deploy to multiple BMC's. Include the BMC info _for each BMC_ where each row is "ip address, username, password".

Each row optionally includes a final parameter - the GuestOS ipv6 address. This is used to check if the resulting machine has deployed successfully. This is calculated deterministically. See bazel target /rs/ic_os/deterministic_ips to calculate.

This file is plaintext readable - make it readable only by the current user.

E.g.:
```csv
10.10.10.123,root,password
10.10.10.124,root,password
```

or

```csv
10.10.10.123,root,password,2a00:fb01:400:44:6801::1234
10.10.10.124,root,password,2a00:fb01:400:44:6801::1235
```

#### Manually preparing SetupOS image

See related google doc for details: 'SetupOS bare-metal hardware installation guide'.


## Run it 

All methods deploy serially by default. How long will it take? NUM_SERVERS * WAIT_TIME

Wait time of ~30 mins is appropriate for inter-DC image mounting. Using a local file share would be much much faster.

Use the `--parallel N` flag to deploy to N machines simultaneously.

Keep an eye on the first one via the iDRAC remote console. If the first one fails, the subsequent ones will probably fail too.


### Boot all the bmc's to the single image provided 

```bash
poetry run ./deploy.py --file_share_url <ip addr or hostname> \
    --file_share_dir <directory images are served from> \ 
    --file_share_image_filename <setupos image filename> \
    --csv_filename <csv filename>
```

Deploy to servers listed in csv file.
```bash
poetry run ./deploy.py --file_share_url 10.10.101.254 \
     --file_share_dir /srv/images \ 
    --file_share_image_filename setupos.img \
    --csv_filename ./zh2-dll01.csv \
```

Use the `--upload_file` flag to upload compressed image to fileshare, unpack to correct dir and rename. Then deploy to servers listed in csv file. SSH cert access is required for the file share. `--file_share_username` may be required to access the fileshare. Current username is used otherwise.
```bash
poetry run ./deploy.py --file_share_url 10.10.101.254 \
    --file_share_username dfnadmin \
    --file_share_dir /srv/images \ 
    --file_share_image_filename setupos.img \
    --csv_filename ./zh2-dll01.csv \
    --upload_file ./setupos-img.dev.tar.zst
```
