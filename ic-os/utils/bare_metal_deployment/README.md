# The Remote Image Deployer

Deploy SetupOS to bare metal remotely using BMC. 
Works only for iDRAC (currently). 

## What do you need?

* A Dell machine with iDRAC version 6 or higher
* SSH key access to a file share, preferably close to the target machine
* A [yaml file](#whats-in-the-yaml-config-file) containing configuration info
* A [csv file](#whats-in-the-csv-file) containing the BMC info and credentials


### Run it via bazel target 
    
Must be run inside the devenv container. 

The config files must be accessible from inside the container - e.g., at the root of the ic directory, which maps to `/ic` inside the container.

```
./gitlab-ci/container/container-run.sh bazel run //ic-os/setupos/envs/dev:launch_bare_metal --config=local -- \
  --config_path $(realpath ./ic-os/utils/bare_metal_deployment/example_config.yaml) \
  --csv_filename $(realpath ./zh2-dll01.csv)
```

#### What's in the yaml config file? 

```
file_share_url: <NFS share on which to upload the file>
file_share_dir: <directory on NFS share which is exposed via NFS>
file_share_image_filename: <name of image file to appear over NFS>
file_share_username: <SSH username to log into file share> # NOTE SSH KEYS ARE ASSUMED TO BE FUNCTIONAL
inject_image_ipv6_prefix: <config.ini: ipv6_prefix>
inject_image_ipv6_gateway: <config.ini: ipv6_gateway>
```

See ./example_config.yaml for a functional example. See `./deploy.py --help` for detailed docs.

#### What's in the csv file? 

Per-machine BMC secrets.

```
<ip_address>,<username>,<password>,<guestos ipv6 address>
```

See [CSV Files](#csv-files) for more info. 

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

#### CSV files

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
10.10.10.123,root,password,2a00:fb01:400:200:6801::1234
10.10.10.124,root,password,2a00:fb01:400:200:6801::1235
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
