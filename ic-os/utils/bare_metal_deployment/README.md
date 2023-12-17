# The Remote Image Deployer

Get SetupOS images to run remotely given BMC info. Works only for iDRAC (currently). Use bazel target or run in poetry shell.

### Run it via bazel target 
    
From inside the devenv container! I.e.: first run `./gitlab-ci/container/container-run.sh` -

```
bazel run //ic-os/setupos/envs/dev:launch_bare_metal --config=local -- \
  --config_path $(realpath ./ic-os/utils/bare_metal_deployment/example_config.yaml) \
  --csv_filename $(realpath ./zh2-dll01.csv)
```

This is all you need for local usage. 

To develop or use finer grained features, read on.


## Requirements

Ignore if running via bazel + devenv container from the ic repo (see below).

* Python 3.10 (maybe lower works)
* Poetry - `pip install poetry` 
  * For local development, LSP editor support. 

### Install prereq's

`git submodule update --init`

`poetry install`

### Prep + Review input data

#### CSV files

deploy.py requires a CSV file with the information to deploy to multiple BMC's. Include the BMC info _for each BMC_ where each row is "ip address, username, password".

Each row can include an extra parameter - the GuestOS ipv6 address. This is used to check if the resulting machine has deployed successfully.

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

#### SetupOS image

If running via the bazel target, skip this section.

Prepare the image for deployment - config.ini, etc.. See the related google doc for details: 'SetupOS bare-metal hardware installation guide'.

Skip these instructions if using the `--upload_file` flag, passing in the compressed file from the above step. Skip directly to running `deploy.py`.

Send to NFS file share:
```bash
# Send to nfs file share machine. Alternatively mount the nfs (if you're allowlisted) and cp to it
scp sh1-setupos.img.zst dfnadmin@zh2-rmu.zh2.dfinity.network:
```

Log in, decompress, host image:
```bash
# Commands run after `ssh dfnadmin@zh2-rmu.zh2.dfinity.network`
zstd -d sh1-setupos.img.zst
sudo mv sh1-setupos.img /srv/images
```

Consider the network url format expected by the tool+iDRAC: "<IP_ADDRESS>:<PATH_TO_IMAGE>"
E.g., "10.10.101.254:/srv/images/sh1-setupos.img"

The network image url must point to an NFS file share. 
    
**The file share machine firewall must allow traffic from the target bmc ip addresses!** 

We've been using `zh2-rmu` for testing. Add the new DC's to the allowlist. 


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
