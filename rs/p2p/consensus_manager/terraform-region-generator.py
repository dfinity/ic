import sys

# List of AWS regions
region_map = {
    # Frankfurt
    "eu_central_1": ["ami-0faab6bdbac9486fb", "m7i.8xlarge"],
    # Zurich
    "eu_central_2": ["ami-02e901e47eb942582", "m6i.8xlarge"],
    # Ireland
    "eu_west_1": ["ami-0905a3c97561e0b69", "m7i.8xlarge"],
    # London
    "eu_west_2": ["ami-0e5f882be1900e43b", "m7i.8xlarge"],
    # Paris
    "eu_west_3": ["ami-01d21b7be69801c2f", "m7i.8xlarge"],
    # Stockholm
    "eu_north_1": ["ami-0014ce3e52359afbd", "m7i.8xlarge"],
    # Milan
    # "eu_south_1": "ami-056bb2662ef466553",
    # Spain
    "eu_south_2": ["ami-0a9e7160cebfd8c12", "m7i.8xlarge"],
    # N. Virgina
    "us_east_1": ["ami-0c7217cdde317cfec", "m7i.8xlarge"],
    # Ohio
    "us_east_2": ["ami-05fb0b8c1424f266b", "m7i.8xlarge"],
    # N. Cali
    "us_west_1": ["ami-0ce2cb35386fc22e9", "m7i.8xlarge"],
    # Oregon
    "us_west_2": ["ami-008fe2fc65df48dac", "m7i.8xlarge"],
    # Capetown
    # "af_south_1": ["ami-0e878fcddf2937686", "m6i.8xlarge"],
    # Hong Kong
    # "ap_east_1": ["ami-0d96ec8a788679eb2", "m6i.8xlarge"],
    # Tokio 
    # "ap_northeast_1": ["ami-07c589821f2b353aa", "m6i.8xlarge"],
    # Seoul
    # "ap_northeast_2": ["ami-0f3a440bbcff3d043", "m7i.8xlarge"],
    # Osaka
    # "ap_northeast_3": ["ami-05ff0b3a7128cd6f8", "m6i.8xlarge"],
    # Mumbai
    # "ap_south_1": ["ami-03f4878755434977f", "m7i.8xlarge"],
    # Hydrabad
    # "ap_south_2": ["ami-0bbc2f7f6287d5ca6", "m6i.8xlarge"],
    # Singapore
    # "ap_southeast_1": ["ami-0fa377108253bf620", "m6i.8xlarge"],
    # Sydney
    # "ap_southeast_2": ["ami-04f5097681773b989", "m7i.8xlarge"],
    # Jakarta
    # "ap_southeast_3": ["ami-02157887724ade8ba", "m6i.8xlarge"],
    # Bahrain
    # "me_south_1": "ami-0ce1025465c85da8d",
    # UAE
    # "me_central_1": ["ami-0b98fa71853d8d270", "m6i.8xlarge"],
    # Canada
    # "ca_central_1": ["ami-0a2e7efb4257c0907", "m7i.8xlarge"],
    # Calgary
    # "ca_west_1": ["ami-0db2fabcbd0e76d52", "m6i.8xlarge"],
    # Sao Paolo
    # "sa_east_1": ["ami-0fb4cf3a99aa89f72", "m6i.8xlarge"]
}


template = """
resource "aws_security_group" "deletable-sg-REGION" {
  provider        = aws.REGION
  name        = "allow_all"

  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "experiment"
  }
}

resource "aws_key_pair" "deletable-key-REGION" {
  provider        = aws.REGION
  key_name   = "my-terraform-key-REGION"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-REGION" {
  provider        = aws.REGION
  ami             = "AMI"
  instance_type   = "MACHINE"
  monitoring = true
  key_name = aws_key_pair.deletable-key-REGION.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-REGION.id]

  tags = {
    Name = "experiment"
  }
  user_data = <<EOF
#!/bin/bash

sudo sysctl -w net.core.rmem_max=500000000
sudo sysctl -w net.core.wmem_max=500000000
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-REGION" {
  depends_on = DEPENDS_ON

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-REGION.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id ID --message-size MESSAGE_SIZE --message-rate MESSAGE_RATE --port 4100 --metrics-port 9090 --peers-addrs PEERS_ADDRS"
    ]
  }
}

"""

local_template = """
resource "null_resource" "deletable-local-prov-REGION" {
  depends_on = DEPENDS_ON

  provisioner "local-exec" {
    command = "python3 metrics-collector.py ALL_ADDRS"
  }
}
"""


merged = ""

def keep_n_elements(d, n):
    new_dict = {}
    for key, value in d.items():
        if len(new_dict) < n:
            new_dict[key] = value
        else:
            break
    return new_dict


num_regions = sys.argv[1]
message_size = sys.argv[2]
message_rate = sys.argv[3]

region_map = keep_n_elements(region_map,int(num_regions))

id = 0
for region, ami in sorted(region_map.items()):
  if id  > int(num_regions):
    break
  depends_on = [f"aws_instance.deletable-instance-{region}" for region in sorted(region_map)]
  depends_on = f"[{', '.join(depends_on)}]"
  peers_addrs = [f"${{aws_instance.deletable-instance-{r}.public_ip}}:4100" for r in sorted(region_map) if r != region]
  peers_addrs = ' '.join(peers_addrs)
  merged += template.replace("REGION", region).replace("AMI",ami[0]).replace("DEPENDS_ON",depends_on).replace("PEERS_ADDRS", peers_addrs).replace("ID", str(id)).replace("MESSAGE_SIZE", message_size).replace("MESSAGE_RATE", message_rate).replace("MACHINE", ami[1])
  id += 1 

depends_on = [f"aws_instance.deletable-instance-{region}" for region in sorted(region_map)]
depends_on = f"[{', '.join(depends_on)}]"
all_addrs = [f"${{aws_instance.deletable-instance-{r}.public_ip}}" for r in sorted(region_map)]
all_addrs = ' '.join(all_addrs)
merged += local_template.replace("ALL_ADDRS", all_addrs).replace("DEPENDS_ON",depends_on)
 
with open("providers.txt") as f:
    data = f.read()
     
with open('main.tf', 'w') as f:
    # Define the data to be written
    f.write(data+merged)
