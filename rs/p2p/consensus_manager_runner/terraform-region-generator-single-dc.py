import sys

# List of AWS regions
# Frankfurt
region = "eu_central_1"
ami = "ami-0faab6bdbac9486fb"
instance = "m7i.4xlarge"


merged  = """
resource "aws_security_group" "deletable-sg-eu_central_1" {
  provider        = aws.eu_central_1
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

resource "aws_key_pair" "deletable-key-eu_central_1" {
  provider        = aws.eu_central_1
  key_name   = "my-terraform-key-eu_central_1"
  public_key = tls_private_key.experiment.public_key_openssh
}

"""

local_template = """
"""

instance_template = """
resource "aws_instance" "deletable-instance-REGION" {
  provider        = aws.eu_central_1
  ami             = "AMI"
  instance_type   = "MACHINE"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_central_1.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_central_1.id]

  tags = {
    Name = "experiment"
  }
  user_data = <<EOF
#!/bin/bash

sudo sysctl -w net.core.rmem_max=500000000
sudo sysctl -w net.core.wmem_max=500000000
sudo sysctl -w net.core.rmem_default=500000000
sudo sysctl -w net.core.wmem_default=500000000
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 

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
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id ID --message-size MESSAGE_SIZE --message-rate MESSAGE_RATE --port 4100 --metrics-port 9090 --peers-addrs PEERS_ADDRS LIBP2P MODE"
    ]
  }
}
"""

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
libp2p = sys.argv[4]
oneton = sys.argv[5]

if libp2p == "true":
    libp2p_option = "--libp2p"
else:
    # libp2p_option = "--relaying"
    libp2p_option = ""

if oneton == "true":
    mode = "--oneton"
else:
    # libp2p_option = "--relaying"
    mode = ""


id = 0
for i in range(0, int(num_regions)):
  if id  > int(num_regions):
    break
  depends_on = [f"aws_instance.deletable-instance-{region}" for region in range(0, int(num_regions))]
  depends_on = f"[{', '.join(depends_on)}]"
  peers_addrs = [f"${{aws_instance.deletable-instance-{r}.private_ip}}:4100" for r in range(0, int(num_regions)) if r != i]
  peers_addrs = ' '.join(peers_addrs)
  merged += instance_template.replace("REGION", str(i)).replace("AMI", ami).replace("DEPENDS_ON", depends_on).replace("PEERS_ADDRS", peers_addrs).replace("ID", str(id)).replace("MESSAGE_SIZE", message_size).replace("MESSAGE_RATE", message_rate).replace("MACHINE", instance).replace("LIBP2P",libp2p_option).replace("MODE", mode)
  id += 1 

depends_on = [f"aws_instance.deletable-instance-{region}" for region in range(0, int(num_regions))]
depends_on = f"[{', '.join(depends_on)}]"
all_addrs = [f"${{aws_instance.deletable-instance-{r}.public_ip}}" for r in range(0, int(num_regions))]
all_addrs = ' '.join(all_addrs)
merged += local_template.replace("ALL_ADDRS", all_addrs).replace("DEPENDS_ON",depends_on)
 
with open("providers.txt") as f:
    data = f.read()
     
with open('main.tf', 'w') as f:
    # Define the data to be written
    f.write(data+merged)
