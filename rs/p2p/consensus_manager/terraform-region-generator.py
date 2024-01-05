
# List of AWS regions
region_map = {
    "eu_central_1": "ami-0faab6bdbac9486fb",
    "us_east_1": "ami-0c7217cdde317cfec",
    "eu_west_1": "ami-0905a3c97561e0b69"
}


template = """
resource "aws_security_group" "sg-REGION" {
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

resource "aws_key_pair" "key-REGION" {
  provider        = aws.eu_central_1
  key_name   = "my-terraform-key"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "instance-REGION" {
  provider        = aws.REGION
  ami             = "AMI"
  instance_type   = "t2.micro"
  key_name = aws_key_pair.key-REGION.key_name
  vpc_security_group_ids = [aws_security_group.sg-REGION.id]

  tags = {
    Name = "experiment"
  }
  user_data = <<EOF
#!/bin/bash

# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "prov-REGION" {
  depends_on = DEPENDS_ON

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.instance-REGION.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30 && /tmp/binary --id ID --message-size 1000 --message-rate 10 --port 4100 --peers-addrs PEERS_ADDRS",
    ]
  }
}
"""

merged = ""




id = 0
for region, ami in region_map.items():
  depends_on = [f"aws_instance.instance-{region}" for region in region_map]
  depends_on = f"[{', '.join(depends_on)}]"
  peers_addrs = [f"${{aws_instance.instance-{r}.public_ip}}:4100" for r in region_map if r != region]
  peers_addrs = ','.join(peers_addrs)
  merged += template.replace("REGION", region).replace("AMI",ami).replace("DEPENDS_ON",depends_on).replace("PEERS_ADDRS", peers_addrs).replace("ID", str(id))
  id += 1 
 
with open("providers.txt") as f:
    data = f.read()
     
with open('main.tf', 'w') as f:
    # Define the data to be written
    f.write(data+merged)
