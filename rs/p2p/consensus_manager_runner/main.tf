provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "us_east_2"
  region = "us-east-2"
}

provider "aws" {
  alias  = "us_west_1"
  region = "us-west-1"
}

provider "aws" {
  alias  = "us_west_2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "af_south_1"
  region = "af-south-1"
}

provider "aws" {
  alias  = "ap_east_1"
  region = "ap-east-1"
}

provider "aws" {
  alias  = "ap_south_1"
  region = "ap-south-1"
}

provider "aws" {
  alias  = "ap_south_2"
  region = "ap-south-2"
}

provider "aws" {
  alias  = "ap_northeast_3"
  region = "ap-northeast-3"
}

provider "aws" {
  alias  = "ap_northeast_2"
  region = "ap-northeast-2"
}

provider "aws" {
  alias  = "ap_southeast_1"
  region = "ap-southeast-1"
}

provider "aws" {
  alias  = "ap_southeast_2"
  region = "ap-southeast-2"
}

provider "aws" {
  alias  = "ap_southeast_3"
  region = "ap-southeast-3"
}

provider "aws" {
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"
}

provider "aws" {
  alias  = "ca_central_1"
  region = "ca-central-1"
}

provider "aws" {
  alias  = "ca_west_1"
  region = "ca-west-1"
}

provider "aws" {
  alias  = "eu_central_1"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "eu_central_2"
  region = "eu-central-2"
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

provider "aws" {
  alias  = "eu_west_2"
  region = "eu-west-2"
}

provider "aws" {
  alias  = "eu_south_1"
  region = "eu-south-1"
}

provider "aws" {
  alias  = "eu_south_2"
  region = "eu-south-2"
}

provider "aws" {
  alias  = "eu_west_3"
  region = "eu-west-3"
}

provider "aws" {
  alias  = "eu_north_1"
  region = "eu-north-1"
}

provider "aws" {
  alias  = "me_south_1"
  region = "me-south-1"
}

provider "aws"{
  alias  = "sa_east_1"
  region = "sa-east-1"
}

provider "aws" {
  alias  = "cn_north_1"
  region = "cn-north-1"
}

provider "aws" {
  alias  = "cn_northwest_1"
  region = "cn-northwest-1"
}

provider "aws" {
  alias  = "me_central_1"
  region = "me-central-1"
}

provider "aws" {
  alias  = "me_central_2"
  region = "me-central-2"
}


variable "runner_url" {
  type        = string
  description = "presigned s3 runner url"
}

resource "tls_private_key" "experiment" {
  algorithm = "RSA"
  rsa_bits  = 2048
}


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


resource "aws_instance" "deletable-instance-0" {
  provider        = aws.eu_central_1
  ami             = "ami-0faab6bdbac9486fb"
  instance_type   = "m7i.4xlarge"
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


resource "null_resource" "deletable-prov-0" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-0.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 0 --message-size 1000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-1.private_ip}:4100 --relaying"
    ]
  }
}

resource "aws_instance" "deletable-instance-1" {
  provider        = aws.eu_central_1
  ami             = "ami-0faab6bdbac9486fb"
  instance_type   = "m7i.4xlarge"
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


resource "null_resource" "deletable-prov-1" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 1 --message-size 1000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 --relaying"
    ]
  }
}

resource "null_resource" "deletable-local-prov-REGION" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1]

  provisioner "local-exec" {
    command = "python3 metrics-collector.py ${aws_instance.deletable-instance-0.public_ip} ${aws_instance.deletable-instance-1.public_ip}"
  }
}
