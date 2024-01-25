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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-0" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

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
      "/tmp/binary --id 0 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-1" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

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
      "/tmp/binary --id 1 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-2" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-2" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 2 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-3" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-3" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-3.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 3 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-4" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-4" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-4.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 4 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-5" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-5" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-5.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 5 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-6" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-6" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-6.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 6 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-7" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-7" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-7.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 7 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-8" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-8" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-8.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 8 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-9" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-9" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-9.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 9 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-10" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-10" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-10.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 10 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-11" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-11" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-11.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 11 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-12" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-12" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-12.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 12 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-13" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-13" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-13.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 13 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-14" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-14" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-14.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 14 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-15" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-15" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-15.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 15 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-16" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-16" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-16.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 16 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-17" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-17" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-17.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 17 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-18" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-18" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-18.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 18 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-19" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-19" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-19.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 19 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-20" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-20" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-20.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 20 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-21" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-21" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-21.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 21 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-22" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-22" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-22.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 22 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-23" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-23" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-23.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 23 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-24" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-24" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-24.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 24 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-25" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-25" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-25.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 25 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-26" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-26" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-26.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 26 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-27" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-27" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-27.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 27 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-28" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-28" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-28.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 28 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-29" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-29" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-29.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 29 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-30.private_ip}:4100 "
    ]
  }
}

resource "aws_instance" "deletable-instance-30" {
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
sudo sysctl -w net.ipv4.tcp_window_scaling = 1
sudo sysctl -w net.ipv4.tcp_wmem= 10240 16777216 33554432 
sudo sysctl -w net.ipv4.tcp_rmem= 10240 16777216 33554432 
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-30" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-30.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "ip addr show",
      "sudo tc qdisc add dev enp39s0 root netem limit 50000000 delay 50ms",
      "/tmp/binary --id 30 --message-size 1000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-0.private_ip}:4100 ${aws_instance.deletable-instance-1.private_ip}:4100 ${aws_instance.deletable-instance-2.private_ip}:4100 ${aws_instance.deletable-instance-3.private_ip}:4100 ${aws_instance.deletable-instance-4.private_ip}:4100 ${aws_instance.deletable-instance-5.private_ip}:4100 ${aws_instance.deletable-instance-6.private_ip}:4100 ${aws_instance.deletable-instance-7.private_ip}:4100 ${aws_instance.deletable-instance-8.private_ip}:4100 ${aws_instance.deletable-instance-9.private_ip}:4100 ${aws_instance.deletable-instance-10.private_ip}:4100 ${aws_instance.deletable-instance-11.private_ip}:4100 ${aws_instance.deletable-instance-12.private_ip}:4100 ${aws_instance.deletable-instance-13.private_ip}:4100 ${aws_instance.deletable-instance-14.private_ip}:4100 ${aws_instance.deletable-instance-15.private_ip}:4100 ${aws_instance.deletable-instance-16.private_ip}:4100 ${aws_instance.deletable-instance-17.private_ip}:4100 ${aws_instance.deletable-instance-18.private_ip}:4100 ${aws_instance.deletable-instance-19.private_ip}:4100 ${aws_instance.deletable-instance-20.private_ip}:4100 ${aws_instance.deletable-instance-21.private_ip}:4100 ${aws_instance.deletable-instance-22.private_ip}:4100 ${aws_instance.deletable-instance-23.private_ip}:4100 ${aws_instance.deletable-instance-24.private_ip}:4100 ${aws_instance.deletable-instance-25.private_ip}:4100 ${aws_instance.deletable-instance-26.private_ip}:4100 ${aws_instance.deletable-instance-27.private_ip}:4100 ${aws_instance.deletable-instance-28.private_ip}:4100 ${aws_instance.deletable-instance-29.private_ip}:4100 "
    ]
  }
}

resource "null_resource" "deletable-local-prov-REGION" {
  depends_on = [aws_instance.deletable-instance-0, aws_instance.deletable-instance-1, aws_instance.deletable-instance-2, aws_instance.deletable-instance-3, aws_instance.deletable-instance-4, aws_instance.deletable-instance-5, aws_instance.deletable-instance-6, aws_instance.deletable-instance-7, aws_instance.deletable-instance-8, aws_instance.deletable-instance-9, aws_instance.deletable-instance-10, aws_instance.deletable-instance-11, aws_instance.deletable-instance-12, aws_instance.deletable-instance-13, aws_instance.deletable-instance-14, aws_instance.deletable-instance-15, aws_instance.deletable-instance-16, aws_instance.deletable-instance-17, aws_instance.deletable-instance-18, aws_instance.deletable-instance-19, aws_instance.deletable-instance-20, aws_instance.deletable-instance-21, aws_instance.deletable-instance-22, aws_instance.deletable-instance-23, aws_instance.deletable-instance-24, aws_instance.deletable-instance-25, aws_instance.deletable-instance-26, aws_instance.deletable-instance-27, aws_instance.deletable-instance-28, aws_instance.deletable-instance-29, aws_instance.deletable-instance-30]

  provisioner "local-exec" {
    command = "python3 metrics-collector.py ${aws_instance.deletable-instance-0.public_ip} ${aws_instance.deletable-instance-1.public_ip} ${aws_instance.deletable-instance-2.public_ip} ${aws_instance.deletable-instance-3.public_ip} ${aws_instance.deletable-instance-4.public_ip} ${aws_instance.deletable-instance-5.public_ip} ${aws_instance.deletable-instance-6.public_ip} ${aws_instance.deletable-instance-7.public_ip} ${aws_instance.deletable-instance-8.public_ip} ${aws_instance.deletable-instance-9.public_ip} ${aws_instance.deletable-instance-10.public_ip} ${aws_instance.deletable-instance-11.public_ip} ${aws_instance.deletable-instance-12.public_ip} ${aws_instance.deletable-instance-13.public_ip} ${aws_instance.deletable-instance-14.public_ip} ${aws_instance.deletable-instance-15.public_ip} ${aws_instance.deletable-instance-16.public_ip} ${aws_instance.deletable-instance-17.public_ip} ${aws_instance.deletable-instance-18.public_ip} ${aws_instance.deletable-instance-19.public_ip} ${aws_instance.deletable-instance-20.public_ip} ${aws_instance.deletable-instance-21.public_ip} ${aws_instance.deletable-instance-22.public_ip} ${aws_instance.deletable-instance-23.public_ip} ${aws_instance.deletable-instance-24.public_ip} ${aws_instance.deletable-instance-25.public_ip} ${aws_instance.deletable-instance-26.public_ip} ${aws_instance.deletable-instance-27.public_ip} ${aws_instance.deletable-instance-28.public_ip} ${aws_instance.deletable-instance-29.public_ip} ${aws_instance.deletable-instance-30.public_ip}"
  }
}
