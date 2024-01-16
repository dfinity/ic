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

resource "aws_instance" "deletable-instance-eu_central_1" {
  provider        = aws.eu_central_1
  ami             = "ami-0faab6bdbac9486fb"
  instance_type   = "m7i.8xlarge"
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
# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "${var.runner_url}"

# Make binary executable
chmod +x /tmp/binary
EOF
}


resource "null_resource" "deletable-prov-eu_central_1" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_central_1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 0 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-eu_central_2" {
  provider        = aws.eu_central_2
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

resource "aws_key_pair" "deletable-key-eu_central_2" {
  provider        = aws.eu_central_2
  key_name   = "my-terraform-key-eu_central_2"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-eu_central_2" {
  provider        = aws.eu_central_2
  ami             = "ami-02e901e47eb942582"
  instance_type   = "m6i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_central_2.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_central_2.id]

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


resource "null_resource" "deletable-prov-eu_central_2" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_central_2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 1 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-eu_north_1" {
  provider        = aws.eu_north_1
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

resource "aws_key_pair" "deletable-key-eu_north_1" {
  provider        = aws.eu_north_1
  key_name   = "my-terraform-key-eu_north_1"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-eu_north_1" {
  provider        = aws.eu_north_1
  ami             = "ami-0014ce3e52359afbd"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_north_1.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_north_1.id]

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


resource "null_resource" "deletable-prov-eu_north_1" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_north_1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 2 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-eu_south_2" {
  provider        = aws.eu_south_2
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

resource "aws_key_pair" "deletable-key-eu_south_2" {
  provider        = aws.eu_south_2
  key_name   = "my-terraform-key-eu_south_2"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-eu_south_2" {
  provider        = aws.eu_south_2
  ami             = "ami-0a9e7160cebfd8c12"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_south_2.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_south_2.id]

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


resource "null_resource" "deletable-prov-eu_south_2" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_south_2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 3 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-eu_west_1" {
  provider        = aws.eu_west_1
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

resource "aws_key_pair" "deletable-key-eu_west_1" {
  provider        = aws.eu_west_1
  key_name   = "my-terraform-key-eu_west_1"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-eu_west_1" {
  provider        = aws.eu_west_1
  ami             = "ami-0905a3c97561e0b69"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_west_1.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_west_1.id]

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


resource "null_resource" "deletable-prov-eu_west_1" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_west_1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 4 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-eu_west_2" {
  provider        = aws.eu_west_2
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

resource "aws_key_pair" "deletable-key-eu_west_2" {
  provider        = aws.eu_west_2
  key_name   = "my-terraform-key-eu_west_2"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-eu_west_2" {
  provider        = aws.eu_west_2
  ami             = "ami-0e5f882be1900e43b"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_west_2.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_west_2.id]

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


resource "null_resource" "deletable-prov-eu_west_2" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_west_2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 5 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-eu_west_3" {
  provider        = aws.eu_west_3
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

resource "aws_key_pair" "deletable-key-eu_west_3" {
  provider        = aws.eu_west_3
  key_name   = "my-terraform-key-eu_west_3"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-eu_west_3" {
  provider        = aws.eu_west_3
  ami             = "ami-01d21b7be69801c2f"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-eu_west_3.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-eu_west_3.id]

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


resource "null_resource" "deletable-prov-eu_west_3" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-eu_west_3.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 6 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-us_east_1" {
  provider        = aws.us_east_1
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

resource "aws_key_pair" "deletable-key-us_east_1" {
  provider        = aws.us_east_1
  key_name   = "my-terraform-key-us_east_1"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-us_east_1" {
  provider        = aws.us_east_1
  ami             = "ami-0c7217cdde317cfec"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-us_east_1.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-us_east_1.id]

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


resource "null_resource" "deletable-prov-us_east_1" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-us_east_1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 7 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-us_east_2" {
  provider        = aws.us_east_2
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

resource "aws_key_pair" "deletable-key-us_east_2" {
  provider        = aws.us_east_2
  key_name   = "my-terraform-key-us_east_2"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-us_east_2" {
  provider        = aws.us_east_2
  ami             = "ami-05fb0b8c1424f266b"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-us_east_2.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-us_east_2.id]

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


resource "null_resource" "deletable-prov-us_east_2" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-us_east_2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 8 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-us_west_1" {
  provider        = aws.us_west_1
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

resource "aws_key_pair" "deletable-key-us_west_1" {
  provider        = aws.us_west_1
  key_name   = "my-terraform-key-us_west_1"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-us_west_1" {
  provider        = aws.us_west_1
  ami             = "ami-0ce2cb35386fc22e9"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-us_west_1.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-us_west_1.id]

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


resource "null_resource" "deletable-prov-us_west_1" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-us_west_1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 9 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_2.public_ip}:4100"
    ]
  }
}


resource "aws_security_group" "deletable-sg-us_west_2" {
  provider        = aws.us_west_2
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

resource "aws_key_pair" "deletable-key-us_west_2" {
  provider        = aws.us_west_2
  key_name   = "my-terraform-key-us_west_2"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_instance" "deletable-instance-us_west_2" {
  provider        = aws.us_west_2
  ami             = "ami-008fe2fc65df48dac"
  instance_type   = "m7i.8xlarge"
  monitoring = true
  key_name = aws_key_pair.deletable-key-us_west_2.key_name
  vpc_security_group_ids = [aws_security_group.deletable-sg-us_west_2.id]

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


resource "null_resource" "deletable-prov-us_west_2" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.deletable-instance-us_west_2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30",
      "/tmp/binary --id 10 --message-size 5000000 --message-rate 10 --port 4100 --metrics-port 9090 --peers-addrs ${aws_instance.deletable-instance-eu_central_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_central_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_north_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_south_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_1.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_2.public_ip}:4100 ${aws_instance.deletable-instance-eu_west_3.public_ip}:4100 ${aws_instance.deletable-instance-us_east_1.public_ip}:4100 ${aws_instance.deletable-instance-us_east_2.public_ip}:4100 ${aws_instance.deletable-instance-us_west_1.public_ip}:4100"
    ]
  }
}


resource "null_resource" "deletable-local-prov-REGION" {
  depends_on = [aws_instance.deletable-instance-eu_central_1, aws_instance.deletable-instance-eu_central_2, aws_instance.deletable-instance-eu_north_1, aws_instance.deletable-instance-eu_south_2, aws_instance.deletable-instance-eu_west_1, aws_instance.deletable-instance-eu_west_2, aws_instance.deletable-instance-eu_west_3, aws_instance.deletable-instance-us_east_1, aws_instance.deletable-instance-us_east_2, aws_instance.deletable-instance-us_west_1, aws_instance.deletable-instance-us_west_2]

  provisioner "local-exec" {
    command = "python3 metrics-collector.py ${aws_instance.deletable-instance-eu_central_1.public_ip} ${aws_instance.deletable-instance-eu_central_2.public_ip} ${aws_instance.deletable-instance-eu_north_1.public_ip} ${aws_instance.deletable-instance-eu_south_2.public_ip} ${aws_instance.deletable-instance-eu_west_1.public_ip} ${aws_instance.deletable-instance-eu_west_2.public_ip} ${aws_instance.deletable-instance-eu_west_3.public_ip} ${aws_instance.deletable-instance-us_east_1.public_ip} ${aws_instance.deletable-instance-us_east_2.public_ip} ${aws_instance.deletable-instance-us_west_1.public_ip} ${aws_instance.deletable-instance-us_west_2.public_ip}"
  }
}
