provider "aws" {
  alias           = "eu-central-1"
  region          = "eu-central-1"
}

provider "aws" {
  alias           = "us-east-1"
  region          = "us-east-1"
}


variable "regions" {
  description = "A list of regions to deploy instances"
  type        = list(string)
  default     = ["eu-central-1", "us-east-1"]  # Add more regions as needed
}

variable "runner_url" {
  type        = string
  description = "presigned s3 runner url"
}

resource "aws_instance" "experiment_1" {
  provider        = aws.eu_central_1
  ami             = "ami-0faab6bdbac9486fb"
  instance_type   = "t2.micro"
  key_name = aws_key_pair.generated_key_1.key_name
  vpc_security_group_ids = [aws_security_group.allow_all_1.id]

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

resource "aws_security_group" "allow_all_1" {
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

resource "aws_instance" "experiment_2" {
  provider        = aws.us_east_1
  ami             = "ami-0c7217cdde317cfec"
  instance_type   = "t2.micro"
  key_name = aws_key_pair.generated_key_2.key_name
  vpc_security_group_ids = [aws_security_group.allow_all_2.id]

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

resource "aws_security_group" "allow_all_2" {
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

resource "tls_private_key" "experiment" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "generated_key_1" {
  provider        = aws.eu_central_1
  key_name   = "my-terraform-key"
  public_key = tls_private_key.experiment.public_key_openssh
}

resource "aws_key_pair" "generated_key_2" {
  provider        = aws.us_east_1
  key_name   = "my-terraform-key"
  public_key = tls_private_key.experiment.public_key_openssh
}


resource "null_resource" "update_experiment_1" {
  depends_on = [aws_instance.experiment_1, aws_instance.experiment_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.experiment_1.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      
      "sleep 30 && /tmp/binary --id 0 --message-size 1000 --message-rate 10 --port 4100 --peers-addrs ${aws_instance.experiment_2.public_ip}:4100",
    ]
  }
}

resource "null_resource" "update_experiment_2" {
  depends_on = [aws_instance.experiment_1, aws_instance.experiment_2]

  provisioner "remote-exec" {
    connection {
      host        = aws_instance.experiment_2.public_ip
      user        = "ubuntu"
      private_key = tls_private_key.experiment.private_key_pem
    }

    inline = [
      "sleep 30 && /tmp/binary --id 1 --message-size 1000 --message-rate 10 --port 4100 --peers-addrs ${aws_instance.experiment_1.public_ip}:4100",
    ]
  }
}
