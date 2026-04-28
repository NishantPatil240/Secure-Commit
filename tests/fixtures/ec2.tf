# key pair 

resource "aws_key_pair" "my_key" {
  key_name   = "terra-key-ec2"
  public_key = file("terra-key-ec2.pub")
}

#VPC and Security groups

resource "aws_default_vpc" "my_vpc" {

}

resource "aws_security_group" "terra_sg" {
  name   = "terra-sg"
  vpc_id = aws_default_vpc.my_vpc.id

  #inbound rules

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH port open"
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP port open"
  }

  # outbound rules

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow Https outbound traffic"
  }

  tags = {
    Name = "terra-sg"
  }
}

# EC2 instance

resource "aws_instance" "terra_instance" {
  # count           = 3   #here 3 instance will be created of same type and same name
  for_each = tomap({
    automate-terra-instance-micro = "t3.micro"
    automate-terra-instance-small = "t3.small"
  })

  depends_on      = [aws_security_group.terra_sg, aws_key_pair.my_key]
  key_name        = aws_key_pair.my_key.key_name
  security_groups = [aws_security_group.terra_sg.name]
  instance_type   = each.value
  ami             = var.ec2_ami_id
  user_data       = file("install_nginx.sh")


  root_block_device {
    volume_size = var.env == "prod" ? 20 : var.ec2_default_volume_size
    volume_type = var.ec2_volume_type
  }

  tags = {
    Name = each.key
  }
}



