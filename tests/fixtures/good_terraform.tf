# GOOD Terraform — all rules satisfied
resource "aws_s3_bucket" "good_bucket" {
  bucket = "my-private-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }
}

resource "aws_security_group" "good_sg" {
  name = "good-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "good_db" {
  identifier        = "mydb"
  instance_class    = "db.t3.micro"
  engine            = "mysql"
  storage_encrypted = true
}

resource "aws_cloudtrail" "good_trail" {
  name          = "main-trail"
  enable_logging = true
}
