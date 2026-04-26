# BAD Terraform — intentional violations for testing
# AWS-001: Public S3 bucket
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

# AWS-002: SSH open to the entire internet
resource "aws_security_group" "bad_sg" {
  name = "bad-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# AWS-003: RDS without encryption
resource "aws_db_instance" "bad_db" {
  identifier        = "mydb"
  instance_class    = "db.t3.micro"
  engine            = "mysql"
  storage_encrypted = false
}

# AWS-007: IAM policy with wildcard admin
resource "aws_iam_policy" "bad_policy" {
  name = "admin-policy"
  policy = jsonencode({
    actions   = "*"
    resources = "*"
  })
}
