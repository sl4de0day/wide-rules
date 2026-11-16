resource "aws_s3_bucket_acl" "private_data" {
  bucket = "internal-audit-bucket"
  acl    = "private"
}

resource "aws_security_group_rule" "internal_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}
