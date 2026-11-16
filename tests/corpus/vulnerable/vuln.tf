resource "aws_s3_bucket_acl" "bad_acl" {
  bucket = "leaked-assets"
  acl    = "public-read"
}

resource "aws_security_group_rule" "open_world" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
