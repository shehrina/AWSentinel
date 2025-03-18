###################################################
# Cloud Security Scanner Deployment Infrastructure
# Free Tier Version - S3 and Minimal Components Only
###################################################

resource "aws_iam_role" "scanner_role" {
  name = "cloud-security-scanner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = var.tags
}

# Attach required policies for scanning AWS resources
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.scanner_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.scanner_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# S3 bucket for storing scan reports - Free tier eligible
resource "aws_s3_bucket" "reports_bucket" {
  bucket = "${var.resource_prefix}-security-reports"

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.reports_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypt_reports" {
  bucket = aws_s3_bucket.reports_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# SNS Topic for notifications - Free tier eligible
resource "aws_sns_topic" "security_alerts" {
  name = "cloud-security-alerts"
  tags = var.tags
}

# Optional SNS Topic Subscription for email notifications - Free
resource "aws_sns_topic_subscription" "email_alerts" {
  for_each  = length(var.alert_recipients) > 0 ? toset(var.alert_recipients) : []
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = each.value
} 