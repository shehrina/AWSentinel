output "reports_bucket_name" {
  description = "Name of the S3 bucket storing scan reports"
  value       = aws_s3_bucket.reports_bucket.bucket
}

output "reports_bucket_arn" {
  description = "ARN of the S3 bucket storing scan reports"
  value       = aws_s3_bucket.reports_bucket.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "iam_role_arn" {
  description = "ARN of the IAM role used by the scanner"
  value       = aws_iam_role.scanner_role.arn
} 