output "scan_report_path" {
  description = "Path to the local scan report file"
  value       = local_file.scan_report.filename
}

output "random_suffix" {
  description = "Random suffix generated for resource naming"
  value       = random_string.suffix.result
}

output "default_security_group_id" {
  description = "Default security group ID in the VPC"
  value       = data.aws_security_group.default.id
}

output "configuration_timestamp" {
  description = "Timestamp when the configuration was applied"
  value       = timestamp()
} 