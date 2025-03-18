output "scan_report_path" {
  description = "Path to the local scan report file"
  value       = module.security_scanner.scan_report_path
}

output "random_suffix" {
  description = "Random suffix generated for resource naming"
  value       = module.security_scanner.random_suffix
}

output "default_security_group_id" {
  description = "Default security group ID in the VPC"
  value       = module.security_scanner.default_security_group_id
}

output "configuration_timestamp" {
  description = "Timestamp when the configuration was applied"
  value       = module.security_scanner.configuration_timestamp
} 