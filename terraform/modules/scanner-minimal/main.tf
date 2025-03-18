# Minimal Security Scanner Module
# This module only creates resources that require minimal permissions
# Version: free-tier-minimal

# Local variables
locals {
  resource_prefix = var.resource_prefix != "" ? "${var.resource_prefix}-" : ""
}

# Read-only data sources
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# Security group data source (read-only)
data "aws_security_group" "default" {
  vpc_id = var.vpc_id
  name   = "default"
}

# Random string for unique resource naming
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Outputs file with scan results
resource "local_file" "scan_report" {
  content  = jsonencode({
    timestamp = timestamp()
    region    = var.aws_region
    message   = "Security scanner configuration ready for minimal deployment"
    vpc_id    = var.vpc_id
    subnet_id = var.subnet_id
    account_id = data.aws_caller_identity.current.account_id
  })
  filename = "${path.module}/scan_report.json"
}

# Null resource that can be used to trigger local scanner execution
resource "null_resource" "scanner_trigger" {
  triggers = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    command = "echo 'Security scanner configuration ready at ${timestamp()}'"
  }
} 