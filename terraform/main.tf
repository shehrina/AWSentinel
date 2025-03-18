terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
    /* Remove Google provider completely
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    */
  }
}

# AWS Provider configuration
provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# GCP Provider configuration - commented out since we're focusing on AWS
/* 
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
*/

# AWS S3 Bucket remediation
resource "aws_s3_bucket_public_access_block" "block_public_access" {
  for_each = toset(var.s3_buckets_to_secure)

  bucket = each.value

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AWS RDS encryption enforcement
resource "aws_rds_cluster_parameter_group" "force_ssl" {
  for_each = toset(var.rds_clusters_to_secure)

  family = "aurora-postgresql13"
  name   = "${each.value}-force-ssl"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

/* Comment out all GCP resources
# GCP Storage bucket remediation
resource "google_storage_bucket" "secure_buckets" {
  for_each = toset(var.gcs_buckets_to_secure)

  name     = each.value
  location = var.gcp_region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = var.gcp_kms_key
  }
}

# GCP Cloud SQL encryption
resource "google_sql_database_instance" "secure_instances" {
  for_each = toset(var.cloudsql_instances_to_secure)

  name             = each.value
  database_version = "POSTGRES_13"
  region          = var.gcp_region

  settings {
    tier = "db-f1-micro"
    
    ip_configuration {
      require_ssl = true
    }
    
    backup_configuration {
      enabled = true
    }
    
    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
  }
}
*/

# IAM policy enforcement
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers               = true
  require_uppercase_characters   = true
  require_symbols               = true
  allow_users_to_change_password = true
  password_reuse_prevention     = 24
  max_password_age             = 90
}

# Security group remediation
resource "aws_security_group_rule" "restrict_access" {
  for_each = var.security_groups_to_restrict

  type              = "ingress"
  from_port         = each.value.port
  to_port           = each.value.port
  protocol          = "tcp"
  cidr_blocks       = each.value.allowed_cidrs
  security_group_id = each.value.security_group_id
}

# Logging and monitoring
resource "aws_cloudwatch_log_group" "security_logs" {
  name              = "/aws/security-scanner/logs"
  retention_in_days = var.log_retention_days
}

/* Comment out all GCP resources
resource "google_logging_project_sink" "security_sink" {
  name        = "security-audit-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = "resource.type=cloud_audit_log"

  unique_writer_identity = true
}

resource "google_storage_bucket" "audit_logs" {
  name     = "${var.gcp_project_id}-security-audit-logs"
  location = var.gcp_region

  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
} 
*/

variable "aws_region" {
  description = "The AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_access_key" {
  description = "AWS access key"
  type        = string
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS secret key"
  type        = string
  sensitive   = true
}

variable "vpc_id" {
  description = "The VPC ID to deploy resources"
  type        = string
}

variable "subnet_id" {
  description = "The subnet ID to deploy resources"
  type        = string
}

variable "scanner_resource_prefix" {
  description = "Prefix to add to all scanner resources"
  type        = string
  default     = "security-scanner"
}

variable "scanner_cron_schedule" {
  description = "Cron schedule for the scanner to run"
  type        = string
  default     = "cron(0 0 * * ? *)"
}

# Minimal Security Scanner Module - only creates resources with limited permissions
module "security_scanner" {
  source            = "./modules/scanner-minimal"
  
  # Basic configuration
  aws_region        = var.aws_region
  resource_prefix   = var.scanner_resource_prefix
  vpc_id            = var.vpc_id
  subnet_id         = var.subnet_id
  
  # Scanner schedule
  cron_schedule     = var.scanner_cron_schedule
}

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