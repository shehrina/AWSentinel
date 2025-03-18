// AWS Variables
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

// Scanner Variables
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

/* Commented out variables that require elevated permissions

// GCP Variables
variable "gcp_project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "The GCP region to deploy resources"
  type        = string
  default     = "us-central1"
}

variable "gcp_kms_key" {
  description = "The GCP KMS key to use for encryption"
  type        = string
  default     = ""
}

// Security Variables
variable "enforce_password_policy" {
  description = "Whether to enforce a strict password policy"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 90
}

variable "enforce_encryption" {
  description = "Whether to enforce encryption on storage resources"
  type        = bool
  default     = true
}

// Resources to Secure
variable "s3_buckets_to_secure" {
  description = "List of S3 buckets to check security configurations"
  type        = list(string)
  default     = []
}

variable "rds_instances_to_secure" {
  description = "List of RDS instances to check security configurations"
  type        = list(string)
  default     = []
}

variable "ec2_instances_to_secure" {
  description = "List of EC2 instances to check security configurations"
  type        = list(string)
  default     = []
}

variable "cloudtrail_trails_to_secure" {
  description = "List of CloudTrail trails to check security configurations"
  type        = list(string)
  default     = []
}

variable "gcs_buckets_to_secure" {
  description = "List of GCS buckets to check security configurations"
  type        = list(string)
  default     = []
}

variable "cloudsql_instances_to_secure" {
  description = "List of CloudSQL instances to check security configurations"
  type        = list(string)
  default     = []
}

// Scanner Deploy Variables
variable "scanner_instance_type" {
  description = "The instance type for the scanner"
  type        = string
  default     = "t3.micro"
}

variable "scanner_allow_ssh" {
  description = "Whether to allow SSH access to the scanner"
  type        = bool
  default     = false
}

// Network Variables
variable "allowed_ip_ranges" {
  description = "List of IP ranges to allow traffic from"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Managed_by  = "terraform"
    Purpose     = "security"
  }
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

variable "scanner_instance_type" {
  description = "The instance type for the scanner"
  type        = string
  default     = "t3.micro"
}

variable "scanner_allow_ssh" {
  description = "Whether to allow SSH access to the scanner"
  type        = bool
  default     = false
} 