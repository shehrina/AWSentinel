variable "resource_prefix" {
  description = "Prefix to add to resource names for uniqueness"
  type        = string
  default     = "cloud-security"
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance (Ubuntu recommended)"
  type        = string
  # Default Ubuntu 22.04 LTS in us-east-1
  default     = "ami-0c7217cdde317cfec"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "subnet_id" {
  description = "Subnet ID for EC2 instance deployment"
  type        = string
}

variable "allow_ssh" {
  description = "Allow SSH access to the EC2 instance"
  type        = bool
  default     = false
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH to the EC2 instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "scan_cron_schedule" {
  description = "Cron schedule for running the scanner (used in crontab)"
  type        = string
  default     = "0 0 * * *"  # Daily at midnight
}

variable "scan_cron_expression" {
  description = "Cron expression for CloudWatch Events schedule"
  type        = string
  default     = "0 0 * * ? *"  # Daily at midnight
}

variable "enable_scheduled_scans" {
  description = "Enable scheduled scanning"
  type        = bool
  default     = true
}

variable "alert_recipients" {
  description = "Email addresses to receive scanner alerts"
  type        = list(string)
  default     = []
}

variable "smtp_host" {
  description = "SMTP server host for email alerts"
  type        = string
  default     = "smtp.gmail.com"
}

variable "smtp_port" {
  description = "SMTP server port for email alerts"
  type        = string
  default     = "587"
}

variable "smtp_username" {
  description = "SMTP username for email alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "smtp_password" {
  description = "SMTP password for email alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Project     = "Cloud Security Scanner"
    Environment = "Production"
    Terraform   = "true"
  }
} 