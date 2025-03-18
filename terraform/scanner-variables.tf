###################################################
# Scanner Deployment Variables
###################################################

/*
variable "scanner_resource_prefix" {
  description = "Prefix to add to scanner resources"
  type        = string
  default     = "security-scanner"
}

variable "scanner_instance_type" {
  description = "EC2 instance type for scanner"
  type        = string
  default     = "t3.micro"
}

variable "scanner_allow_ssh" {
  description = "Allow SSH access to scanner instance"
  type        = bool
  default     = false
}

variable "scanner_ssh_allowed_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = []
}

variable "scanner_enable_scheduled_scans" {
  description = "Enable automatic scheduled scanning"
  type        = bool
  default     = true
}

variable "scanner_cron_schedule" {
  description = "Cron schedule for automated scans"
  type        = string
  default     = "0 0 * * ?"
}

variable "scanner_cron_expression" {
  description = "Alternative scheduled expression"
  type        = string
  default     = ""
}

# Notification Variables

variable "scanner_alert_recipients" {
  description = "Email addresses for scanner alerts"
  type        = list(string)
  default     = []
}

variable "scanner_smtp_host" {
  description = "SMTP host for email notifications"
  type        = string
  default     = ""
}

variable "scanner_smtp_port" {
  description = "SMTP port for email notifications"
  type        = number
  default     = 587
}

variable "scanner_smtp_username" {
  description = "SMTP username for email notifications"
  type        = string
  default     = ""
}

variable "scanner_smtp_password" {
  description = "SMTP password for email notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "scanner_slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}
*/

variable "scanner_subnet_id" {
  description = "Subnet ID for the scanner instance"
  type        = string
  default     = ""
} 