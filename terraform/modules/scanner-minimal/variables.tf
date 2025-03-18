variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "resource_prefix" {
  description = "Prefix to add to resource names"
  type        = string
  default     = "security-scanner"
}

variable "vpc_id" {
  description = "VPC ID where resources will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID where resources will be deployed"
  type        = string
}

variable "cron_schedule" {
  description = "Cron schedule for the scanner to run"
  type        = string
  default     = "cron(0 0 * * ? *)"
} 