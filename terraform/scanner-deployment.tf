###################################################
# Cloud Security Scanner Deployment
###################################################

# Use the default VPC and subnet for simplicity
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  subnet_id = var.scanner_subnet_id != "" ? var.scanner_subnet_id : try(data.aws_subnets.default.ids[0], null)
}

# Deploy the security scanner
/*
module "security_scanner" {
  source                    = "./modules/scanner-deployment"
  
  # Basic configuration
  aws_region                = var.aws_region
  resource_prefix           = var.scanner_resource_prefix
  vpc_id                    = var.vpc_id
  subnet_id                 = var.subnet_id
  
  # Instance configuration
  instance_type             = var.scanner_instance_type
  allow_ssh                 = var.scanner_allow_ssh
  
  # Scanner schedule - defaults to daily at 12am UTC
  cron_schedule             = var.scanner_cron_schedule
  
  # Notifications for scanner findings
  # Use existing alerts infrastructure if you have it
  sns_alert_subscriptions   = var.scanner_alert_recipients
  smtp_notifications        = false
  slack_notifications       = false
  
  # Enable encryption for scanner artifacts
  enforce_encryption        = var.enforce_encryption

  # Tags
  tags = {
    Environment = "production"
    Service     = "security-scanner"
    Managed_by  = "terraform"
  }
}
*/ 