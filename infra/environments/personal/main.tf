variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID for the monitoring server"
  type        = string
}

variable "subnet_id" {
  description = "Public subnet ID for the monitoring server"
  type        = string
}

variable "allowed_ip_cidr" {
  description = "Your IP in CIDR notation for SSH/Grafana/Prometheus access (e.g. '1.2.3.4/32')"
  type        = string
}

variable "key_name" {
  description = "EC2 Key Pair name for SSH access"
  type        = string
}

variable "grafana_admin_password" {
  description = "Grafana admin password — treat as a secret, do not commit"
  type        = string
  sensitive   = true
}

variable "report_bucket_name" {
  description = "Name of the S3 bucket for audit reports"
  type        = string
}

variable "report_bucket_arn" {
  description = "ARN of the S3 bucket for audit reports"
  type        = string
}

variable "tf_state_bucket_arn" {
  description = "ARN of the S3 bucket storing Terraform state"
  type        = string
}

variable "scan_regions" {
  description = "Comma-separated AWS regions to audit"
  type        = string
  default     = "us-east-1"
}

variable "lambda_zip_path" {
  description = "Path to the Lambda zip (run 'make deploy' first)"
  type        = string
  default     = "../../../build/sentinel-auditor.zip"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "personal"
      Project     = "infra-sentinel"
      ManagedBy   = "terraform"
    }
  }
}

module "sentinel_lambda" {
  source = "../../modules/sentinel-lambda"

  report_bucket_name  = var.report_bucket_name
  report_bucket_arn   = var.report_bucket_arn
  tf_state_bucket_arn = var.tf_state_bucket_arn
  scan_regions        = var.scan_regions
  lambda_zip_path     = var.lambda_zip_path
}

module "monitoring" {
  source = "../../modules/monitoring"

  vpc_id                 = var.vpc_id
  subnet_id              = var.subnet_id
  allowed_ip_cidr        = var.allowed_ip_cidr
  key_name               = var.key_name
  grafana_admin_password = var.grafana_admin_password
}

output "sentinel_lambda_arn" {
  description = "ARN of the Sentinel Lambda function"
  value       = module.sentinel_lambda.function_arn
}

output "monitoring_server_ip" {
  description = "Elastic IP of the monitoring server"
  value       = module.monitoring.elastic_ip
}

output "grafana_dashboard_url" {
  description = "Grafana URL (may take ~60s after apply for Docker to start)"
  value       = "http://${module.monitoring.elastic_ip}:3000"
}
