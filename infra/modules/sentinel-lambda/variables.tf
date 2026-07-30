variable "report_bucket_arn" {
  description = "ARN of the S3 bucket for audit reports"
  type        = string
}

variable "report_bucket_name" {
  description = "Name of the S3 bucket for audit reports (passed as Lambda env var)"
  type        = string
}

variable "tf_state_bucket_arn" {
  description = "ARN of the S3 bucket storing Terraform state files"
  type        = string
}

variable "scan_regions" {
  description = "Comma-separated AWS regions to audit (e.g. 'us-east-1,us-west-2')"
  type        = string
  default     = "us-east-1"
}

variable "lambda_zip_path" {
  description = "Path to the built Lambda zip (run 'make deploy' first)"
  type        = string
}
