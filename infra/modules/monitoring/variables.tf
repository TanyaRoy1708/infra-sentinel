variable "vpc_id" {
  description = "VPC ID for the monitoring server"
  type        = string
}

variable "subnet_id" {
  description = "Public subnet ID for the monitoring server"
  type        = string
}

variable "allowed_ip_cidr" {
  description = "Your IP in CIDR notation to allow SSH/Grafana/Prometheus access (e.g. '1.2.3.4/32')"
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
