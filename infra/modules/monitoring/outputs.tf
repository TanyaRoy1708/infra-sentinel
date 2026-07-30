output "elastic_ip" {
  description = "Public Elastic IP of the monitoring server"
  value       = aws_eip.monitoring_eip.public_ip
}

output "instance_id" {
  description = "EC2 instance ID of the monitoring server"
  value       = aws_instance.monitoring_server.id
}

output "security_group_id" {
  description = "Security Group ID attached to the monitoring server"
  value       = aws_security_group.monitoring_sg.id
}
