output "function_arn" {
  description = "ARN of the Sentinel Lambda function"
  value       = aws_lambda_function.sentinel_auditor.arn
}

output "function_name" {
  description = "Name of the Sentinel Lambda function"
  value       = aws_lambda_function.sentinel_auditor.function_name
}

output "iam_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.sentinel_lambda_role.arn
}
