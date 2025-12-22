output "security_hub_arn" {
  description = "ARN of Security Hub"
  value       = aws_securityhub_account.main.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

output "config_recorder_name" {
  description = "AWS Config recorder name"
  value       = var.enable_config ? aws_config_configuration_recorder.main[0].name : null
}

output "auto_remediation_lambda_arn" {
  description = "ARN of auto-remediation Lambda function"
  value       = aws_lambda_function.auto_remediation.arn
}

output "security_alerts_topic_arn" {
  description = "ARN of SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "s3_buckets" {
  description = "S3 buckets created for CSPM"
  value = {
    guardduty_findings = aws_s3_bucket.guardduty_findings.id
    config             = aws_s3_bucket.config.id
    lambda_code        = aws_s3_bucket.lambda_code.id
  }
}