output "config_bucket_name" {
  description = "S3 bucket para AWS Config logs"
  value       = aws_s3_bucket.config_bucket.id
}

output "security_hub_arn" {
  description = "Security Hub account ARN"
  value       = aws_securityhub_account.main.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "sns_topic_arn" {
  description = "SNS topic para alertas"
  value       = aws_sns_topic.security_alerts.arn
}

output "config_recorder_name" {
  description = "Config recorder name"
  value       = aws_config_configuration_recorder.main.name
}
