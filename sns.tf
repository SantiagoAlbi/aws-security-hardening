# SNS Topic para alertas de seguridad
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-security-alerts"
  display_name      = "Security Hardening Alerts"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name = "${var.project_name}-security-alerts"
  }
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "security_alerts_policy" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowServicesPublish"
        Effect = "Allow"
        Principal = {
          Service = [
            "events.amazonaws.com",
            "securityhub.amazonaws.com",
            "guardduty.amazonaws.com",
            "config.amazonaws.com"
          ]
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# Email subscription
resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
