# IAM Role para Lambda de remediación
resource "aws_iam_role" "remediation_lambda_role" {
  name = "${var.project_name}-remediation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-remediation-lambda-role"
  }
}

# Policy: CloudWatch Logs
resource "aws_iam_role_policy_attachment" "remediation_lambda_logs" {
  role       = aws_iam_role.remediation_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Policy: Remediation permissions
resource "aws_iam_policy" "remediation_policy" {
  name        = "${var.project_name}-remediation-policy"
  description = "Permissions for security remediation Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutEncryptionConfiguration",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CopySnapshot",
          "ec2:CreateTags",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediation_policy_attach" {
  role       = aws_iam_role.remediation_lambda_role.name
  policy_arn = aws_iam_policy.remediation_policy.arn
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "remediation_lambda" {
  name              = "/aws/lambda/${var.project_name}-auto-remediation"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-remediation-logs"
  }
}

# Lambda Function
resource "aws_lambda_function" "auto_remediation" {
  filename      = "lambda_remediation.zip"
  function_name = "${var.project_name}-auto-remediation"
  role          = aws_iam_role.remediation_lambda_role.arn
  handler       = "lambda_remediation.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300 # 5 minutos
  memory_size   = 256

  environment {
    variables = {
      SNS_TOPIC_ARN  = aws_sns_topic.security_alerts.arn
      AUTO_REMEDIATE = var.enable_auto_remediation
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.remediation_lambda,
    aws_iam_role_policy_attachment.remediation_lambda_logs
  ]

  tags = {
    Name = "${var.project_name}-auto-remediation"
  }
}

# EventBridge Rule: trigger cuando Config detecta NON_COMPLIANT
resource "aws_cloudwatch_event_rule" "config_compliance_change" {
  name        = "${var.project_name}-config-compliance-change"
  description = "Trigger remediation on Config compliance changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = {
    Name = "${var.project_name}-config-compliance"
  }
}

# EventBridge Target: Lambda
resource "aws_cloudwatch_event_target" "remediation_lambda" {
  rule      = aws_cloudwatch_event_rule.config_compliance_change.name
  target_id = "RemediationLambda"
  arn       = aws_lambda_function.auto_remediation.arn
}

# Permiso para EventBridge invocar Lambda
resource "aws_lambda_permission" "allow_eventbridge_remediation" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance_change.arn
}
