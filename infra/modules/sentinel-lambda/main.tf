data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sentinel_lambda_role" {
  name               = "sentinel-lambda-execution-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "sentinel_lambda_policy" {
  statement {
    sid       = "AllowPutReports"
    actions   = ["s3:PutObject"]
    resources = ["${var.report_bucket_arn}/*"]
  }

  statement {
    sid       = "AllowReadTFState"
    actions   = ["s3:GetObject"]
    resources = ["${var.tf_state_bucket_arn}/*"]
  }

  statement {
    sid = "AllowReadOnlyServices"
    actions = [
      "ec2:Describe*",
      "rds:Describe*",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:ListMetrics"
    ]
    resources = ["*"]
  }

  # ce permissions are used in Phase 4 (Cost Intelligence)
  statement {
    sid = "AllowCostExplorer"
    actions = [
      "ce:GetCostAndUsage",
      "ce:GetCostForecast"
    ]
    resources = ["*"]
  }

  statement {
    sid = "AllowCloudWatchLogs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_policy" "sentinel_lambda_policy" {
  name        = "sentinel-lambda-policy"
  description = "Least-privilege policy for the Sentinel auditor Lambda"
  policy      = data.aws_iam_policy_document.sentinel_lambda_policy.json
}

resource "aws_iam_role_policy_attachment" "sentinel_lambda_attach" {
  role       = aws_iam_role.sentinel_lambda_role.name
  policy_arn = aws_iam_policy.sentinel_lambda_policy.arn
}

resource "aws_lambda_function" "sentinel_auditor" {
  function_name    = "sentinel-infrastructure-auditor"
  role             = aws_iam_role.sentinel_lambda_role.arn
  handler          = "main.lambda_handler"
  runtime          = "python3.12"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  environment {
    variables = {
      SCAN_REGIONS       = var.scan_regions
      REPORT_BUCKET_NAME = var.report_bucket_name
    }
  }
}

resource "aws_cloudwatch_event_rule" "sentinel_schedule" {
  name                = "sentinel-auditor-schedule"
  description         = "Triggers the Sentinel auditor every 6 hours"
  schedule_expression = "rate(6 hours)"
}

resource "aws_cloudwatch_event_target" "sentinel_target" {
  rule      = aws_cloudwatch_event_rule.sentinel_schedule.name
  target_id = "SentinelAuditorLambda"
  arn       = aws_lambda_function.sentinel_auditor.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sentinel_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sentinel_schedule.arn
}

resource "aws_cloudwatch_log_group" "sentinel_lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.sentinel_auditor.function_name}"
  retention_in_days = 7
}
