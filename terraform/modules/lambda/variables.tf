variable "project" {
  description = "Project name for resource naming"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "bedrock_fast_model_id" {
  description = "Bedrock model ID for fast/cheap agents (summary, triage)"
  type        = string
}

variable "bedrock_smart_model_id" {
  description = "Bedrock model ID for smart/expensive agents (solution, remediation)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for Lambda security group"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for Lambda VPC config"
  type        = list(string)
}

variable "execution_role_arn" {
  description = "IAM role ARN for Lambda execution"
  type        = string
}

variable "step_functions_role_arn" {
  description = "IAM role ARN for Step Functions"
  type        = string
}

variable "sqs_queue_arn" {
  description = "SQS queue ARN for event source mapping"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for Slack notifications"
  type        = string
  default     = ""
}

variable "eks_cluster_name" {
  description = "EKS cluster name for Remediation Agent"
  type        = string
}

variable "mcp_auth_secret_id" {
  description = "Secrets Manager secret ID for the EKS MCP bearer token"
  type        = string
  default     = "seks/mcp/auth-token"
}

variable "mcp_server_url_secret_id" {
  description = "Secrets Manager secret ID containing the private EKS MCP server URL"
  type        = string
  default     = "seks/mcp/server-url"
}

variable "forensics_bucket_name" {
  description = "Name of the forensics S3 bucket where evidence manifests and synthesis reports are written"
  type        = string
}

variable "tenant_id" {
  description = "Tenant identifier written to every sensor event and incident"
  type        = string
}

variable "akash_secret_id" {
  description = "Secrets Manager secret ID holding {\"api_key\"} for AkashML"
  type        = string
}

variable "senso_secret_id" {
  description = "Secrets Manager secret ID holding {\"api_key\"} for Senso"
  type        = string
}

variable "clickhouse_secret_id" {
  description = "Secrets Manager secret ID holding {host, username, password} for ClickHouse Cloud"
  type        = string
}

variable "mongodb_secret_id" {
  description = "Secrets Manager secret ID holding {\"uri\"} for MongoDB Atlas"
  type        = string
}

variable "slack_incident_channel" {
  description = "Slack channel ID for approval cards and incident Canvas links"
  type        = string
  default     = ""
}

variable "gate_image_uri" {
  description = "ECR image URI (with tag) for the Semgrep gate container Lambda"
  type        = string
}
