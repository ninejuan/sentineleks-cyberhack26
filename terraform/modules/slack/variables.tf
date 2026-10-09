variable "project" {
  description = "Project name for resource naming"
  type        = string
}

variable "execution_role_arn" {
  description = "IAM role ARN for Slack bot Lambda"
  type        = string
}

variable "mongodb_secret_id" {
  description = "Secrets Manager secret ID holding {\"uri\"} for MongoDB Atlas (incidents + approval_audit)"
  type        = string
}

variable "lambda_vpc_config" {
  description = "Private subnets + security group so the bot egresses through the NAT EIP allow-listed in Atlas"
  type = object({
    subnet_ids         = list(string)
    security_group_ids = list(string)
  })
}

variable "lambda_layer_arn" {
  description = "Lambda layer ARN for shared dependencies"
  type        = string
  default     = ""
}
