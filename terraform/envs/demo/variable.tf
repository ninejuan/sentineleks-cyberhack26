variable "environment" {
  description = "Deployment environment (e.g. demo, dev, prod)"
  type        = string
  default     = "demo"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "seks"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "endpoint_public_access_cidrs" {
  description = "CIDR blocks allowed to access the EKS public endpoint (e.g. team IPs)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "admin_principal_arn" {
  description = "IAM principal ARN (user or role) to grant EKS cluster admin access. Defaults to current caller."
  type        = string
  default     = ""
}

variable "slack_incident_channel" {
  description = "Slack channel ID (C...) that receives approval cards and incident Canvas links"
  type        = string
  default     = ""
}

variable "gate_image_tag" {
  description = "Tag of the Semgrep gate image pushed by make build-gate"
  type        = string
  default     = "bootstrap"
}
