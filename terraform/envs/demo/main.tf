data "aws_caller_identity" "current" {}

data "aws_bedrock_foundation_models" "claude" {
  by_provider = "Anthropic"
}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  admin_principal = var.admin_principal_arn != "" ? var.admin_principal_arn : data.aws_caller_identity.current.arn
  admin_user_name = startswith(local.admin_principal, "arn:aws:iam::${local.account_id}:user/") ? trimprefix(local.admin_principal, "arn:aws:iam::${local.account_id}:user/") : ""
  admin_role_name = startswith(local.admin_principal, "arn:aws:iam::${local.account_id}:role/") ? trimprefix(local.admin_principal, "arn:aws:iam::${local.account_id}:role/") : ""

  # OpenAI GPT-5.6 on Bedrock (Converse API): Luna for summary/triage, Terra for solution/remediation/forensics
  bedrock_fast_model_id  = "us.openai.gpt-5.6-luna"
  bedrock_smart_model_id = "us.openai.gpt-5.6-terra"

  common_tags = {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
  }
}

module "kms" {
  source = "../../modules/kms"

  project         = var.project_name
  account_id      = local.account_id
  region          = var.region
  lambda_role_arn = module.iam.lambda_agent_role_arn
}

module "s3" {
  source = "../../modules/s3"

  project     = var.project_name
  account_id  = local.account_id
  kms_key_arn = module.kms.key_arn
}

module "vpc" {
  source = "../../modules/vpc"

  project            = var.project_name
  vpc_cidr           = "10.0.0.0/16"
  availability_zones = ["${var.region}a", "${var.region}b"]
  log_bucket_arn     = module.s3.logs_bucket_arn
}

module "iam" {
  source = "../../modules/iam"

  project = var.project_name
  region  = var.region
}

module "eks" {
  source = "../../modules/eks"

  cluster_name                 = "${var.project_name}-${var.environment}"
  cluster_role_arn             = module.iam.eks_cluster_role_arn
  node_role_arn                = module.iam.eks_node_role_arn
  admin_role_arn               = local.admin_principal
  falco_pod_role_arn           = module.iam.falco_pod_role_arn
  falco_k8saudit_role_arn      = module.iam.falco_k8saudit_role_arn
  external_secrets_role_arn    = module.iam.external_secrets_role_arn
  mcp_server_role_arn          = module.iam.mcp_server_role_arn
  aws_lb_controller_role_arn   = module.iam.aws_lb_controller_role_arn
  ebs_csi_role_arn             = module.iam.ebs_csi_role_arn
  cilium_operator_role_arn     = module.iam.cilium_operator_role_arn
  tetragon_forwarder_role_arn  = module.iam.tetragon_forwarder_role_arn
  vpc_id                       = module.vpc.vpc_id
  private_subnet_ids           = module.vpc.private_subnet_ids
  endpoint_public_access_cidrs = var.endpoint_public_access_cidrs
}

module "sns_sqs" {
  source = "../../modules/sns-sqs"

  project    = var.project_name
  kms_key_id = module.kms.key_id
}

module "guardduty" {
  source = "../../modules/guardduty"

  project              = var.project_name
  lambda_arn           = module.lambda.ingestor_function_arn
  lambda_function_name = module.lambda.ingestor_function_name
}

module "opensearch" {
  source = "../../modules/opensearch"

  project             = var.project_name
  region              = var.region
  bedrock_kb_role_arn = module.iam.bedrock_kb_role_arn
  lambda_role_arn     = module.iam.lambda_agent_role_arn
  admin_principal_arn = local.admin_principal
}

module "lambda" {
  source = "../../modules/lambda"

  project                  = var.project_name
  region                   = var.region
  bedrock_fast_model_id    = local.bedrock_fast_model_id
  bedrock_smart_model_id   = local.bedrock_smart_model_id
  vpc_id                   = module.vpc.vpc_id
  private_subnet_ids       = module.vpc.private_subnet_ids
  execution_role_arn       = module.iam.lambda_agent_role_arn
  step_functions_role_arn  = module.iam.step_functions_role_arn
  sqs_queue_arn            = module.sns_sqs.sqs_queue_arn
  eks_cluster_name         = module.eks.cluster_name
  mcp_auth_secret_id       = aws_secretsmanager_secret.mcp_auth_token.name
  mcp_server_url_secret_id = aws_secretsmanager_secret.mcp_server_url.name
  forensics_bucket_name    = module.s3.forensics_bucket_id
  tenant_id                = "${var.project_name}-${var.environment}"
  akash_secret_id          = aws_secretsmanager_secret.akashml.name
  senso_secret_id          = aws_secretsmanager_secret.senso.name
  clickhouse_secret_id     = aws_secretsmanager_secret.clickhouse.name
  mongodb_secret_id        = aws_secretsmanager_secret.mongodb.name
  slack_incident_channel   = var.slack_incident_channel
  gate_image_uri           = "${aws_ecr_repository.gate.repository_url}:${var.gate_image_tag}"
}

module "slack" {
  source = "../../modules/slack"

  project            = var.project_name
  execution_role_arn = module.iam.lambda_agent_role_arn
  lambda_layer_arn   = module.lambda.lambda_layer_arn
  lambda_vpc_config = {
    subnet_ids         = module.vpc.private_subnet_ids
    security_group_ids = [module.lambda.lambda_security_group_id]
  }
  mongodb_secret_id = aws_secretsmanager_secret.mongodb.name
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.project_name}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.kms.key_arn
  }

  tags = {
    Name = "${var.project_name}-incidents"
  }
}

resource "aws_dynamodb_table" "approval_audit" {
  name         = "${var.project_name}-approval-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approval_id"

  attribute {
    name = "approval_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.kms.key_arn
  }

  tags = {
    Name = "${var.project_name}-approval-audit"
  }
}

resource "aws_dynamodb_table" "event_dedup" {
  name         = "${var.project_name}-event-dedup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "dedup_key"

  attribute {
    name = "dedup_key"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-event-dedup"
  }
}

resource "aws_dynamodb_table" "tetragon_events" {
  name         = "${var.project_name}-tetragon-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pod_uid"
  range_key    = "sk"

  attribute {
    name = "pod_uid"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.kms.key_arn
  }

  tags = {
    Name = "${var.project_name}-tetragon-events"
  }
}

resource "aws_secretsmanager_secret" "slack_bot_token" {
  name                    = "${var.project_name}/slack/bot-token"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-slack-bot-token"
  }
}

resource "aws_secretsmanager_secret" "slack_signing_secret" {
  name                    = "${var.project_name}/slack/signing-secret"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-slack-signing-secret"
  }
}

resource "aws_secretsmanager_secret" "mcp_auth_token" {
  name                    = "${var.project_name}/mcp/auth-token"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-mcp-auth-token"
  }
}

resource "aws_secretsmanager_secret" "mcp_server_url" {
  name                    = "${var.project_name}/mcp/server-url"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-mcp-server-url"
  }
}

resource "aws_secretsmanager_secret" "akashml" {
  name                    = "${var.project_name}/akashml/api-key"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-akashml-api-key"
  }
}

resource "aws_secretsmanager_secret" "senso" {
  name                    = "${var.project_name}/senso/api-key"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-senso-api-key"
  }
}

resource "aws_secretsmanager_secret" "clickhouse" {
  name                    = "${var.project_name}/clickhouse/credentials"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-clickhouse-credentials"
  }
}

resource "aws_secretsmanager_secret" "mongodb" {
  name                    = "${var.project_name}/mongodb/uri"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.project_name}-mongodb-uri"
  }
}

resource "aws_ecr_repository" "gate" {
  name                 = "${var.project_name}/gate-agent"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_security_group" "mcp_nlb" {
  name        = "${var.project_name}-sg-mcp-nlb"
  description = "Internal EKS MCP load balancer security group"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = "${var.project_name}-sg-mcp-nlb"
  }
}

resource "aws_security_group_rule" "lambda_to_mcp_nlb" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = module.lambda.lambda_security_group_id
  security_group_id        = aws_security_group.mcp_nlb.id
  description              = "Lambda agents to internal EKS MCP load balancer"
}

resource "aws_security_group_rule" "mcp_nlb_egress" {
  type              = "egress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = [module.vpc.vpc_cidr]
  security_group_id = aws_security_group.mcp_nlb.id
  description       = "MCP load balancer to in-cluster MCP pods"
}

resource "aws_ecr_repository" "mcp_server" {
  name                 = "${var.project_name}/eks-mcp-server"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-eks-mcp-server"
  }
}

resource "aws_iam_user_policy" "admin_assume_opensearch_index_manager" {
  count = local.admin_user_name != "" ? 1 : 0

  name = "${var.project_name}-assume-opensearch-index-manager"
  user = local.admin_user_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sts:AssumeRole",
      ]
      Resource = module.iam.opensearch_index_manager_role_arn
    }]
  })
}

resource "aws_iam_role_policy" "admin_assume_opensearch_index_manager" {
  count = local.admin_role_name != "" ? 1 : 0

  name = "${var.project_name}-assume-opensearch-index-manager"
  role = local.admin_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sts:AssumeRole",
      ]
      Resource = module.iam.opensearch_index_manager_role_arn
    }]
  })
}
