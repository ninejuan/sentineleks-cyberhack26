import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    project: str = field(default_factory=lambda: os.environ.get("PROJECT", "seks"))
    region: str = field(default_factory=lambda: os.environ.get("AWS_REGION", "us-east-1"))
    log_level: str = field(default_factory=lambda: os.environ.get("LOG_LEVEL", "INFO"))
    agent_type: str = field(default_factory=lambda: os.environ.get("AGENT_TYPE", ""))
    bedrock_model_id: str = field(default_factory=lambda: os.environ.get("BEDROCK_MODEL_ID", ""))
    opensearch_endpoint: str = field(default_factory=lambda: os.environ.get("OPENSEARCH_ENDPOINT", ""))
    knowledge_base_id: str = field(default_factory=lambda: os.environ.get("KNOWLEDGE_BASE_ID", ""))
    state_machine_arn: str = field(default_factory=lambda: os.environ.get("STATE_MACHINE_ARN", ""))
    store_enabled: bool = field(
        default_factory=lambda: os.environ.get("INCIDENT_STORE_ENABLED", "true").lower() == "true"
    )
    eks_cluster_name: str = field(default_factory=lambda: os.environ.get("EKS_CLUSTER_NAME", "seks-demo"))
    mcp_server_url: str = field(default_factory=lambda: os.environ.get("MCP_SERVER_URL", ""))
    mcp_server_url_secret_id: str = field(
        default_factory=lambda: os.environ.get("MCP_SERVER_URL_SECRET_ID", "seks/mcp/server-url")
    )
    mcp_auth_secret_id: str = field(default_factory=lambda: os.environ.get("MCP_AUTH_SECRET_ID", "seks/mcp/auth-token"))
    mcp_timeout_seconds: int = field(default_factory=lambda: int(os.environ.get("MCP_TIMEOUT_SECONDS", "10")))
    oncall_user: str = field(default_factory=lambda: os.environ.get("ONCALL_USER", ""))
    oncall_channel: str = field(default_factory=lambda: os.environ.get("ONCALL_CHANNEL", ""))
    escalation_channel: str = field(default_factory=lambda: os.environ.get("ESCALATION_CHANNEL", ""))
    alerts_channel_p1: str = field(default_factory=lambda: os.environ.get("ALERTS_CHANNEL_P1", ""))
    alerts_channel_p2: str = field(default_factory=lambda: os.environ.get("ALERTS_CHANNEL_P2", ""))
    forensics_bucket: str = field(default_factory=lambda: os.environ.get("FORENSICS_BUCKET", ""))
    bedrock_fast_model_id: str = field(
        default_factory=lambda: os.environ.get("BEDROCK_FAST_MODEL_ID", "us.openai.gpt-5.6-luna")
    )
    bedrock_smart_model_id: str = field(
        default_factory=lambda: os.environ.get("BEDROCK_SMART_MODEL_ID", "us.openai.gpt-5.6-terra")
    )
    akash_base_url: str = field(default_factory=lambda: os.environ.get("AKASH_BASE_URL", "https://api.akashml.com/v1"))
    akash_model_id: str = field(
        default_factory=lambda: os.environ.get("AKASH_MODEL_ID", "meta-llama/Llama-3.3-70B-Instruct")
    )
    akash_secret_id: str = field(default_factory=lambda: os.environ.get("AKASH_SECRET_ID", "seks/akashml/api-key"))
    senso_base_url: str = field(
        default_factory=lambda: os.environ.get("SENSO_BASE_URL", "https://apiv2.senso.ai/api/v1")
    )
    senso_secret_id: str = field(default_factory=lambda: os.environ.get("SENSO_SECRET_ID", "seks/senso/api-key"))
    clickhouse_secret_id: str = field(
        default_factory=lambda: os.environ.get("CLICKHOUSE_SECRET_ID", "seks/clickhouse/credentials")
    )
    mongodb_secret_id: str = field(default_factory=lambda: os.environ.get("MONGODB_SECRET_ID", "seks/mongodb/uri"))
    mongodb_database: str = field(default_factory=lambda: os.environ.get("MONGODB_DATABASE", "seks"))
    tenant_id: str = field(default_factory=lambda: os.environ.get("TENANT_ID", "seks-demo"))
    slack_incident_channel: str = field(default_factory=lambda: os.environ.get("SLACK_INCIDENT_CHANNEL", ""))
