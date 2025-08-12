"""
Parameters Stack - SSM Parameters and Secrets Manager for Security Audit Framework
"""
from aws_cdk import (
    Stack,
    aws_ssm as ssm,
    aws_secretsmanager as secrets,
    aws_kms as kms,
    RemovalPolicy,
    CfnOutput
)
from constructs import Construct


class ParametersStack(Stack):
    """SSM Parameters and Secrets for Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str, 
                 kms_key: kms.Key = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Slack webhook URL parameter (SecureString) - placeholder to be updated via console
        self.slack_webhook_param = ssm.StringParameter(
            self, "SlackWebhookUrl",
            parameter_name="/security-audit/slack-webhook-url",
            string_value="CHANGE_ME_IN_CONSOLE",  # Must be updated after deployment
            description="Slack webhook URL for security notifications - UPDATE AFTER DEPLOYMENT",
            tier=ssm.ParameterTier.STANDARD,
            type=ssm.ParameterType.SECURE_STRING
        )
        
        # Teams webhook URL parameter (SecureString) - placeholder to be updated via console
        self.teams_webhook_param = ssm.StringParameter(
            self, "TeamsWebhookUrl",
            parameter_name="/security-audit/teams-webhook-url",
            string_value="CHANGE_ME_IN_CONSOLE",  # Must be updated after deployment
            description="Microsoft Teams webhook URL for security notifications - UPDATE AFTER DEPLOYMENT",
            tier=ssm.ParameterTier.STANDARD,
            type=ssm.ParameterType.SECURE_STRING
        )
        
        # API authentication token secret
        self.api_token_secret = secrets.Secret(
            self, "ApiAuthToken",
            secret_name="security-audit/api-auth-token",
            description="API authentication token for custom authorizer",
            generate_secret_string=secrets.SecretStringGenerator(
                secret_string_template='{"token": ""}',
                generate_string_key="token",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\\",
                password_length=32
            ),
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # GitHub token for integrations - generates placeholder that must be updated
        self.github_token_secret = secrets.Secret(
            self, "GitHubToken",
            secret_name="security-audit/github-token",
            description="GitHub personal access token for repository access - UPDATE WITH ACTUAL TOKEN",
            generate_secret_string=secrets.SecretStringGenerator(
                secret_string_template='{"token": ""}',
                generate_string_key="token",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\\",
                password_length=40,
                include_space=False
            ),
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Container registry credentials
        self.ecr_scanning_credentials = secrets.Secret(
            self, "ECRScanningCredentials",
            secret_name="security-audit/ecr-scanning-credentials",
            description="Credentials for ECR vulnerability scanning",
            generate_secret_string=secrets.SecretStringGenerator(
                secret_string_template='{"username": "", "password": ""}',
                generate_string_key="password",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\\",
                password_length=32
            ),
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Vulnerability database API keys
        self.nvd_api_key = secrets.Secret(
            self, "NVDApiKey",
            secret_name="security-audit/nvd-api-key",
            description="NIST NVD API key for vulnerability database access",
            generate_secret_string=secrets.SecretStringGenerator(
                secret_string_template='{"api_key": ""}',
                generate_string_key="api_key",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\\",
                password_length=40
            ),
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Third-party security service API keys
        self.security_service_keys = secrets.Secret(
            self, "SecurityServiceKeys",
            secret_name="security-audit/third-party-keys",
            description="API keys for third-party security services",
            secret_object_value={
                "snyk_api_key": secrets.SecretValue.unsafe_plain_text("CHANGE_ME"),
                "sonarqube_token": secrets.SecretValue.unsafe_plain_text("CHANGE_ME"),
                "virustotal_api_key": secrets.SecretValue.unsafe_plain_text("CHANGE_ME"),
                "shodan_api_key": secrets.SecretValue.unsafe_plain_text("CHANGE_ME")
            },
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Cross-account scanning role ARN
        self.cross_account_role_secret = secrets.Secret(
            self, "CrossAccountRoleArn",
            secret_name="security-audit/cross-account-role",
            description="ARN of cross-account role for scanning other AWS accounts",
            generate_secret_string=secrets.SecretStringGenerator(
                secret_string_template='{"role_arn": "arn:aws:iam::ACCOUNT_ID:role/SecurityAuditRole", "external_id": ""}',
                generate_string_key="external_id",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\\",
                password_length=32
            ),
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Jenkins integration credentials
        self.jenkins_credentials = secrets.Secret(
            self, "JenkinsCredentials",
            secret_name="security-audit/jenkins-credentials",
            description="Jenkins API credentials for CI/CD integration",
            generate_secret_string=secrets.SecretStringGenerator(
                secret_string_template='{"username": "jenkins-user", "api_token": ""}',
                generate_string_key="api_token",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\\",
                password_length=32
            ),
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # AI model API keys
        self.ai_model_keys = secrets.Secret(
            self, "AIModelKeys",
            secret_name="security-audit/ai-model-keys",
            description="API keys for AI/ML services",
            secret_object_value={
                "openai_api_key": secrets.SecretValue.unsafe_plain_text("CHANGE_ME"),
                "anthropic_api_key": secrets.SecretValue.unsafe_plain_text("CHANGE_ME"),
                "huggingface_token": secrets.SecretValue.unsafe_plain_text("CHANGE_ME")
            },
            encryption_key=kms_key,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Feature flags
        self.enable_ai_features = ssm.StringParameter(
            self, "EnableAIFeatures",
            parameter_name="/security-audit/features/enable-ai",
            string_value="true",
            description="Enable AI-powered security features",
            tier=ssm.ParameterTier.STANDARD
        )
        
        self.enable_auto_remediation = ssm.StringParameter(
            self, "EnableAutoRemediation",
            parameter_name="/security-audit/features/enable-auto-remediation",
            string_value="false",
            description="Enable automatic remediation of security issues",
            tier=ssm.ParameterTier.STANDARD
        )
        
        # Configuration parameters
        self.scan_timeout = ssm.StringParameter(
            self, "ScanTimeout",
            parameter_name="/security-audit/config/scan-timeout",
            string_value="3600",
            description="Maximum scan duration in seconds",
            tier=ssm.ParameterTier.STANDARD
        )
        
        self.max_concurrent_scans = ssm.StringParameter(
            self, "MaxConcurrentScans",
            parameter_name="/security-audit/config/max-concurrent-scans",
            string_value="10",
            description="Maximum number of concurrent scans",
            tier=ssm.ParameterTier.STANDARD
        )
        
        # AI model configuration
        self.bedrock_model_id = ssm.StringParameter(
            self, "BedrockModelId",
            parameter_name="/security-audit/ai/bedrock-model-id",
            string_value="anthropic.claude-3-sonnet-20240229-v1:0",
            description="Bedrock model ID for AI analysis",
            tier=ssm.ParameterTier.STANDARD
        )
        
        self.ai_temperature = ssm.StringParameter(
            self, "AITemperature",
            parameter_name="/security-audit/ai/temperature",
            string_value="0.1",
            description="AI model temperature for consistent results",
            tier=ssm.ParameterTier.STANDARD
        )
        
        # Outputs
        CfnOutput(
            self, "SlackWebhookParamName",
            value=self.slack_webhook_param.parameter_name,
            description="SSM parameter name for Slack webhook URL"
        )
        
        CfnOutput(
            self, "TeamsWebhookParamName",
            value=self.teams_webhook_param.parameter_name,
            description="SSM parameter name for Teams webhook URL"
        )
        
        CfnOutput(
            self, "ApiTokenSecretArn",
            value=self.api_token_secret.secret_arn,
            description="ARN of API authentication token secret"
        )