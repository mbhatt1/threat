"""
IAM Stack Updates - Additional permissions for agent communication and EFS access
"""

def add_efs_permissions(task_role, region, account):
    """Add EFS mount permissions to a task role"""
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "elasticfilesystem:ClientMount",
            "elasticfilesystem:ClientWrite",
            "elasticfilesystem:DescribeMountTargets",
            "elasticfilesystem:DescribeFileSystems"
        ],
        resources=[
            f"arn:aws:elasticfilesystem:{region}:{account}:file-system/*"
        ]
    ))
    
    # Access point permissions
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "elasticfilesystem:ClientRootAccess"
        ],
        resources=[
            f"arn:aws:elasticfilesystem:{region}:{account}:access-point/*"
        ]
    ))


def add_communication_permissions(task_role, region, account):
    """Add SQS and SNS permissions for inter-agent communication"""
    # SQS permissions
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl",
            "sqs:ChangeMessageVisibility"
        ],
        resources=[
            f"arn:aws:sqs:{region}:{account}:security-agent-*",
            f"arn:aws:sqs:{region}:{account}:security-priority-findings",
            f"arn:aws:sqs:{region}:{account}:security-ordered-processing.fifo"
        ]
    ))
    
    # SNS permissions
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "sns:Publish",
            "sns:Subscribe",
            "sns:GetTopicAttributes"
        ],
        resources=[
            f"arn:aws:sns:{region}:{account}:security-agent-broadcast",
            f"arn:aws:sns:{region}:{account}:security-critical-findings",
            f"arn:aws:sns:{region}:{account}:security-remediation"
        ]
    ))


def add_enhanced_monitoring_permissions(task_role, region, account):
    """Add CloudWatch metrics and logging permissions"""
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "cloudwatch:PutMetricData",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:ListMetrics"
        ],
        resources=["*"],
        conditions={
            "StringEquals": {
                "cloudwatch:namespace": ["AISecurityAudit", "SecurityAgents"]
            }
        }
    ))
    
    # X-Ray tracing
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords"
        ],
        resources=["*"]
    ))


def add_shared_resource_permissions(task_role, region, account):
    """Add permissions for accessing shared resources"""
    # SSM Parameter Store access
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath"
        ],
        resources=[
            f"arn:aws:ssm:{region}:{account}:parameter/security-audit/*"
        ]
    ))
    
    # KMS permissions for encryption
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:GenerateDataKey",
            "kms:DescribeKey"
        ],
        resources=[
            f"arn:aws:kms:{region}:{account}:key/*"
        ],
        conditions={
            "StringEquals": {
                "kms:ViaService": [
                    f"s3.{region}.amazonaws.com",
                    f"dynamodb.{region}.amazonaws.com",
                    f"sqs.{region}.amazonaws.com"
                ]
            }
        }
    ))
    
    # Service Discovery permissions
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "servicediscovery:DiscoverInstances",
            "servicediscovery:GetNamespace"
        ],
        resources=["*"]
    ))


def add_ai_agent_permissions(task_role, region, account):
    """Add permissions specific to AI-powered agents"""
    # Enhanced Bedrock permissions
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "bedrock:InvokeModel",
            "bedrock:InvokeModelWithResponseStream",
            "bedrock:ListFoundationModels",
            "bedrock:GetFoundationModel"
        ],
        resources=[
            f"arn:aws:bedrock:{region}::foundation-model/*"
        ]
    ))
    
    # SageMaker permissions for custom models
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "sagemaker:InvokeEndpoint",
            "sagemaker:DescribeEndpoint"
        ],
        resources=[
            f"arn:aws:sagemaker:{region}:{account}:endpoint/security-*"
        ]
    ))
    
    # Comprehend for NLP analysis
    task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "comprehend:DetectEntities",
            "comprehend:DetectKeyPhrases",
            "comprehend:DetectSentiment",
            "comprehend:DetectSyntax"
        ],
        resources=["*"]
    ))


def update_autonomous_task_role(autonomous_task_role, region, account):
    """Update the autonomous task role with all necessary permissions"""
    add_efs_permissions(autonomous_task_role, region, account)
    add_communication_permissions(autonomous_task_role, region, account)
    add_enhanced_monitoring_permissions(autonomous_task_role, region, account)
    add_shared_resource_permissions(autonomous_task_role, region, account)
    
    # Additional permissions for autonomous agents
    autonomous_task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets"
        ],
        resources=["*"]
    ))
    
    # CodeGuru permissions for code analysis
    autonomous_task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "codeguru-reviewer:CreateCodeReview",
            "codeguru-reviewer:DescribeCodeReview",
            "codeguru-reviewer:ListRecommendations"
        ],
        resources=[
            f"arn:aws:codeguru-reviewer:{region}:{account}:association:*"
        ]
    ))


def update_bedrock_unified_task_role(bedrock_unified_task_role, region, account):
    """Update the Bedrock unified task role with all necessary permissions"""
    add_efs_permissions(bedrock_unified_task_role, region, account)
    add_communication_permissions(bedrock_unified_task_role, region, account)
    add_enhanced_monitoring_permissions(bedrock_unified_task_role, region, account)
    add_shared_resource_permissions(bedrock_unified_task_role, region, account)
    add_ai_agent_permissions(bedrock_unified_task_role, region, account)
    
    # Additional AI-specific permissions
    bedrock_unified_task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "textract:AnalyzeDocument",
            "textract:DetectDocumentText"
        ],
        resources=["*"]
    ))
    
    # Rekognition for image analysis
    bedrock_unified_task_role.add_to_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=[
            "rekognition:DetectText",
            "rekognition:DetectLabels"
        ],
        resources=["*"]
    ))


# Usage in IAM stack:
# After creating the roles, add these permissions:
# update_autonomous_task_role(self.autonomous_task_role, self.region, self.account)
# update_bedrock_unified_task_role(self.bedrock_unified_task_role, self.region, self.account)