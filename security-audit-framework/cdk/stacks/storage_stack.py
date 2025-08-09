"""
Storage Stack - S3 buckets and DynamoDB tables with Intelligent Lifecycle Policies
"""
from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    RemovalPolicy,
    Duration,
    CfnOutput,
    aws_lambda as lambda_,
    aws_iam as iam,
    Tags
)
from constructs import Construct


class StorageStack(Stack):
    """Storage resources for Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # S3 bucket for scan results
        self.results_bucket = s3.Bucket(
            self, "ScanResultsBucket",
            bucket_name=f"security-scan-results-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            lifecycle_rules=self._create_intelligent_lifecycle_rules(),
            removal_policy=RemovalPolicy.RETAIN  # Retain bucket on stack deletion
        )
        
        # Enable S3 Inventory for cost analysis
        # TODO: Fix inventory configuration for CDK v2
        # self.results_bucket.add_inventory(
        #     id="DailyInventory",
        #     frequency=s3.InventoryFrequency.DAILY,
        #     include_object_versions=s3.InventoryObjectVersion.CURRENT,
        #     optional_fields=[
        #         s3.InventoryOptionalField.SIZE,
        #         s3.InventoryOptionalField.LAST_MODIFIED_DATE,
        #         s3.InventoryOptionalField.STORAGE_CLASS,
        #         s3.InventoryOptionalField.ENCRYPTION_STATUS
        #     ]
        # )
        
        # DynamoDB table for scan metadata
        self.scan_table = dynamodb.Table(
            self, "ScanTable",
            table_name="SecurityScans",
            partition_key=dynamodb.Attribute(
                name="scan_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN  # Retain table on stack deletion
        )
        
        # Add GSI for querying by repository
        self.scan_table.add_global_secondary_index(
            index_name="repository-index",
            partition_key=dynamodb.Attribute(
                name="repository_url",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Add GSI for querying by status
        self.scan_table.add_global_secondary_index(
            index_name="status-index",
            partition_key=dynamodb.Attribute(
                name="status",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.INCLUDE,
            non_key_attributes=["scan_id", "repository_url", "total_findings"]
        )
        
        # DynamoDB table for agent configurations (optional)
        self.config_table = dynamodb.Table(
            self, "ConfigTable",
            table_name="SecurityAgentConfigs",
            partition_key=dynamodb.Attribute(
                name="agent_type",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            removal_policy=RemovalPolicy.DESTROY  # Can be recreated
        )
        
        # DynamoDB table for remediation records
        self.remediation_table = dynamodb.Table(
            self, "RemediationTable",
            table_name="SecurityRemediations",
            partition_key=dynamodb.Attribute(
                name="remediation_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN  # Keep remediation records
        )
        
        # Add GSI for querying by scan_id
        self.remediation_table.add_global_secondary_index(
            index_name="scan-index",
            partition_key=dynamodb.Attribute(
                name="scan_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # AI-Powered Tables
        self._create_ai_tables()
        
        # Output bucket name for other stacks
        CfnOutput(
            self, "ResultsBucketName",
            value=self.results_bucket.bucket_name,
            description="S3 bucket for scan results"
        )
        
        CfnOutput(
            self, "ScanTableName",
            value=self.scan_table.table_name,
            description="DynamoDB table for scan metadata"
        )
        
        CfnOutput(
            self, "RemediationTableName",
            value=self.remediation_table.table_name,
            description="DynamoDB table for remediation records"
        )
        
        # Create Lambda for dynamic lifecycle management
        self._create_lifecycle_management_lambda()
    
    def _create_intelligent_lifecycle_rules(self) -> list:
        """Create intelligent S3 lifecycle rules based on data criticality"""
        return [
            # Critical findings - Keep in STANDARD for quick access
            s3.LifecycleRule(
                id="CriticalFindings",
                prefix="raw/",
                tag_filters={
                    "Priority": "critical",
                    "FindingSeverity": "critical"
                },
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(7)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                        transition_after=Duration.days(90)
                    )
                ],
                expiration=Duration.days(730)  # Keep critical findings for 2 years
            ),
            
            # High priority scans - Standard tiering
            s3.LifecycleRule(
                id="HighPriorityScans",
                prefix="raw/",
                tag_filters={
                    "Priority": "high"
                },
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=Duration.days(14)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(30)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                        transition_after=Duration.days(180)
                    )
                ],
                expiration=Duration.days(545)  # Keep for 1.5 years
            ),
            
            # Normal priority scans - Aggressive tiering
            s3.LifecycleRule(
                id="NormalPriorityScans",
                prefix="raw/",
                tag_filters={
                    "Priority": "normal"
                },
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=Duration.days(7)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(30)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                        transition_after=Duration.days(90)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.DEEP_ARCHIVE,
                        transition_after=Duration.days(365)
                    )
                ],
                expiration=Duration.days(1095)  # Keep for 3 years
            ),
            
            # Processed reports - Quick archival
            s3.LifecycleRule(
                id="ProcessedReports",
                prefix="processed/",
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=Duration.days(1)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(7)
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                        transition_after=Duration.days(30)
                    )
                ],
                expiration=Duration.days(365)
            ),
            
            # QuickSight data - Keep accessible
            s3.LifecycleRule(
                id="QuickSightData",
                prefix="quicksight/",
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(30)
                    )
                ],
                expiration=Duration.days(180)  # Keep for 6 months
            ),
            
            # Error logs - Archive quickly
            s3.LifecycleRule(
                id="ErrorLogs",
                prefix="raw/",
                tag_filters={
                    "Type": "error"
                },
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                        transition_after=Duration.days(30)
                    )
                ],
                expiration=Duration.days(90)
            ),
            
            # Clean up incomplete multipart uploads
            s3.LifecycleRule(
                id="CleanupIncompleteUploads",
                abort_incomplete_multipart_upload_after=Duration.days(7)
            ),
            
            # Non-current versions
            s3.LifecycleRule(
                id="NonCurrentVersions",
                noncurrent_version_transitions=[
                    s3.NoncurrentVersionTransition(
                        storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=Duration.days(7)
                    ),
                    s3.NoncurrentVersionTransition(
                        storage_class=s3.StorageClass.GLACIER_INSTANT_RETRIEVAL,
                        transition_after=Duration.days(30)
                    )
                ],
                noncurrent_version_expiration=Duration.days(90)
            )
        ]
    
    def _create_lifecycle_management_lambda(self):
        """Create Lambda function for dynamic lifecycle policy management"""
        
        # Lambda execution role
        lambda_role = iam.Role(
            self, "LifecycleManagementRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )
        
        # Grant S3 permissions
        self.results_bucket.grant_read_write(lambda_role)
        lambda_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "s3:PutObjectTagging",
                "s3:GetObjectTagging",
                "s3:GetBucketTagging",
                "s3:PutBucketTagging"
            ],
            resources=[
                self.results_bucket.bucket_arn,
                f"{self.results_bucket.bucket_arn}/*"
            ]
        ))
        
        # Grant DynamoDB read permissions
        self.scan_table.grant_read_data(lambda_role)
        
        # Create Lambda function
        self.lifecycle_lambda = lambda_.Function(
            self, "LifecycleManagementFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="lifecycle_manager.lambda_handler",
            code=lambda_.Code.from_asset("../src/lambdas/lifecycle_manager"),
            role=lambda_role,
            environment={
                "RESULTS_BUCKET": self.results_bucket.bucket_name,
                "SCAN_TABLE": self.scan_table.table_name
            },
            timeout=Duration.minutes(15),
            memory_size=512,
            description="Manages S3 lifecycle policies based on scan results and priority"
        )
        
        # Add tags
        Tags.of(self.lifecycle_lambda).add("Component", "LifecycleManagement")
        Tags.of(self.lifecycle_lambda).add("Framework", "SecurityAudit")
    
    def _create_ai_tables(self):
        """Create DynamoDB tables for AI-powered features"""
        
        # AI Decisions table for explainability
        self.ai_decisions_table = dynamodb.Table(
            self, "AIDecisionsTable",
            table_name="SecurityAuditAIDecisions",
            partition_key=dynamodb.Attribute(
                name="finding_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Add GSI for finding type queries
        self.ai_decisions_table.add_global_secondary_index(
            index_name="FindingTypeIndex",
            partition_key=dynamodb.Attribute(
                name="finding_type",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Confidence Calibration table
        self.confidence_calibration_table = dynamodb.Table(
            self, "ConfidenceCalibrationTable",
            table_name="SecurityAuditConfidenceCalibration",
            partition_key=dynamodb.Attribute(
                name="model",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="confidence_range_start",
                type=dynamodb.AttributeType.NUMBER
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Tool Comparisons table
        self.tool_comparisons_table = dynamodb.Table(
            self, "ToolComparisonsTable",
            table_name="SecurityAuditToolComparisons",
            partition_key=dynamodb.Attribute(
                name="finding_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="tool_name",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # AI Vulnerability Analysis table
        self.ai_vuln_analysis_table = dynamodb.Table(
            self, "AIVulnAnalysisTable",
            table_name="SecurityAuditAIVulnAnalysis",
            partition_key=dynamodb.Attribute(
                name="package_version",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="analysis_timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Package Risk table
        self.package_risk_table = dynamodb.Table(
            self, "PackageRiskTable",
            table_name="SecurityAuditPackageRisk",
            partition_key=dynamodb.Attribute(
                name="package_name",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Vulnerability Cache table
        self.vuln_cache_table = dynamodb.Table(
            self, "VulnCacheTable",
            table_name="SecurityAuditVulnCache",
            partition_key=dynamodb.Attribute(
                name="cache_key",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Package Health table
        self.package_health_table = dynamodb.Table(
            self, "PackageHealthTable",
            table_name="SecurityAuditPackageHealth",
            partition_key=dynamodb.Attribute(
                name="package_ecosystem",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # AI Policies table
        self.ai_policies_table = dynamodb.Table(
            self, "AIPoliciesTable",
            table_name="SecurityAuditAIPolicies",
            partition_key=dynamodb.Attribute(
                name="policy_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Policy Violations table
        self.policy_violations_table = dynamodb.Table(
            self, "PolicyViolationsTable",
            table_name="SecurityAuditPolicyViolations",
            partition_key=dynamodb.Attribute(
                name="violation_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Add GSI for file path queries
        self.policy_violations_table.add_global_secondary_index(
            index_name="FilePathIndex",
            partition_key=dynamodb.Attribute(
                name="file_path",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="detected_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Flow Analysis table
        self.flow_analysis_table = dynamodb.Table(
            self, "FlowAnalysisTable",
            table_name="SecurityAuditFlowAnalysis",
            partition_key=dynamodb.Attribute(
                name="analysis_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # AI Scans table
        self.ai_scans_table = dynamodb.Table(
            self, "AIScansTable",
            table_name="SecurityAuditAIScans",
            partition_key=dynamodb.Attribute(
                name="scan_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Add GSI for repository queries
        self.ai_scans_table.add_global_secondary_index(
            index_name="RepositoryIndex",
            partition_key=dynamodb.Attribute(
                name="repository",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="started_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # AI Findings table
        self.ai_findings_table = dynamodb.Table(
            self, "AIFindingsTable",
            table_name="SecurityAuditAIFindings",
            partition_key=dynamodb.Attribute(
                name="finding_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Add GSI for scan queries
        self.ai_findings_table.add_global_secondary_index(
            index_name="ScanIndex",
            partition_key=dynamodb.Attribute(
                name="scan_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Add GSI for severity queries
        self.ai_findings_table.add_global_secondary_index(
            index_name="SeverityIndex",
            partition_key=dynamodb.Attribute(
                name="severity",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="business_risk_score",
                type=dynamodb.AttributeType.NUMBER
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # S3 bucket for AI policies
        self.ai_policies_bucket = s3.Bucket(
            self, "AIPoliciesBucket",
            bucket_name=f"security-audit-policies-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="PolicyVersions",
                    noncurrent_version_expiration=Duration.days(30)
                )
            ],
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Output AI table names
        CfnOutput(
            self, "AIDecisionsTableName",
            value=self.ai_decisions_table.table_name,
            description="DynamoDB table for AI decisions and explainability"
        )
        
        CfnOutput(
            self, "AIScansTableName",
            value=self.ai_scans_table.table_name,
            description="DynamoDB table for AI scan metadata"
        )
        
        CfnOutput(
            self, "AIFindingsTableName",
            value=self.ai_findings_table.table_name,
            description="DynamoDB table for AI findings"
        )
        
        CfnOutput(
            self, "AIPoliciesBucketName",
            value=self.ai_policies_bucket.bucket_name,
            description="S3 bucket for AI security policies"
        )