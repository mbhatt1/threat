"""
Athena Stack - Sets up AWS Athena for querying security scan results
"""
from aws_cdk import (
    Stack,
    CfnOutput,
    Duration,
    CustomResource,
    aws_athena as athena,
    aws_glue as glue,
    aws_s3 as s3,
    aws_iam as iam,
    aws_lambda as lambda_,
    custom_resources as cr,
    RemovalPolicy
)
from constructs import Construct
from typing import Dict, Any


class AthenaStack(Stack):
    """Athena configuration for security scan analysis"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 results_bucket: s3.Bucket,
                 athena_results_bucket: s3.Bucket,
                 athena_setup_lambda: lambda_.Function,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.database_name = "security_audit_findings"
        
        # Create Glue database for Athena
        self.glue_database = glue.CfnDatabase(
            self, "SecurityAuditDatabase",
            catalog_id=self.account,
            database_input=glue.CfnDatabase.DatabaseInputProperty(
                name=self.database_name,
                description="Database for security audit findings and scan results",
                location_uri=f"s3://{results_bucket.bucket_name}/"
            )
        )
        
        # Create Athena workgroup
        self.athena_workgroup = athena.CfnWorkGroup(
            self, "SecurityAuditWorkGroup",
            name="security-audit-workgroup",
            description="Athena workgroup for security scan analysis",
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=f"s3://{athena_results_bucket.bucket_name}/athena-results/",
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_S3"
                    )
                ),
                enforce_work_group_configuration=True,
                publish_cloud_watch_metrics_enabled=True,
                bytes_scanned_cutoff_per_query=10737418240,  # 10GB limit
                requester_pays_enabled=False,
                engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                    selected_engine_version="AUTO"
                )
            ),
            tags=[
                {
                    "key": "Project",
                    "value": "SecurityAudit"
                },
                {
                    "key": "ManagedBy",
                    "value": "CDK"
                }
            ]
        )
        
        # Create data catalog for Athena
        self.data_catalog = athena.CfnDataCatalog(
            self, "SecurityAuditDataCatalog",
            name="security-audit-catalog",
            type="GLUE",
            description="Data catalog for security audit findings",
            parameters={
                "catalog-id": self.account
            }
        )
        
        # Grant permissions to Athena setup Lambda
        results_bucket.grant_read(athena_setup_lambda)
        athena_results_bucket.grant_read_write(athena_setup_lambda)
        
        # Add Athena and Glue permissions to Lambda
        athena_setup_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=[
                "athena:StartQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:StopQueryExecution",
                "athena:GetWorkGroup",
                "athena:GetDataCatalog",
                "athena:GetDatabase",
                "athena:GetTableMetadata",
                "athena:ListDatabases",
                "athena:ListTableMetadata"
            ],
            resources=["*"]
        ))
        
        athena_setup_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=[
                "glue:CreateDatabase",
                "glue:GetDatabase",
                "glue:GetDatabases",
                "glue:CreateTable",
                "glue:GetTable",
                "glue:GetTables",
                "glue:UpdateTable",
                "glue:DeleteTable",
                "glue:BatchCreatePartition",
                "glue:BatchDeletePartition",
                "glue:GetPartition",
                "glue:GetPartitions",
                "glue:CreatePartition",
                "glue:DeletePartition",
                "glue:UpdatePartition"
            ],
            resources=[
                f"arn:aws:glue:{self.region}:{self.account}:catalog",
                f"arn:aws:glue:{self.region}:{self.account}:database/{self.database_name}",
                f"arn:aws:glue:{self.region}:{self.account}:table/{self.database_name}/*"
            ]
        ))
        
        # Create custom resource to setup Athena tables
        provider = cr.Provider(
            self, "AthenaSetupProvider",
            on_event_handler=athena_setup_lambda,
            log_retention=cr.AwsCustomResourcePolicy.ANY_RESOURCE
        )
        
        setup_resource = CustomResource(
            self, "AthenaTableSetup",
            service_token=provider.service_token,
            properties={
                "action": "setup_all",
                "database_name": self.database_name,
                "results_bucket": results_bucket.bucket_name,
                "athena_results_location": f"s3://{athena_results_bucket.bucket_name}/athena-results/",
                "workgroup": self.athena_workgroup.name
            }
        )
        
        # Ensure database is created before running setup
        setup_resource.node.add_dependency(self.glue_database)
        setup_resource.node.add_dependency(self.athena_workgroup)
        
        # Create named queries for common analysis
        self.create_named_queries()
        
        # Outputs
        CfnOutput(
            self, "AthenaDatabaseName",
            value=self.database_name,
            description="Athena database name for security findings"
        )
        
        CfnOutput(
            self, "AthenaWorkgroupName",
            value=self.athena_workgroup.name,
            description="Athena workgroup name"
        )
        
        CfnOutput(
            self, "AthenaResultsLocation",
            value=f"s3://{athena_results_bucket.bucket_name}/athena-results/",
            description="S3 location for Athena query results"
        )
    
    def create_named_queries(self):
        """Create named queries for common analysis tasks"""
        
        # Query 1: Daily security summary
        athena.CfnNamedQuery(
            self, "DailySecuritySummary",
            name="Daily Security Summary",
            description="Get daily summary of security findings",
            database=self.database_name,
            query_string=f"""
                SELECT 
                    scan_date,
                    COUNT(DISTINCT scan_id) as total_scans,
                    COUNT(*) as total_findings,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_findings,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_findings,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_findings,
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low_findings,
                    COLLECT_SET(agent_type) as active_agents
                FROM {self.database_name}.security_findings
                WHERE scan_date = CAST(CURRENT_DATE AS VARCHAR)
                GROUP BY scan_date
            """,
            work_group=self.athena_workgroup.name
        )
        
        # Query 2: Top security risks
        athena.CfnNamedQuery(
            self, "TopSecurityRisks",
            name="Top Security Risks",
            description="Identify top security risks by severity and frequency",
            database=self.database_name,
            query_string=f"""
                SELECT 
                    type as vulnerability_type,
                    severity,
                    COUNT(*) as occurrence_count,
                    COUNT(DISTINCT file_path) as affected_files,
                    COUNT(DISTINCT repository) as affected_repositories,
                    ARBITRARY(message) as example_message,
                    COLLECT_SET(cwe_id) FILTER (WHERE cwe_id IS NOT NULL) as related_cwes
                FROM {self.database_name}.security_findings
                WHERE scan_date >= DATE_ADD('day', -7, CURRENT_DATE)
                  AND severity IN ('CRITICAL', 'HIGH')
                GROUP BY type, severity
                ORDER BY 
                    CASE severity 
                        WHEN 'CRITICAL' THEN 1 
                        WHEN 'HIGH' THEN 2 
                        ELSE 3 
                    END,
                    occurrence_count DESC
                LIMIT 20
            """,
            work_group=self.athena_workgroup.name
        )
        
        # Query 3: Security trends over time
        athena.CfnNamedQuery(
            self, "SecurityTrends",
            name="Security Trends Analysis",
            description="Analyze security trends over the past 30 days",
            database=self.database_name,
            query_string=f"""
                WITH daily_stats AS (
                    SELECT 
                        scan_date,
                        COUNT(DISTINCT scan_id) as scan_count,
                        COUNT(*) as finding_count,
                        SUM(CASE WHEN severity IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as high_severity_count
                    FROM {self.database_name}.security_findings
                    WHERE scan_date >= DATE_ADD('day', -30, CURRENT_DATE)
                    GROUP BY scan_date
                )
                SELECT 
                    scan_date,
                    scan_count,
                    finding_count,
                    high_severity_count,
                    AVG(finding_count) OVER (ORDER BY scan_date ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) as moving_avg_findings,
                    finding_count - LAG(finding_count, 1) OVER (ORDER BY scan_date) as daily_change
                FROM daily_stats
                ORDER BY scan_date DESC
            """,
            work_group=self.athena_workgroup.name
        )
        
        # Query 4: Agent performance metrics
        athena.CfnNamedQuery(
            self, "AgentPerformanceMetrics",
            name="Security Agent Performance",
            description="Analyze performance metrics for security agents",
            database=self.database_name,
            query_string=f"""
                SELECT 
                    s.scan_date,
                    ar.agent_type,
                    COUNT(DISTINCT s.scan_id) as scans_executed,
                    AVG(ar.execution_time) as avg_execution_time_seconds,
                    AVG(ar.cost) as avg_cost_usd,
                    SUM(ar.findings_count) as total_findings,
                    AVG(ar.findings_count) as avg_findings_per_scan,
                    SUM(ar.cost) as total_cost_usd
                FROM {self.database_name}.aggregated_findings s
                CROSS JOIN UNNEST(agent_results) AS t(ar)
                WHERE s.scan_date >= DATE_ADD('day', -7, CURRENT_DATE)
                  AND ar.status = 'COMPLETED'
                GROUP BY s.scan_date, ar.agent_type
                ORDER BY s.scan_date DESC, total_findings DESC
            """,
            work_group=self.athena_workgroup.name
        )
        
        # Query 5: Remediation priorities
        athena.CfnNamedQuery(
            self, "RemediationPriorities",
            name="Remediation Priority List",
            description="Generate prioritized list of vulnerabilities for remediation",
            database=self.database_name,
            query_string=f"""
                WITH vulnerability_impact AS (
                    SELECT 
                        type,
                        severity,
                        file_path,
                        COUNT(*) as occurrence_count,
                        MAX(confidence) as max_confidence,
                        ARBITRARY(remediation_suggestion) as remediation,
                        COLLECT_SET(scan_id) as affected_scans
                    FROM {self.database_name}.security_findings
                    WHERE scan_date >= DATE_ADD('day', -7, CURRENT_DATE)
                    GROUP BY type, severity, file_path
                )
                SELECT 
                    type as vulnerability_type,
                    severity,
                    file_path,
                    occurrence_count,
                    max_confidence,
                    remediation,
                    CARDINALITY(affected_scans) as scan_count,
                    CASE 
                        WHEN severity = 'CRITICAL' THEN occurrence_count * 1000
                        WHEN severity = 'HIGH' THEN occurrence_count * 100
                        WHEN severity = 'MEDIUM' THEN occurrence_count * 10
                        ELSE occurrence_count
                    END as priority_score
                FROM vulnerability_impact
                WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                ORDER BY priority_score DESC
                LIMIT 50
            """,
            work_group=self.athena_workgroup.name
        )