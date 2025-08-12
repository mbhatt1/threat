"""
QuickSight Stack - Configures QuickSight for security dashboard visualization
"""
from aws_cdk import (
    Stack,
    CfnOutput,
    aws_quicksight as quicksight,
    aws_iam as iam,
    aws_s3 as s3,
    aws_athena as athena,
    RemovalPolicy
)
from constructs import Construct
from typing import Dict, Any


class QuickSightStack(Stack):
    """QuickSight configuration for security dashboards"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 results_bucket: s3.Bucket,
                 athena_results_bucket: s3.Bucket,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create QuickSight service role
        self.quicksight_role = iam.Role(
            self, "QuickSightServiceRole",
            assumed_by=iam.ServicePrincipal("quicksight.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSQuicksightAthenaAccess")
            ]
        )
        
        # Grant S3 permissions
        results_bucket.grant_read(self.quicksight_role)
        athena_results_bucket.grant_read_write(self.quicksight_role)
        
        # Add permissions for Athena
        self.quicksight_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "athena:GetWorkGroup",
                "athena:StartQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:StopQueryExecution",
                "athena:GetDataCatalog",
                "athena:GetDatabase",
                "athena:GetTableMetadata",
                "athena:ListDatabases",
                "athena:ListTableMetadata",
                "athena:ListWorkGroups"
            ],
            resources=["*"]
        ))
        
        # Add Glue permissions for data catalog
        self.quicksight_role.add_to_policy(iam.PolicyStatement(
            actions=[
                "glue:GetDatabase",
                "glue:GetDatabases",
                "glue:GetTable",
                "glue:GetTables",
                "glue:GetPartition",
                "glue:GetPartitions",
                "glue:BatchGetPartition"
            ],
            resources=["*"]
        ))
        
        # Create QuickSight group for security analysts
        self.security_analysts_group = quicksight.CfnGroup(
            self, "SecurityAnalystsGroup",
            aws_account_id=self.account,
            group_name="SecurityAnalysts",
            namespace="default",
            description="Group for security analysts to access dashboards"
        )
        
        # Create QuickSight template for security dashboards
        self.dashboard_template = quicksight.CfnTemplate(
            self, "SecurityDashboardTemplate",
            aws_account_id=self.account,
            template_id="security-dashboard-template",
            name="Security Dashboard Template",
            version_description="Template for security scan dashboards",
            source_entity=quicksight.CfnTemplate.TemplateSourceEntityProperty(
                source_analysis=quicksight.CfnTemplate.TemplateSourceAnalysisProperty(
                    arn=f"arn:aws:quicksight:{self.region}:{self.account}:analysis/security-analysis-template",
                    data_set_references=[
                        quicksight.CfnTemplate.DataSetReferenceProperty(
                            data_set_arn=f"arn:aws:quicksight:{self.region}:{self.account}:dataset/findings-template",
                            data_set_placeholder="findings"
                        ),
                        quicksight.CfnTemplate.DataSetReferenceProperty(
                            data_set_arn=f"arn:aws:quicksight:{self.region}:{self.account}:dataset/metrics-template",
                            data_set_placeholder="metrics"
                        )
                    ]
                )
            ),
            permissions=[
                quicksight.CfnTemplate.ResourcePermissionProperty(
                    principal=f"arn:aws:quicksight:{self.region}:{self.account}:group/default/SecurityAnalysts",
                    actions=[
                        "quicksight:DescribeTemplate",
                        "quicksight:DescribeTemplateAlias",
                        "quicksight:ListTemplateVersions",
                        "quicksight:ListTemplateAliases"
                    ]
                )
            ]
        )
        
        # Create Athena workgroup for QuickSight
        self.athena_workgroup = athena.CfnWorkGroup(
            self, "QuickSightAthenaWorkGroup",
            name="quicksight-security-scans",
            description="Athena workgroup for QuickSight security dashboards",
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    output_location=f"s3://{athena_results_bucket.bucket_name}/quicksight-queries/",
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="SSE_S3"
                    )
                ),
                enforce_work_group_configuration=True,
                publish_cloud_watch_metrics_enabled=True,
                bytes_scanned_cutoff_per_query=1000000000,  # 1GB limit per query
                requester_pays_enabled=False
            )
        )
        
        # Create QuickSight data source for Athena
        self.athena_data_source = quicksight.CfnDataSource(
            self, "AthenaDataSource",
            aws_account_id=self.account,
            data_source_id="security-scans-athena-source",
            name="Security Scans Athena Data Source",
            type="ATHENA",
            data_source_parameters=quicksight.CfnDataSource.DataSourceParametersProperty(
                athena_parameters=quicksight.CfnDataSource.AthenaParametersProperty(
                    work_group=self.athena_workgroup.name
                )
            ),
            permissions=[
                quicksight.CfnDataSource.ResourcePermissionProperty(
                    principal=f"arn:aws:quicksight:{self.region}:{self.account}:group/default/SecurityAnalysts",
                    actions=[
                        "quicksight:DescribeDataSource",
                        "quicksight:DescribeDataSourcePermissions",
                        "quicksight:PassDataSource",
                        "quicksight:UpdateDataSource",
                        "quicksight:UpdateDataSourcePermissions"
                    ]
                )
            ],
            ssl_properties=quicksight.CfnDataSource.SslPropertiesProperty(
                disable_ssl=False
            )
        )
        
        # Create sample datasets for template
        self.sample_findings_dataset = quicksight.CfnDataSet(
            self, "SampleFindingsDataSet",
            aws_account_id=self.account,
            data_set_id="findings-template",
            name="Sample Security Findings Dataset",
            import_mode="SPICE",
            physical_table_map={
                "findings-table": quicksight.CfnDataSet.PhysicalTableProperty(
                    custom_sql=quicksight.CfnDataSet.CustomSqlProperty(
                        data_source_arn=self.athena_data_source.attr_arn,
                        name="findings",
                        sql_query="""
                            SELECT 
                                'sample-scan-id' as scan_id,
                                'finding-001' as finding_id,
                                'SQL_INJECTION' as type,
                                'HIGH' as severity,
                                '/app/src/main.py' as file_path,
                                'SQL injection vulnerability detected' as message,
                                'SAST' as agent_type,
                                CURRENT_TIMESTAMP as timestamp
                        """,
                        columns=[
                            {"name": "scan_id", "type": "STRING"},
                            {"name": "finding_id", "type": "STRING"},
                            {"name": "type", "type": "STRING"},
                            {"name": "severity", "type": "STRING"},
                            {"name": "file_path", "type": "STRING"},
                            {"name": "message", "type": "STRING"},
                            {"name": "agent_type", "type": "STRING"},
                            {"name": "timestamp", "type": "DATETIME"}
                        ]
                    )
                )
            },
            permissions=[
                quicksight.CfnDataSet.ResourcePermissionProperty(
                    principal=f"arn:aws:quicksight:{self.region}:{self.account}:group/default/SecurityAnalysts",
                    actions=[
                        "quicksight:DescribeDataSet",
                        "quicksight:DescribeDataSetPermissions",
                        "quicksight:PassDataSet",
                        "quicksight:DescribeIngestion",
                        "quicksight:ListIngestions"
                    ]
                )
            ]
        )
        
        # Output QuickSight configuration
        CfnOutput(
            self, "QuickSightDataSourceId",
            value=self.athena_data_source.data_source_id,
            description="QuickSight Athena data source ID"
        )
        
        CfnOutput(
            self, "QuickSightServiceRoleArn",
            value=self.quicksight_role.role_arn,
            description="QuickSight service role ARN"
        )
        
        CfnOutput(
            self, "QuickSightSecurityGroupArn",
            value=f"arn:aws:quicksight:{self.region}:{self.account}:group/default/SecurityAnalysts",
            description="QuickSight security analysts group ARN"
        )
        
        CfnOutput(
            self, "AthenaWorkgroupName",
            value=self.athena_workgroup.name,
            description="Athena workgroup for QuickSight"
        )
        
        # Create dashboard configuration parameter
        self.dashboard_config = {
            "data_source_id": self.athena_data_source.data_source_id,
            "workgroup_name": self.athena_workgroup.name,
            "template_id": self.dashboard_template.template_id,
            "security_group_arn": f"arn:aws:quicksight:{self.region}:{self.account}:group/default/SecurityAnalysts"
        }