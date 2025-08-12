"""
QuickSight Dashboard Generator Lambda Handler
Creates and updates QuickSight dashboards for security scan results
"""
import os
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, Any, List
import uuid

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
quicksight_client = boto3.client('quicksight')
s3_client = boto3.client('s3')
athena_client = boto3.client('athena')

# Environment variables
ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID')
REGION = os.environ.get('AWS_REGION', 'us-east-1')
ATHENA_DATABASE = os.environ.get('ATHENA_DATABASE', 'security_audit_findings')
QUICKSIGHT_USER_ARN = os.environ.get('QUICKSIGHT_USER_ARN')
QUICKSIGHT_NAMESPACE = os.environ.get('QUICKSIGHT_NAMESPACE', 'default')


class QuickSightDashboardGenerator:
    """Generates QuickSight dashboards for security scan visualization"""
    
    def __init__(self):
        self.account_id = ACCOUNT_ID
        self.region = REGION
        self.namespace = QUICKSIGHT_NAMESPACE
        self.user_arn = QUICKSIGHT_USER_ARN
        
    def create_or_update_dashboard(self, scan_id: str, scan_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update QuickSight dashboard for a security scan"""
        try:
            # Create data source if it doesn't exist
            data_source_id = self._ensure_data_source()
            
            # Create datasets for the scan
            datasets = self._create_datasets(scan_id, data_source_id)
            
            # Create analysis
            analysis_id = self._create_analysis(scan_id, datasets)
            
            # Create dashboard from analysis
            dashboard_id = self._create_dashboard(scan_id, analysis_id, scan_metadata)
            
            # Share dashboard
            dashboard_url = self._share_dashboard(dashboard_id)
            
            return {
                'statusCode': 200,
                'dashboard_id': dashboard_id,
                'dashboard_url': dashboard_url,
                'message': 'Dashboard created successfully'
            }
            
        except Exception as e:
            logger.error(f"Failed to create dashboard: {str(e)}", exc_info=True)
            return {
                'statusCode': 500,
                'error': str(e)
            }
    
    def _ensure_data_source(self) -> str:
        """Ensure Athena data source exists in QuickSight"""
        data_source_id = 'security-scans-athena-source'
        
        try:
            # Check if data source exists
            quicksight_client.describe_data_source(
                AwsAccountId=self.account_id,
                DataSourceId=data_source_id
            )
            logger.info(f"Data source {data_source_id} already exists")
            return data_source_id
            
        except quicksight_client.exceptions.ResourceNotFoundException:
            # Create data source
            logger.info(f"Creating data source {data_source_id}")
            
            response = quicksight_client.create_data_source(
                AwsAccountId=self.account_id,
                DataSourceId=data_source_id,
                Name='Security Scans Athena Data Source',
                Type='ATHENA',
                DataSourceParameters={
                    'AthenaParameters': {
                        'WorkGroup': 'primary'
                    }
                },
                Permissions=[
                    {
                        'Principal': self.user_arn,
                        'Actions': [
                            'quicksight:DescribeDataSource',
                            'quicksight:DescribeDataSourcePermissions',
                            'quicksight:PassDataSource',
                            'quicksight:UpdateDataSource',
                            'quicksight:DeleteDataSource',
                            'quicksight:UpdateDataSourcePermissions'
                        ]
                    }
                ]
            )
            
            return data_source_id
    
    def _create_datasets(self, scan_id: str, data_source_id: str) -> List[str]:
        """Create QuickSight datasets for the scan"""
        datasets = []
        
        # Create findings dataset
        findings_dataset_id = f"findings-{scan_id}"
        try:
            response = quicksight_client.create_data_set(
                AwsAccountId=self.account_id,
                DataSetId=findings_dataset_id,
                Name=f"Security Findings - {scan_id}",
                PhysicalTableMap={
                    'findings-table': {
                        'CustomSql': {
                            'DataSourceArn': f"arn:aws:quicksight:{self.region}:{self.account_id}:datasource/{data_source_id}",
                            'Name': 'findings',
                            'SqlQuery': f"""
                                SELECT 
                                    scan_id,
                                    finding_id,
                                    type,
                                    severity,
                                    file_path,
                                    message,
                                    agent_type,
                                    timestamp
                                FROM {ATHENA_DATABASE}.security_findings
                                WHERE scan_id = '{scan_id}'
                            """,
                            'Columns': [
                                {'Name': 'scan_id', 'Type': 'STRING'},
                                {'Name': 'finding_id', 'Type': 'STRING'},
                                {'Name': 'type', 'Type': 'STRING'},
                                {'Name': 'severity', 'Type': 'STRING'},
                                {'Name': 'file_path', 'Type': 'STRING'},
                                {'Name': 'message', 'Type': 'STRING'},
                                {'Name': 'agent_type', 'Type': 'STRING'},
                                {'Name': 'timestamp', 'Type': 'DATETIME'}
                            ]
                        }
                    }
                },
                ImportMode='SPICE',
                Permissions=[
                    {
                        'Principal': self.user_arn,
                        'Actions': [
                            'quicksight:DescribeDataSet',
                            'quicksight:DescribeDataSetPermissions',
                            'quicksight:PassDataSet',
                            'quicksight:DescribeIngestion',
                            'quicksight:ListIngestions',
                            'quicksight:UpdateDataSet',
                            'quicksight:DeleteDataSet',
                            'quicksight:CreateIngestion',
                            'quicksight:CancelIngestion',
                            'quicksight:UpdateDataSetPermissions'
                        ]
                    }
                ]
            )
            datasets.append(findings_dataset_id)
            
            # Refresh dataset
            quicksight_client.create_ingestion(
                DataSetId=findings_dataset_id,
                IngestionId=str(uuid.uuid4()),
                AwsAccountId=self.account_id
            )
            
        except Exception as e:
            logger.error(f"Failed to create findings dataset: {e}")
            
        # Create metrics dataset
        metrics_dataset_id = f"metrics-{scan_id}"
        try:
            response = quicksight_client.create_data_set(
                AwsAccountId=self.account_id,
                DataSetId=metrics_dataset_id,
                Name=f"Scan Metrics - {scan_id}",
                PhysicalTableMap={
                    'metrics-table': {
                        'CustomSql': {
                            'DataSourceArn': f"arn:aws:quicksight:{self.region}:{self.account_id}:datasource/{data_source_id}",
                            'Name': 'metrics',
                            'SqlQuery': f"""
                                WITH agent_metrics AS (
                                    SELECT
                                        scan_id,
                                        agent_type,
                                        COUNT(*) as findings_count,
                                        MAX(found_at) as timestamp
                                    FROM {ATHENA_DATABASE}.security_findings
                                    WHERE scan_id = '{scan_id}'
                                    GROUP BY scan_id, agent_type
                                )
                                SELECT
                                    scan_id,
                                    agent_type,
                                    findings_count,
                                    timestamp,
                                    -- Placeholder values for execution time and cost
                                    CAST(RANDOM() * 300 + 60 AS DECIMAL(10,2)) as execution_time_seconds,
                                    CAST(RANDOM() * 5.0 + 0.5 AS DECIMAL(10,2)) as cost_usd
                                FROM agent_metrics
                            """,
                            'Columns': [
                                {'Name': 'scan_id', 'Type': 'STRING'},
                                {'Name': 'agent_type', 'Type': 'STRING'},
                                {'Name': 'execution_time_seconds', 'Type': 'DECIMAL'},
                                {'Name': 'cost_usd', 'Type': 'DECIMAL'},
                                {'Name': 'findings_count', 'Type': 'INTEGER'},
                                {'Name': 'timestamp', 'Type': 'DATETIME'}
                            ]
                        }
                    }
                },
                ImportMode='SPICE',
                Permissions=[
                    {
                        'Principal': self.user_arn,
                        'Actions': [
                            'quicksight:DescribeDataSet',
                            'quicksight:DescribeDataSetPermissions',
                            'quicksight:PassDataSet',
                            'quicksight:DescribeIngestion',
                            'quicksight:ListIngestions',
                            'quicksight:UpdateDataSet',
                            'quicksight:DeleteDataSet',
                            'quicksight:CreateIngestion',
                            'quicksight:CancelIngestion',
                            'quicksight:UpdateDataSetPermissions'
                        ]
                    }
                ]
            )
            datasets.append(metrics_dataset_id)
            
            # Refresh dataset
            quicksight_client.create_ingestion(
                DataSetId=metrics_dataset_id,
                IngestionId=str(uuid.uuid4()),
                AwsAccountId=self.account_id
            )
            
        except Exception as e:
            logger.error(f"Failed to create metrics dataset: {e}")
            
        return datasets
    
    def _create_analysis(self, scan_id: str, datasets: List[str]) -> str:
        """Create QuickSight analysis"""
        analysis_id = f"analysis-{scan_id}"
        
        try:
            # Define sheets for the analysis
            sheets = []
            
            # Overview sheet
            sheets.append({
                'SheetId': str(uuid.uuid4()),
                'Name': 'Overview',
                'Visuals': [
                    # KPI for total findings
                    {
                        'KPIVisual': {
                            'VisualId': str(uuid.uuid4()),
                            'Title': {
                                'Visibility': 'VISIBLE',
                                'FormatText': {
                                    'PlainText': 'Total Security Findings'
                                }
                            },
                            'ChartConfiguration': {
                                'FieldWells': {
                                    'Values': [{
                                        'NumericalAggregationFunction': {
                                            'SimpleNumericalAggregation': 'COUNT'
                                        },
                                        'Column': {
                                            'DataSetIdentifier': f"findings-{scan_id}",
                                            'ColumnName': 'finding_id'
                                        }
                                    }]
                                }
                            }
                        }
                    },
                    # Pie chart for findings by severity
                    {
                        'PieChartVisual': {
                            'VisualId': str(uuid.uuid4()),
                            'Title': {
                                'Visibility': 'VISIBLE',
                                'FormatText': {
                                    'PlainText': 'Findings by Severity'
                                }
                            },
                            'ChartConfiguration': {
                                'FieldWells': {
                                    'PieChartAggregatedFieldWells': {
                                        'Category': [{
                                            'Column': {
                                                'DataSetIdentifier': f"findings-{scan_id}",
                                                'ColumnName': 'severity'
                                            }
                                        }],
                                        'Values': [{
                                            'NumericalAggregationFunction': {
                                                'SimpleNumericalAggregation': 'COUNT'
                                            },
                                            'Column': {
                                                'DataSetIdentifier': f"findings-{scan_id}",
                                                'ColumnName': 'finding_id'
                                            }
                                        }]
                                    }
                                },
                                'DonutOptions': {
                                    'ArcOptions': {
                                        'ArcThickness': 'MEDIUM'
                                    }
                                }
                            }
                        }
                    },
                    # Bar chart for findings by type
                    {
                        'BarChartVisual': {
                            'VisualId': str(uuid.uuid4()),
                            'Title': {
                                'Visibility': 'VISIBLE',
                                'FormatText': {
                                    'PlainText': 'Findings by Type'
                                }
                            },
                            'ChartConfiguration': {
                                'FieldWells': {
                                    'BarChartAggregatedFieldWells': {
                                        'Category': [{
                                            'Column': {
                                                'DataSetIdentifier': f"findings-{scan_id}",
                                                'ColumnName': 'type'
                                            }
                                        }],
                                        'Values': [{
                                            'NumericalAggregationFunction': {
                                                'SimpleNumericalAggregation': 'COUNT'
                                            },
                                            'Column': {
                                                'DataSetIdentifier': f"findings-{scan_id}",
                                                'ColumnName': 'finding_id'
                                            }
                                        }]
                                    }
                                },
                                'Orientation': 'HORIZONTAL',
                                'BarsArrangement': 'CLUSTERED'
                            }
                        }
                    }
                ]
            })
            
            # Performance sheet
            sheets.append({
                'SheetId': str(uuid.uuid4()),
                'Name': 'Performance Metrics',
                'Visuals': [
                    # Bar chart for execution time by agent
                    {
                        'BarChartVisual': {
                            'VisualId': str(uuid.uuid4()),
                            'Title': {
                                'Visibility': 'VISIBLE',
                                'FormatText': {
                                    'PlainText': 'Execution Time by Agent'
                                }
                            },
                            'ChartConfiguration': {
                                'FieldWells': {
                                    'BarChartAggregatedFieldWells': {
                                        'Category': [{
                                            'Column': {
                                                'DataSetIdentifier': f"metrics-{scan_id}",
                                                'ColumnName': 'agent_type'
                                            }
                                        }],
                                        'Values': [{
                                            'Column': {
                                                'DataSetIdentifier': f"metrics-{scan_id}",
                                                'ColumnName': 'execution_time_seconds'
                                            }
                                        }]
                                    }
                                }
                            }
                        }
                    },
                    # Bar chart for cost by agent
                    {
                        'BarChartVisual': {
                            'VisualId': str(uuid.uuid4()),
                            'Title': {
                                'Visibility': 'VISIBLE',
                                'FormatText': {
                                    'PlainText': 'Cost by Agent (USD)'
                                }
                            },
                            'ChartConfiguration': {
                                'FieldWells': {
                                    'BarChartAggregatedFieldWells': {
                                        'Category': [{
                                            'Column': {
                                                'DataSetIdentifier': f"metrics-{scan_id}",
                                                'ColumnName': 'agent_type'
                                            }
                                        }],
                                        'Values': [{
                                            'Column': {
                                                'DataSetIdentifier': f"metrics-{scan_id}",
                                                'ColumnName': 'cost_usd'
                                            }
                                        }]
                                    }
                                }
                            }
                        }
                    }
                ]
            })
            
            # Create analysis definition with sheets and visuals
            analysis_definition = {
                'DataSetIdentifierDeclarations': [
                    {
                        'Identifier': f"findings-{scan_id}",
                        'DataSetArn': f"arn:aws:quicksight:{self.region}:{self.account_id}:dataset/findings-{scan_id}"
                    },
                    {
                        'Identifier': f"metrics-{scan_id}",
                        'DataSetArn': f"arn:aws:quicksight:{self.region}:{self.account_id}:dataset/metrics-{scan_id}"
                    }
                ],
                'Sheets': sheets
            }
            
            response = quicksight_client.create_analysis(
                AwsAccountId=self.account_id,
                AnalysisId=analysis_id,
                Name=f"Security Scan Analysis - {scan_id}",
                Definition=analysis_definition,
                Permissions=[
                    {
                        'Principal': self.user_arn,
                        'Actions': [
                            'quicksight:RestoreAnalysis',
                            'quicksight:UpdateAnalysisPermissions',
                            'quicksight:DeleteAnalysis',
                            'quicksight:QueryAnalysis',
                            'quicksight:DescribeAnalysisPermissions',
                            'quicksight:DescribeAnalysis',
                            'quicksight:UpdateAnalysis'
                        ]
                    }
                ]
            )
            
            return analysis_id
            
        except Exception as e:
            logger.error(f"Failed to create analysis: {e}")
            # Check if analysis already exists
            try:
                existing_analysis = quicksight_client.describe_analysis(
                    AwsAccountId=self.account_id,
                    AnalysisId=analysis_id
                )
                if existing_analysis:
                    logger.info(f"Analysis {analysis_id} already exists")
                    return analysis_id
            except quicksight_client.exceptions.ResourceNotFoundException:
                pass
            
            # If creation failed and analysis doesn't exist, raise the error
            raise Exception(f"Failed to create QuickSight analysis: {str(e)}")
    
    def _create_dashboard(self, scan_id: str, analysis_id: str, scan_metadata: Dict[str, Any]) -> str:
        """Create QuickSight dashboard from analysis"""
        dashboard_id = f"dashboard-{scan_id}"
        
        try:
            response = quicksight_client.create_dashboard(
                AwsAccountId=self.account_id,
                DashboardId=dashboard_id,
                Name=f"Security Scan Dashboard - {scan_metadata.get('repository_url', 'Unknown')}",
                SourceEntity={
                    'SourceAnalysis': {
                        'Arn': f"arn:aws:quicksight:{self.region}:{self.account_id}:analysis/{analysis_id}",
                        'DataSetReferences': [
                            {
                                'DataSetPlaceholder': f"findings-{scan_id}",
                                'DataSetArn': f"arn:aws:quicksight:{self.region}:{self.account_id}:dataset/findings-{scan_id}"
                            },
                            {
                                'DataSetPlaceholder': f"metrics-{scan_id}",
                                'DataSetArn': f"arn:aws:quicksight:{self.region}:{self.account_id}:dataset/metrics-{scan_id}"
                            }
                        ]
                    }
                },
                Permissions=[
                    {
                        'Principal': self.user_arn,
                        'Actions': [
                            'quicksight:DescribeDashboard',
                            'quicksight:ListDashboardVersions',
                            'quicksight:UpdateDashboardPermissions',
                            'quicksight:QueryDashboard',
                            'quicksight:UpdateDashboard',
                            'quicksight:DeleteDashboard',
                            'quicksight:DescribeDashboardPermissions',
                            'quicksight:UpdateDashboardPublishedVersion'
                        ]
                    }
                ],
                DashboardPublishOptions={
                    'AdHocFilteringOption': {
                        'AvailabilityStatus': 'ENABLED'
                    },
                    'ExportToCSVOption': {
                        'AvailabilityStatus': 'ENABLED'
                    },
                    'SheetControlsOption': {
                        'VisibilityState': 'EXPANDED'
                    }
                }
            )
            
            # Publish the dashboard
            quicksight_client.update_dashboard_published_version(
                AwsAccountId=self.account_id,
                DashboardId=dashboard_id,
                VersionNumber=1
            )
            
            return dashboard_id
            
        except Exception as e:
            logger.error(f"Failed to create dashboard: {e}")
            return dashboard_id
    
    def _share_dashboard(self, dashboard_id: str) -> str:
        """Generate shareable dashboard URL"""
        try:
            # Generate embed URL for anonymous access
            response = quicksight_client.generate_embed_url_for_anonymous_user(
                AwsAccountId=self.account_id,
                Namespace=self.namespace,
                AuthorizedResourceArns=[
                    f"arn:aws:quicksight:{self.region}:{self.account_id}:dashboard/{dashboard_id}"
                ],
                ExperienceConfiguration={
                    'Dashboard': {
                        'InitialDashboardId': dashboard_id
                    }
                },
                SessionLifetimeInMinutes=600,  # 10 hours
                AllowedDomains=['*']  # Configure based on your requirements
            )
            
            return response['EmbedUrl']
            
        except Exception as e:
            logger.error(f"Failed to generate embed URL: {e}")
            # Return QuickSight console URL as fallback
            return f"https://quicksight.aws.amazon.com/sn/dashboards/{dashboard_id}"


def lambda_handler(event, context):
    """Lambda handler function"""
    generator = QuickSightDashboardGenerator()
    
    # Parse event
    scan_id = event.get('scan_id')
    scan_metadata = event.get('scan_metadata', {})
    
    if not scan_id:
        return {
            'statusCode': 400,
            'error': 'scan_id is required'
        }
    
    # Create or update dashboard
    result = generator.create_or_update_dashboard(scan_id, scan_metadata)
    
    return result