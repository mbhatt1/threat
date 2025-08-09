"""
AWS Athena Setup Lambda Handler
Creates and manages Athena tables for querying security findings
"""
import os
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, Any, List

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
athena_client = boto3.client('athena')
glue_client = boto3.client('glue')
s3_client = boto3.client('s3')


class AthenaSetupHandler:
    """Sets up Athena tables and views for security findings analysis"""
    
    def __init__(self):
        self.database_name = os.environ.get('ATHENA_DATABASE', 'security_audit_findings')
        self.results_bucket = os.environ.get('RESULTS_BUCKET', 'security-scan-results')
        self.athena_results_location = f"s3://{self.results_bucket}/athena-results/"
        self.region = os.environ.get('AWS_REGION', 'us-east-1')
    
    def handle_request(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main handler for Athena setup"""
        try:
            action = event.get('action', 'setup_all')
            
            if action == 'setup_all':
                return self._setup_all_tables()
            elif action == 'create_database':
                return self._create_database()
            elif action == 'create_findings_table':
                return self._create_findings_table()
            elif action == 'create_scans_table':
                return self._create_scans_table()
            elif action == 'create_views':
                return self._create_analysis_views()
            elif action == 'repair_partitions':
                return self._repair_table_partitions()
            else:
                raise ValueError(f"Unknown action: {action}")
                
        except Exception as e:
            logger.error(f"Athena setup failed: {str(e)}", exc_info=True)
            return {
                'statusCode': 500,
                'error': str(e)
            }
    
    def _setup_all_tables(self) -> Dict[str, Any]:
        """Setup all Athena tables and views"""
        results = {}
        
        # Create database
        results['database'] = self._create_database()
        
        # Create tables
        results['findings_table'] = self._create_findings_table()
        results['scans_table'] = self._create_scans_table()
        results['aggregated_findings_table'] = self._create_aggregated_findings_table()
        
        # Create views
        results['views'] = self._create_analysis_views()
        
        # Repair partitions
        results['partitions'] = self._repair_table_partitions()
        
        return {
            'statusCode': 200,
            'message': 'Athena setup completed successfully',
            'results': results
        }
    
    def _create_database(self) -> Dict[str, Any]:
        """Create Athena database if it doesn't exist"""
        try:
            create_db_query = f"""
            CREATE DATABASE IF NOT EXISTS {self.database_name}
            COMMENT 'Database for security audit findings'
            LOCATION 's3://{self.results_bucket}/'
            """
            
            query_id = self._execute_athena_query(create_db_query)
            
            return {
                'status': 'success',
                'database': self.database_name,
                'query_id': query_id
            }
            
        except Exception as e:
            logger.error(f"Failed to create database: {e}")
            raise
    
    def _create_findings_table(self) -> Dict[str, Any]:
        """Create table for individual security findings"""
        try:
            create_table_query = f"""
            CREATE EXTERNAL TABLE IF NOT EXISTS {self.database_name}.security_findings (
                finding_id STRING,
                scan_id STRING,
                type STRING,
                severity STRING,
                confidence STRING,
                message STRING,
                file_path STRING,
                start_line INT,
                end_line INT,
                code_snippet STRING,
                remediation_suggestion STRING,
                cve_id STRING,
                cwe_id STRING,
                owasp_category STRING,
                dependency_name STRING,
                dependency_version STRING,
                agent_type STRING,
                found_at TIMESTAMP
            )
            PARTITIONED BY (
                scan_date STRING,
                repository STRING
            )
            STORED AS JSON
            LOCATION 's3://{self.results_bucket}/raw/'
            TBLPROPERTIES (
                'projection.enabled' = 'true',
                'projection.scan_date.type' = 'date',
                'projection.scan_date.range' = '2024-01-01,NOW',
                'projection.scan_date.format' = 'yyyy-MM-dd',
                'projection.repository.type' = 'enum',
                'projection.repository.values' = 'default',
                'storage.location.template' = 's3://{self.results_bucket}/raw/${{scan_date}}/${{repository}}'
            )
            """
            
            query_id = self._execute_athena_query(create_table_query)
            
            return {
                'status': 'success',
                'table': 'security_findings',
                'query_id': query_id
            }
            
        except Exception as e:
            logger.error(f"Failed to create findings table: {e}")
            raise
    
    def _create_scans_table(self) -> Dict[str, Any]:
        """Create table for scan metadata"""
        try:
            create_table_query = f"""
            CREATE EXTERNAL TABLE IF NOT EXISTS {self.database_name}.security_scans (
                scan_id STRING,
                repository_url STRING,
                branch STRING,
                commit_hash STRING,
                scan_type STRING,
                priority STRING,
                status STRING,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                total_findings INT,
                critical_findings INT,
                high_findings INT,
                medium_findings INT,
                low_findings INT,
                info_findings INT,
                total_cost_usd DOUBLE,
                agents_executed ARRAY<STRING>,
                execution_time_seconds INT
            )
            PARTITIONED BY (
                scan_date STRING
            )
            STORED AS JSON
            LOCATION 's3://{self.results_bucket}/scans/'
            TBLPROPERTIES (
                'projection.enabled' = 'true',
                'projection.scan_date.type' = 'date',
                'projection.scan_date.range' = '2024-01-01,NOW',
                'projection.scan_date.format' = 'yyyy-MM-dd'
            )
            """
            
            query_id = self._execute_athena_query(create_table_query)
            
            return {
                'status': 'success',
                'table': 'security_scans',
                'query_id': query_id
            }
            
        except Exception as e:
            logger.error(f"Failed to create scans table: {e}")
            raise
    
    def _create_aggregated_findings_table(self) -> Dict[str, Any]:
        """Create table for aggregated findings"""
        try:
            create_table_query = f"""
            CREATE EXTERNAL TABLE IF NOT EXISTS {self.database_name}.aggregated_findings (
                scan_id STRING,
                repository_url STRING,
                commit_hash STRING,
                scan_timestamp TIMESTAMP,
                findings ARRAY<
                    STRUCT<
                        finding_id: STRING,
                        type: STRING,
                        severity: STRING,
                        confidence: STRING,
                        message: STRING,
                        file_path: STRING,
                        start_line: INT,
                        end_line: INT,
                        remediation_suggestion: STRING
                    >
                >,
                summary STRUCT<
                    total_findings: INT,
                    critical: INT,
                    high: INT,
                    medium: INT,
                    low: INT,
                    info: INT
                >,
                agent_results ARRAY<
                    STRUCT<
                        agent_type: STRING,
                        status: STRING,
                        findings_count: INT,
                        execution_time: INT,
                        cost: DOUBLE
                    >
                >
            )
            PARTITIONED BY (
                scan_date STRING
            )
            ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
            LOCATION 's3://{self.results_bucket}/processed/'
            TBLPROPERTIES (
                'projection.enabled' = 'true',
                'projection.scan_date.type' = 'date',
                'projection.scan_date.range' = '2024-01-01,NOW',
                'projection.scan_date.format' = 'yyyy-MM-dd'
            )
            """
            
            query_id = self._execute_athena_query(create_table_query)
            
            return {
                'status': 'success',
                'table': 'aggregated_findings',
                'query_id': query_id
            }
            
        except Exception as e:
            logger.error(f"Failed to create aggregated findings table: {e}")
            raise
    
    def _create_analysis_views(self) -> Dict[str, Any]:
        """Create analysis views for common queries"""
        views_created = []
        
        # View 1: Top vulnerable files
        try:
            view_query = f"""
            CREATE OR REPLACE VIEW {self.database_name}.top_vulnerable_files AS
            SELECT 
                file_path,
                COUNT(*) as vulnerability_count,
                COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_count,
                COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_count,
                COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium_count,
                ARRAY_AGG(DISTINCT type) as vulnerability_types
            FROM {self.database_name}.security_findings
            WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
            GROUP BY file_path
            ORDER BY vulnerability_count DESC
            """
            
            self._execute_athena_query(view_query)
            views_created.append('top_vulnerable_files')
        except Exception as e:
            logger.error(f"Failed to create top_vulnerable_files view: {e}")
        
        # View 2: Vulnerability trends over time
        try:
            view_query = f"""
            CREATE OR REPLACE VIEW {self.database_name}.vulnerability_trends AS
            SELECT 
                scan_date,
                COUNT(DISTINCT scan_id) as scan_count,
                COUNT(*) as total_findings,
                COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
                COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high,
                COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as medium,
                COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low,
                COUNT(CASE WHEN severity = 'INFO' THEN 1 END) as info
            FROM {self.database_name}.security_findings
            GROUP BY scan_date
            ORDER BY scan_date DESC
            """
            
            self._execute_athena_query(view_query)
            views_created.append('vulnerability_trends')
        except Exception as e:
            logger.error(f"Failed to create vulnerability_trends view: {e}")
        
        # View 3: Most common vulnerability types
        try:
            view_query = f"""
            CREATE OR REPLACE VIEW {self.database_name}.common_vulnerabilities AS
            SELECT 
                type,
                severity,
                COUNT(*) as occurrence_count,
                COUNT(DISTINCT file_path) as affected_files,
                COUNT(DISTINCT scan_id) as affected_scans,
                ARRAY_AGG(DISTINCT cwe_id) FILTER (WHERE cwe_id IS NOT NULL) as cwe_ids
            FROM {self.database_name}.security_findings
            GROUP BY type, severity
            ORDER BY occurrence_count DESC
            """
            
            self._execute_athena_query(view_query)
            views_created.append('common_vulnerabilities')
        except Exception as e:
            logger.error(f"Failed to create common_vulnerabilities view: {e}")
        
        # View 4: Cost analysis per scan
        try:
            view_query = f"""
            CREATE OR REPLACE VIEW {self.database_name}.scan_cost_analysis AS
            SELECT 
                s.scan_id,
                s.repository_url,
                s.scan_date,
                s.total_findings,
                s.total_cost_usd,
                s.execution_time_seconds,
                CASE 
                    WHEN s.total_findings > 0 
                    THEN s.total_cost_usd / s.total_findings 
                    ELSE 0 
                END as cost_per_finding,
                s.total_cost_usd / (s.execution_time_seconds / 3600.0) as cost_per_hour
            FROM {self.database_name}.security_scans s
            WHERE s.status = 'COMPLETED'
            ORDER BY s.scan_date DESC
            """
            
            self._execute_athena_query(view_query)
            views_created.append('scan_cost_analysis')
        except Exception as e:
            logger.error(f"Failed to create scan_cost_analysis view: {e}")
        
        return {
            'status': 'success',
            'views_created': views_created
        }
    
    def _repair_table_partitions(self) -> Dict[str, Any]:
        """Repair table partitions to discover new data"""
        repaired_tables = []
        
        tables_to_repair = ['security_findings', 'security_scans', 'aggregated_findings']
        
        for table in tables_to_repair:
            try:
                repair_query = f"MSCK REPAIR TABLE {self.database_name}.{table}"
                self._execute_athena_query(repair_query)
                repaired_tables.append(table)
            except Exception as e:
                logger.error(f"Failed to repair partitions for {table}: {e}")
        
        return {
            'status': 'success',
            'repaired_tables': repaired_tables
        }
    
    def _execute_athena_query(self, query: str) -> str:
        """Execute an Athena query and return query ID"""
        try:
            response = athena_client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={
                    'Database': self.database_name
                },
                ResultConfiguration={
                    'OutputLocation': self.athena_results_location
                }
            )
            
            query_id = response['QueryExecutionId']
            
            # Wait for query to complete
            self._wait_for_query_completion(query_id)
            
            return query_id
            
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise
    
    def _wait_for_query_completion(self, query_id: str, max_attempts: int = 30):
        """Wait for Athena query to complete"""
        import time
        
        for attempt in range(max_attempts):
            response = athena_client.get_query_execution(QueryExecutionId=query_id)
            status = response['QueryExecution']['Status']['State']
            
            if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                if status != 'SUCCEEDED':
                    error_msg = response['QueryExecution']['Status'].get('StateChangeReason', 'Unknown error')
                    raise Exception(f"Query {query_id} failed: {error_msg}")
                return
            
            time.sleep(2)  # Wait 2 seconds before next check
        
        raise Exception(f"Query {query_id} timed out after {max_attempts * 2} seconds")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler entry point"""
    handler = AthenaSetupHandler()
    return handler.handle_request(event, context)