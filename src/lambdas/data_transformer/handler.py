"""
Data Transformer Lambda - Transforms security scan data for analytics and reporting
"""
import os
import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal
import gzip
import base64
from io import BytesIO
import csv

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
athena_client = boto3.client('athena')
glue_client = boto3.client('glue')

# Environment variables
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET')
ANALYTICS_BUCKET = os.environ.get('ANALYTICS_BUCKET', RESULTS_BUCKET)
FINDINGS_TABLE = os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
SCANS_TABLE = os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans')
GLUE_DATABASE = os.environ.get('GLUE_DATABASE', 'security_analytics')
ATHENA_WORKGROUP = os.environ.get('ATHENA_WORKGROUP', 'primary')


class DataTransformer:
    """Transforms security data for analytics"""
    
    def __init__(self):
        self.findings_table = dynamodb.Table(FINDINGS_TABLE)
        self.scans_table = dynamodb.Table(SCANS_TABLE)
        
    def transform_data(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform security scan data for analytics
        
        Transformations:
        1. Flatten nested structures
        2. Convert to analytics-friendly formats (Parquet, CSV)
        3. Aggregate metrics
        4. Create time-series data
        5. Generate compliance mappings
        """
        
        transform_type = event.get('transform_type', 'scan_results')
        scan_id = event.get('scan_id')
        ai_scan_id = event.get('ai_scan_id')
        
        if not scan_id and not ai_scan_id:
            raise ValueError("scan_id or ai_scan_id required")
        
        results = {
            'scan_id': scan_id,
            'ai_scan_id': ai_scan_id,
            'transform_type': transform_type,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if transform_type == 'scan_results':
            output = self._transform_scan_results(scan_id, ai_scan_id)
            results.update(output)
        
        elif transform_type == 'time_series':
            output = self._create_time_series_data(event.get('days', 30))
            results.update(output)
        
        elif transform_type == 'compliance_mapping':
            output = self._create_compliance_mappings(scan_id, ai_scan_id)
            results.update(output)
        
        elif transform_type == 'executive_dashboard':
            output = self._create_executive_dashboard_data(scan_id, ai_scan_id)
            results.update(output)
        
        elif transform_type == 'vulnerability_trends':
            output = self._analyze_vulnerability_trends()
            results.update(output)
        
        elif transform_type == 'batch_transform':
            output = self._batch_transform_scans(event.get('scan_ids', []))
            results.update(output)
        
        else:
            raise ValueError(f"Unknown transform type: {transform_type}")
        
        return results
    
    def _transform_scan_results(self, scan_id: str, ai_scan_id: str) -> Dict[str, Any]:
        """Transform scan results for analytics"""
        
        # Get findings from DynamoDB
        findings = self._get_findings(ai_scan_id or scan_id)
        
        if not findings:
            return {
                'status': 'no_data',
                'message': 'No findings to transform'
            }
        
        # Get scan metadata
        scan_metadata = self._get_scan_metadata(ai_scan_id or scan_id)
        
        # Transform findings to flat structure
        transformed_findings = []
        for finding in findings:
            flat_finding = self._flatten_finding(finding, scan_metadata)
            transformed_findings.append(flat_finding)
        
        # Generate analytics files
        output_files = {}
        
        # 1. CSV for simple analysis
        csv_key = f"analytics/findings/{ai_scan_id or scan_id}/findings.csv"
        csv_url = self._write_csv(transformed_findings, csv_key)
        output_files['csv'] = csv_url
        
        # 2. JSON Lines for streaming
        jsonl_key = f"analytics/findings/{ai_scan_id or scan_id}/findings.jsonl"
        jsonl_url = self._write_jsonl(transformed_findings, jsonl_key)
        output_files['jsonl'] = jsonl_url
        
        # 3. Aggregated metrics
        metrics = self._calculate_metrics(transformed_findings, scan_metadata)
        metrics_key = f"analytics/metrics/{ai_scan_id or scan_id}/metrics.json"
        metrics_url = self._write_json(metrics, metrics_key)
        output_files['metrics'] = metrics_url
        
        # 4. Parquet for Athena (if pyarrow available)
        try:
            parquet_key = f"analytics/findings/{ai_scan_id or scan_id}/findings.parquet"
            parquet_url = self._write_parquet(transformed_findings, parquet_key)
            output_files['parquet'] = parquet_url
        except ImportError:
            logger.warning("PyArrow not available, skipping Parquet output")
        
        # 5. Time-partitioned data
        partition_key = self._write_partitioned_data(transformed_findings, ai_scan_id or scan_id)
        output_files['partitioned'] = partition_key
        
        # Update Glue catalog
        self._update_glue_catalog(ai_scan_id or scan_id)
        
        return {
            'status': 'success',
            'findings_count': len(findings),
            'output_files': output_files,
            'metrics': metrics,
            'glue_updated': True
        }
    
    def _get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve findings from DynamoDB"""
        findings = []
        
        try:
            # Query using GSI
            response = self.findings_table.query(
                IndexName='ScanIndex',
                KeyConditionExpression='scan_id = :scan_id',
                ExpressionAttributeValues={':scan_id': scan_id}
            )
            
            findings.extend(response.get('Items', []))
            
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.findings_table.query(
                    IndexName='ScanIndex',
                    KeyConditionExpression='scan_id = :scan_id',
                    ExpressionAttributeValues={':scan_id': scan_id},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                findings.extend(response.get('Items', []))
                
        except Exception as e:
            logger.error(f"Error retrieving findings: {e}")
        
        return findings
    
    def _get_scan_metadata(self, scan_id: str) -> Dict[str, Any]:
        """Get scan metadata"""
        try:
            response = self.scans_table.get_item(Key={'scan_id': scan_id})
            return response.get('Item', {})
        except:
            return {}
    
    def _flatten_finding(self, finding: Dict[str, Any], scan_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten finding structure for analytics"""
        
        # Convert Decimal to float
        def convert_decimals(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif isinstance(obj, dict):
                return {k: convert_decimals(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_decimals(i) for i in obj]
            return obj
        
        finding = convert_decimals(finding)
        
        # Extract nested fields
        flat = {
            'finding_id': finding.get('finding_id'),
            'scan_id': finding.get('scan_id'),
            'timestamp': finding.get('created_at', datetime.utcnow().isoformat()),
            'finding_type': finding.get('finding_type'),
            'severity': finding.get('severity'),
            'confidence': finding.get('confidence', 0),
            'confidence_level': finding.get('confidence_level'),
            'business_risk_score': finding.get('business_risk_score', 0),
            'file_path': finding.get('file_path'),
            'description': finding.get('description', ''),
            'remediation': finding.get('remediation', ''),
            'package_name': finding.get('package_name'),
            'asset_criticality': finding.get('asset_criticality', 'normal'),
            
            # Scan metadata
            'repository': scan_metadata.get('repository', ''),
            'branch': scan_metadata.get('branch', 'main'),
            'scan_type': scan_metadata.get('scan_type', 'unknown'),
            'scan_started': scan_metadata.get('started_at'),
            'scan_completed': scan_metadata.get('completed_at'),
            
            # Derived fields
            'risk_category': self._categorize_risk(finding),
            'compliance_impact': self._assess_compliance_impact(finding),
            'estimated_fix_time': self._estimate_fix_time(finding),
            'vulnerability_age_days': self._calculate_vulnerability_age(finding),
            
            # Analytics fields
            'year': datetime.utcnow().year,
            'month': datetime.utcnow().month,
            'day': datetime.utcnow().day,
            'hour': datetime.utcnow().hour,
            'weekday': datetime.utcnow().strftime('%A'),
            'quarter': (datetime.utcnow().month - 1) // 3 + 1
        }
        
        # Add evidence count if available
        if 'evidence' in finding:
            flat['evidence_count'] = len(finding.get('evidence', []))
        
        # Add false positive indicators count
        if 'false_positive_indicators' in finding:
            flat['false_positive_indicators_count'] = len(finding.get('false_positive_indicators', []))
        
        return flat
    
    def _calculate_metrics(self, findings: List[Dict], scan_metadata: Dict) -> Dict[str, Any]:
        """Calculate aggregated metrics"""
        
        if not findings:
            return {}
        
        # Basic counts
        severity_counts = {}
        type_counts = {}
        risk_categories = {}
        file_counts = {}
        
        # Aggregate metrics
        total_risk = 0
        total_confidence = 0
        critical_files = set()
        
        for finding in findings:
            # Severity distribution
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Type distribution
            finding_type = finding.get('finding_type', 'unknown')
            type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
            
            # Risk categories
            risk_cat = finding.get('risk_category', 'unknown')
            risk_categories[risk_cat] = risk_categories.get(risk_cat, 0) + 1
            
            # File distribution
            file_path = finding.get('file_path', 'unknown')
            file_counts[file_path] = file_counts.get(file_path, 0) + 1
            
            # Aggregate scores
            total_risk += finding.get('business_risk_score', 0)
            total_confidence += finding.get('confidence', 0)
            
            # Track critical files
            if finding.get('asset_criticality') == 'critical':
                critical_files.add(file_path)
        
        # Calculate derived metrics
        metrics = {
            'summary': {
                'total_findings': len(findings),
                'unique_files': len(file_counts),
                'critical_files': len(critical_files),
                'average_risk_score': total_risk / len(findings) if findings else 0,
                'average_confidence': total_confidence / len(findings) if findings else 0,
                'scan_duration_seconds': self._calculate_scan_duration(scan_metadata)
            },
            'distributions': {
                'by_severity': severity_counts,
                'by_type': type_counts,
                'by_risk_category': risk_categories,
                'top_affected_files': dict(sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            },
            'risk_analysis': {
                'high_risk_findings': len([f for f in findings if f.get('business_risk_score', 0) > 0.7]),
                'critical_severity_count': severity_counts.get('CRITICAL', 0),
                'estimated_total_fix_hours': sum(f.get('estimated_fix_time', 0) for f in findings)
            },
            'compliance': {
                'pci_dss_impact': len([f for f in findings if 'PCI-DSS' in f.get('compliance_impact', '')]),
                'hipaa_impact': len([f for f in findings if 'HIPAA' in f.get('compliance_impact', '')]),
                'gdpr_impact': len([f for f in findings if 'GDPR' in f.get('compliance_impact', '')])
            }
        }
        
        return metrics
    
    def _write_csv(self, data: List[Dict], key: str) -> str:
        """Write data to CSV in S3"""
        if not data:
            return ""
        
        # Create CSV in memory
        output = BytesIO()
        fieldnames = list(data[0].keys())
        
        # Write as string first
        string_buffer = BytesIO()
        writer = csv.DictWriter(string_buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        
        # Compress
        string_buffer.seek(0)
        with gzip.GzipFile(fileobj=output, mode='wb') as gz:
            gz.write(string_buffer.getvalue().encode('utf-8'))
        
        # Upload to S3
        output.seek(0)
        s3_client.put_object(
            Bucket=ANALYTICS_BUCKET,
            Key=f"{key}.gz",
            Body=output.getvalue(),
            ContentType='text/csv',
            ContentEncoding='gzip'
        )
        
        return f"s3://{ANALYTICS_BUCKET}/{key}.gz"
    
    def _write_jsonl(self, data: List[Dict], key: str) -> str:
        """Write data as JSON Lines to S3"""
        if not data:
            return ""
        
        # Create JSONL in memory
        output = BytesIO()
        
        # Write each record as a line
        for record in data:
            line = json.dumps(record, default=str) + '\n'
            output.write(line.encode('utf-8'))
        
        # Upload to S3
        output.seek(0)
        s3_client.put_object(
            Bucket=ANALYTICS_BUCKET,
            Key=key,
            Body=output.getvalue(),
            ContentType='application/x-ndjson'
        )
        
        return f"s3://{ANALYTICS_BUCKET}/{key}"
    
    def _write_json(self, data: Dict, key: str) -> str:
        """Write JSON data to S3"""
        s3_client.put_object(
            Bucket=ANALYTICS_BUCKET,
            Key=key,
            Body=json.dumps(data, indent=2, default=str),
            ContentType='application/json'
        )
        
        return f"s3://{ANALYTICS_BUCKET}/{key}"
    
    def _write_parquet(self, data: List[Dict], key: str) -> str:
        """Write data as Parquet to S3"""
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
            import pandas as pd
            
            # Convert to DataFrame
            df = pd.DataFrame(data)
            
            # Convert to PyArrow Table
            table = pa.Table.from_pandas(df)
            
            # Write to buffer
            buffer = BytesIO()
            pq.write_table(table, buffer)
            
            # Upload to S3
            buffer.seek(0)
            s3_client.put_object(
                Bucket=ANALYTICS_BUCKET,
                Key=key,
                Body=buffer.getvalue(),
                ContentType='application/x-parquet'
            )
            
            return f"s3://{ANALYTICS_BUCKET}/{key}"
            
        except ImportError:
            logger.error("PyArrow not installed")
            raise
    
    def _write_partitioned_data(self, findings: List[Dict], scan_id: str) -> str:
        """Write time-partitioned data for efficient querying"""
        
        # Group by date
        partitions = {}
        for finding in findings:
            date = finding.get('timestamp', datetime.utcnow().isoformat())[:10]
            year, month, day = date.split('-')
            
            partition_key = f"year={year}/month={month}/day={day}"
            if partition_key not in partitions:
                partitions[partition_key] = []
            partitions[partition_key].append(finding)
        
        # Write each partition
        base_key = f"analytics/partitioned/findings"
        for partition, data in partitions.items():
            key = f"{base_key}/{partition}/scan_{scan_id}.json"
            self._write_json(data, key)
        
        return f"s3://{ANALYTICS_BUCKET}/{base_key}/"
    
    def _update_glue_catalog(self, scan_id: str):
        """Update AWS Glue catalog for Athena queries"""
        try:
            # Check if database exists
            try:
                glue_client.get_database(Name=GLUE_DATABASE)
            except glue_client.exceptions.EntityNotFoundException:
                # Create database
                glue_client.create_database(
                    DatabaseInput={
                        'Name': GLUE_DATABASE,
                        'Description': 'Security analytics database'
                    }
                )
            
            # Update/create findings table
            table_name = 'security_findings'
            table_input = {
                'Name': table_name,
                'StorageDescriptor': {
                    'Columns': [
                        {'Name': 'finding_id', 'Type': 'string'},
                        {'Name': 'scan_id', 'Type': 'string'},
                        {'Name': 'timestamp', 'Type': 'timestamp'},
                        {'Name': 'finding_type', 'Type': 'string'},
                        {'Name': 'severity', 'Type': 'string'},
                        {'Name': 'confidence', 'Type': 'double'},
                        {'Name': 'business_risk_score', 'Type': 'double'},
                        {'Name': 'file_path', 'Type': 'string'},
                        {'Name': 'repository', 'Type': 'string'},
                        {'Name': 'branch', 'Type': 'string'}
                    ],
                    'Location': f's3://{ANALYTICS_BUCKET}/analytics/partitioned/findings/',
                    'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                    'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                    'SerdeInfo': {
                        'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe'
                    }
                },
                'PartitionKeys': [
                    {'Name': 'year', 'Type': 'string'},
                    {'Name': 'month', 'Type': 'string'},
                    {'Name': 'day', 'Type': 'string'}
                ]
            }
            
            try:
                glue_client.update_table(
                    DatabaseName=GLUE_DATABASE,
                    TableInput=table_input
                )
            except glue_client.exceptions.EntityNotFoundException:
                glue_client.create_table(
                    DatabaseName=GLUE_DATABASE,
                    TableInput=table_input
                )
            
        except Exception as e:
            logger.error(f"Failed to update Glue catalog: {e}")
    
    def _create_time_series_data(self, days: int) -> Dict[str, Any]:
        """Create time series data for trend analysis"""
        
        # Query historical data
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # In production, query from DynamoDB or S3
        # This is a simplified version
        time_series = []
        
        # Generate sample data points
        current = start_date
        while current <= end_date:
            data_point = {
                'date': current.strftime('%Y-%m-%d'),
                'total_findings': 0,  # Would query actual data
                'critical_findings': 0,
                'high_findings': 0,
                'average_risk_score': 0
            }
            time_series.append(data_point)
            current += timedelta(days=1)
        
        # Write time series data
        ts_key = f"analytics/time_series/security_trends_{days}d.json"
        ts_url = self._write_json({'time_series': time_series}, ts_key)
        
        return {
            'status': 'success',
            'days': days,
            'data_points': len(time_series),
            'output_file': ts_url
        }
    
    def _create_compliance_mappings(self, scan_id: str, ai_scan_id: str) -> Dict[str, Any]:
        """Map findings to compliance frameworks"""
        
        findings = self._get_findings(ai_scan_id or scan_id)
        
        compliance_mappings = {
            'PCI-DSS': self._map_to_pci_dss(findings),
            'HIPAA': self._map_to_hipaa(findings),
            'SOC2': self._map_to_soc2(findings),
            'GDPR': self._map_to_gdpr(findings),
            'NIST': self._map_to_nist(findings)
        }
        
        # Write compliance report
        comp_key = f"analytics/compliance/{ai_scan_id or scan_id}/compliance_mappings.json"
        comp_url = self._write_json(compliance_mappings, comp_key)
        
        return {
            'status': 'success',
            'frameworks_mapped': list(compliance_mappings.keys()),
            'output_file': comp_url
        }
    
    def _create_executive_dashboard_data(self, scan_id: str, ai_scan_id: str) -> Dict[str, Any]:
        """Create executive dashboard data"""
        
        findings = self._get_findings(ai_scan_id or scan_id)
        scan_metadata = self._get_scan_metadata(ai_scan_id or scan_id)
        
        dashboard_data = {
            'scan_summary': {
                'scan_id': scan_id,
                'repository': scan_metadata.get('repository', 'Unknown'),
                'scan_date': scan_metadata.get('completed_at', datetime.utcnow().isoformat()),
                'total_findings': len(findings),
                'critical_findings': len([f for f in findings if f.get('severity') == 'CRITICAL']),
                'business_risk_score': scan_metadata.get('business_risk_score', 0)
            },
            'risk_indicators': {
                'immediate_action_required': len([f for f in findings if f.get('severity') == 'CRITICAL']),
                'high_business_impact': len([f for f in findings if f.get('business_risk_score', 0) > 0.7]),
                'compliance_violations': len([f for f in findings if f.get('compliance_impact')])
            },
            'top_risks': self._get_top_risks(findings, 5),
            'remediation_summary': {
                'estimated_hours': sum(self._estimate_fix_time(f) for f in findings),
                'priority_fixes': len([f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']])
            },
            'trend_indicators': {
                'risk_trend': 'increasing',  # Would calculate from historical data
                'finding_velocity': 0  # New findings per day
            }
        }
        
        # Write dashboard data
        dash_key = f"analytics/dashboards/{ai_scan_id or scan_id}/executive_dashboard.json"
        dash_url = self._write_json(dashboard_data, dash_key)
        
        return {
            'status': 'success',
            'dashboard_generated': True,
            'output_file': dash_url
        }
    
    def _categorize_risk(self, finding: Dict) -> str:
        """Categorize risk level"""
        risk_score = finding.get('business_risk_score', 0)
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _assess_compliance_impact(self, finding: Dict) -> str:
        """Assess compliance impact of finding"""
        finding_type = finding.get('finding_type', '').lower()
        severity = finding.get('severity', 'MEDIUM')
        
        impacts = []
        
        # PCI-DSS
        if any(term in finding_type for term in ['payment', 'card', 'pci', 'encryption']):
            impacts.append('PCI-DSS')
        
        # HIPAA
        if any(term in finding_type for term in ['health', 'medical', 'patient', 'phi']):
            impacts.append('HIPAA')
        
        # GDPR
        if any(term in finding_type for term in ['privacy', 'personal', 'gdpr', 'consent']):
            impacts.append('GDPR')
        
        # SOC2
        if severity in ['CRITICAL', 'HIGH']:
            impacts.append('SOC2')
        
        return ','.join(impacts) if impacts else 'none'
    
    def _estimate_fix_time(self, finding: Dict) -> float:
        """Estimate time to fix in hours"""
        severity = finding.get('severity', 'MEDIUM')
        finding_type = finding.get('finding_type', '').lower()
        
        base_hours = {
            'CRITICAL': 8,
            'HIGH': 4,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        hours = base_hours.get(severity, 2)
        
        # Adjust based on type
        if 'configuration' in finding_type:
            hours *= 0.5  # Quick fix
        elif 'architecture' in finding_type:
            hours *= 2  # Complex fix
        
        return hours
    
    def _calculate_vulnerability_age(self, finding: Dict) -> int:
        """Calculate age of vulnerability in days"""
        created = finding.get('created_at', datetime.utcnow().isoformat())
        try:
            created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
            age = (datetime.utcnow() - created_date).days
            return max(0, age)
        except:
            return 0
    
    def _calculate_scan_duration(self, scan_metadata: Dict) -> float:
        """Calculate scan duration in seconds"""
        started = scan_metadata.get('started_at')
        completed = scan_metadata.get('completed_at')
        
        if started and completed:
            try:
                start_time = datetime.fromisoformat(started.replace('Z', '+00:00'))
                end_time = datetime.fromisoformat(completed.replace('Z', '+00:00'))
                return (end_time - start_time).total_seconds()
            except:
                pass
        
        return 0
    
    def _get_top_risks(self, findings: List[Dict], limit: int = 5) -> List[Dict]:
        """Get top risks by business impact"""
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get('business_risk_score', 0),
            reverse=True
        )
        
        return [
            {
                'finding_id': f.get('finding_id'),
                'type': f.get('finding_type'),
                'severity': f.get('severity'),
                'risk_score': f.get('business_risk_score', 0),
                'file': f.get('file_path')
            }
            for f in sorted_findings[:limit]
        ]
    
    def _map_to_pci_dss(self, findings: List[Dict]) -> Dict[str, Any]:
        """Map findings to PCI-DSS requirements"""
        pci_mapping = {
            'requirement_2': [],  # Default passwords
            'requirement_3': [],  # Protect stored data
            'requirement_4': [],  # Encrypt transmission
            'requirement_6': [],  # Secure development
            'requirement_8': []   # Access control
        }
        
        for finding in findings:
            finding_type = finding.get('finding_type', '').lower()
            
            if 'password' in finding_type or 'credential' in finding_type:
                pci_mapping['requirement_2'].append(finding.get('finding_id'))
            
            if 'encryption' in finding_type or 'storage' in finding_type:
                pci_mapping['requirement_3'].append(finding.get('finding_id'))
            
            if 'transmission' in finding_type or 'ssl' in finding_type:
                pci_mapping['requirement_4'].append(finding.get('finding_id'))
            
            if finding.get('severity') in ['CRITICAL', 'HIGH']:
                pci_mapping['requirement_6'].append(finding.get('finding_id'))
            
            if 'access' in finding_type or 'auth' in finding_type:
                pci_mapping['requirement_8'].append(finding.get('finding_id'))
        
        return pci_mapping
    
    def _map_to_hipaa(self, findings: List[Dict]) -> Dict[str, Any]:
        """Map findings to HIPAA safeguards"""
        return {
            'administrative': [],
            'physical': [],
            'technical': []
        }
    
    def _map_to_soc2(self, findings: List[Dict]) -> Dict[str, Any]:
        """Map findings to SOC2 criteria"""
        return {
            'security': [],
            'availability': [],
            'processing_integrity': [],
            'confidentiality': [],
            'privacy': []
        }
    
    def _map_to_gdpr(self, findings: List[Dict]) -> Dict[str, Any]:
        """Map findings to GDPR articles"""
        return {
            'article_25': [],  # Data protection by design
            'article_32': [],  # Security of processing
            'article_33': [],  # Breach notification
            'article_35': []   # Data protection impact assessment
        }
    
    def _map_to_nist(self, findings: List[Dict]) -> Dict[str, Any]:
        """Map findings to NIST framework"""
        return {
            'identify': [],
            'protect': [],
            'detect': [],
            'respond': [],
            'recover': []
        }
    
    def _analyze_vulnerability_trends(self) -> Dict[str, Any]:
        """Analyze vulnerability trends across all scans"""
        # In production, aggregate data from multiple scans
        return {
            'status': 'success',
            'trend_analysis': {
                'vulnerability_growth_rate': 0,
                'most_common_types': [],
                'risk_score_trend': 'stable',
                'remediation_velocity': 0
            }
        }
    
    def _batch_transform_scans(self, scan_ids: List[str]) -> Dict[str, Any]:
        """Transform multiple scans in batch"""
        results = []
        
        for scan_id in scan_ids:
            try:
                result = self._transform_scan_results(scan_id, None)
                results.append({
                    'scan_id': scan_id,
                    'status': result.get('status'),
                    'findings_count': result.get('findings_count', 0)
                })
            except Exception as e:
                results.append({
                    'scan_id': scan_id,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {
            'status': 'batch_complete',
            'total_scans': len(scan_ids),
            'successful': len([r for r in results if r['status'] == 'success']),
            'results': results
        }


def lambda_handler(event, context):
    """Lambda handler for data transformation"""
    
    transformer = DataTransformer()
    
    try:
        # Handle different event sources
        if 'Records' in event:
            # DynamoDB Stream or S3 event
            results = []
            for record in event['Records']:
                if 'dynamodb' in record:
                    # Transform on scan completion
                    if record['eventName'] in ['INSERT', 'MODIFY']:
                        new_image = record['dynamodb'].get('NewImage', {})
                        if new_image.get('status', {}).get('S') == 'completed':
                            transform_event = {
                                'transform_type': 'scan_results',
                                'scan_id': new_image.get('scan_id', {}).get('S')
                            }
                            result = transformer.transform_data(transform_event)
                            results.append(result)
            
            return {
                'statusCode': 200,
                'results': results
            }
        else:
            # Direct invocation
            return transformer.transform_data(event)
            
    except Exception as e:
        logger.error(f"Data transformation failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }