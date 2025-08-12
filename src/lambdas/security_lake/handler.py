"""
Security Lake Lambda - Integration with AWS Security Lake
"""
import json
import os
import boto3
from datetime import datetime
from typing import Dict, List, Any
import uuid


s3_client = boto3.client('s3')
glue_client = boto3.client('glue')


def handler(event, context):
    """
    Send security findings to AWS Security Lake
    
    Args:
        event: Lambda event containing security findings
        context: Lambda context
        
    Returns:
        Status of data ingestion
    """
    try:
        # Extract findings from event
        findings = event.get('findings', [])
        scan_id = event.get('scan_id', str(uuid.uuid4()))
        repository = event.get('repository', 'unknown')
        
        # Convert findings to OCSF format
        ocsf_records = []
        for finding in findings:
            ocsf_record = convert_to_ocsf(finding, scan_id, repository)
            ocsf_records.append(ocsf_record)
        
        # Write to Security Lake
        if ocsf_records:
            result = write_to_security_lake(ocsf_records)
        else:
            result = {'status': 'no_findings', 'message': 'No findings to process'}
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'scan_id': scan_id,
                'findings_processed': len(ocsf_records),
                'result': result
            })
        }
        
    except Exception as e:
        print(f"Error in Security Lake integration: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def convert_to_ocsf(finding: Dict[str, Any], scan_id: str, repository: str) -> Dict[str, Any]:
    """
    Convert finding to Open Cybersecurity Schema Framework (OCSF) format
    
    Args:
        finding: Security finding
        scan_id: Scan identifier
        repository: Repository name
        
    Returns:
        OCSF formatted record
    """
    # Map severity to OCSF severity_id
    severity_map = {
        'critical': 6,  # Fatal
        'high': 5,      # High
        'medium': 3,    # Medium
        'low': 2,       # Low
        'info': 1       # Informational
    }
    
    ocsf_record = {
        'activity_id': 1,  # Detection
        'category_uid': 2,  # Findings
        'class_uid': 2004,  # Detection Finding
        'metadata': {
            'product': {
                'name': 'AI Security Audit Framework',
                'vendor_name': 'SecurityAudit',
                'version': '2.0.0'
            },
            'version': '1.0.0',
            'logged_time': int(datetime.utcnow().timestamp() * 1000),
            'uid': f"{scan_id}-{finding.get('id', uuid.uuid4())}"
        },
        'severity_id': severity_map.get(finding.get('severity', 'low').lower(), 2),
        'status_id': 1,  # New
        'time': int(datetime.utcnow().timestamp() * 1000),
        'finding': {
            'title': finding.get('type', 'Unknown'),
            'desc': finding.get('description', ''),
            'remediation': {
                'desc': finding.get('remediation', ''),
                'kb_article_list': finding.get('references', [])
            },
            'src_file': {
                'path': finding.get('file_path', ''),
                'line': finding.get('line_number', 0)
            },
            'types': [finding.get('category', 'security')]
        },
        'resources': [{
            'type': 'Repository',
            'uid': repository,
            'name': repository
        }],
        'risk_level': finding.get('risk_level', 'Unknown'),
        'confidence': finding.get('confidence', 0.0),
        'analytic': {
            'name': finding.get('scanner', 'AI Scanner'),
            'type': 'AI/ML'
        }
    }
    
    return ocsf_record


def write_to_security_lake(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Write OCSF records to Security Lake"""
    try:
        # Security Lake configuration
        bucket = os.environ.get('SECURITY_LAKE_BUCKET', 'aws-security-data-lake')
        prefix = os.environ.get('SECURITY_LAKE_PREFIX', 'ext/SecurityAudit')
        
        # Create partition path (year/month/day/hour)
        now = datetime.utcnow()
        partition_path = now.strftime('%Y/%m/%d/%H')
        
        # Generate filename
        filename = f"{prefix}/{partition_path}/findings-{int(now.timestamp())}.json"
        
        # Convert records to JSONL format
        jsonl_content = '\n'.join(json.dumps(record) for record in records)
        
        # Write to S3
        s3_client.put_object(
            Bucket=bucket,
            Key=filename,
            Body=jsonl_content,
            ContentType='application/x-ndjson'
        )
        
        # Update Glue catalog if needed
        update_glue_partition(bucket, prefix, partition_path)
        
        return {
            'status': 'success',
            'location': f"s3://{bucket}/{filename}",
            'records_written': len(records)
        }
        
    except Exception as e:
        print(f"Error writing to Security Lake: {str(e)}")
        return {
            'status': 'error',
            'error': str(e)
        }


def update_glue_partition(bucket: str, prefix: str, partition_path: str):
    """Update Glue catalog partition for Security Lake"""
    try:
        database = os.environ.get('SECURITY_LAKE_DATABASE', 'aws_security_lake')
        table = os.environ.get('SECURITY_LAKE_TABLE', 'security_findings')
        
        # Parse partition values
        parts = partition_path.split('/')
        partition_values = {
            'year': parts[0],
            'month': parts[1],
            'day': parts[2],
            'hour': parts[3]
        }
        
        # Create partition if it doesn't exist
        glue_client.create_partition(
            DatabaseName=database,
            TableName=table,
            PartitionInput={
                'Values': list(partition_values.values()),
                'StorageDescriptor': {
                    'Location': f"s3://{bucket}/{prefix}/{partition_path}/",
                    'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                    'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                    'SerdeInfo': {
                        'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe'
                    }
                }
            }
        )
        
    except glue_client.exceptions.AlreadyExistsException:
        # Partition already exists
        pass
    except Exception as e:
        print(f"Error updating Glue partition: {str(e)}")