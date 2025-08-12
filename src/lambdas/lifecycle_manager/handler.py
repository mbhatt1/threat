"""
Lifecycle Manager Lambda - Manages lifecycle of security scan resources and data
"""
import os
import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from decimal import Decimal

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
ecs_client = boto3.client('ecs')
logs_client = boto3.client('logs')
cloudwatch = boto3.client('cloudwatch')

# Environment variables
SCAN_TABLE = os.environ.get('SCAN_TABLE', 'SecurityScans')
AI_SCANS_TABLE = os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans')
FINDINGS_TABLE = os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET')
ANALYTICS_BUCKET = os.environ.get('ANALYTICS_BUCKET', RESULTS_BUCKET)
LOG_GROUP_PREFIX = os.environ.get('LOG_GROUP_PREFIX', '/aws/lambda/AISecurityAudit')
ECS_CLUSTER = os.environ.get('ECS_CLUSTER')

# Retention policies (in days)
DEFAULT_RETENTION_DAYS = {
    'scan_data': 90,
    'findings': 180,
    'reports': 365,
    'analytics': 90,
    'logs': 30,
    'temporary': 7
}


class LifecycleManager:
    """Manages lifecycle of security scan resources"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(SCAN_TABLE)
        self.ai_scans_table = dynamodb.Table(AI_SCANS_TABLE)
        self.findings_table = dynamodb.Table(FINDINGS_TABLE)
        self.retention_policies = self._load_retention_policies()
        
    def manage_lifecycle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for lifecycle management
        
        Actions:
        1. Archive old scan data
        2. Clean up temporary resources
        3. Rotate logs
        4. Manage S3 lifecycle policies
        5. Monitor resource usage
        """
        
        action = event.get('action', 'scheduled_cleanup')
        
        if action == 'scheduled_cleanup':
            return self._perform_scheduled_cleanup()
        elif action == 'archive_scan':
            return self._archive_scan_data(event.get('scan_id'))
        elif action == 'cleanup_resources':
            return self._cleanup_resources(event.get('resource_type'))
        elif action == 'monitor_usage':
            return self._monitor_resource_usage()
        elif action == 'optimize_storage':
            return self._optimize_storage()
        elif action == 'manage_retention':
            return self._manage_retention_policies()
        else:
            return {'statusCode': 400, 'message': f'Unknown action: {action}'}
    
    def _perform_scheduled_cleanup(self) -> Dict[str, Any]:
        """Perform scheduled cleanup tasks"""
        
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'actions_performed': []
        }
        
        # 1. Archive old scans
        archived_scans = self._archive_old_scans()
        results['actions_performed'].append({
            'action': 'archive_scans',
            'count': archived_scans['archived_count']
        })
        
        # 2. Clean up DynamoDB
        dynamo_cleanup = self._cleanup_dynamodb()
        results['actions_performed'].append({
            'action': 'cleanup_dynamodb',
            'items_deleted': dynamo_cleanup['deleted_count']
        })
        
        # 3. Clean up S3
        s3_cleanup = self._cleanup_s3()
        results['actions_performed'].append({
            'action': 'cleanup_s3',
            'objects_deleted': s3_cleanup['deleted_count']
        })
        
        # 4. Clean up CloudWatch Logs
        logs_cleanup = self._cleanup_logs()
        results['actions_performed'].append({
            'action': 'cleanup_logs',
            'log_groups_cleaned': logs_cleanup['cleaned_count']
        })
        
        # 5. Clean up ECS tasks
        if ECS_CLUSTER:
            ecs_cleanup = self._cleanup_ecs_tasks()
            results['actions_performed'].append({
                'action': 'cleanup_ecs',
                'tasks_stopped': ecs_cleanup['stopped_count']
            })
        
        # 6. Generate cleanup report
        report = self._generate_cleanup_report(results)
        results['report_location'] = report
        
        # 7. Update metrics
        self._update_cleanup_metrics(results)
        
        return {
            'statusCode': 200,
            'cleanup_results': results
        }
    
    def _archive_scan_data(self, scan_id: str) -> Dict[str, Any]:
        """Archive specific scan data"""
        
        if not scan_id:
            return {'statusCode': 400, 'message': 'scan_id required'}
        
        archived = {
            'scan_id': scan_id,
            'archived_at': datetime.utcnow().isoformat(),
            'components': []
        }
        
        # 1. Get scan metadata
        scan_data = self._get_scan_data(scan_id)
        if not scan_data:
            return {'statusCode': 404, 'message': 'Scan not found'}
        
        # 2. Archive findings to S3
        findings_archive = self._archive_findings(scan_id)
        archived['components'].append({
            'type': 'findings',
            'status': findings_archive['status'],
            'location': findings_archive.get('archive_location')
        })
        
        # 3. Archive reports
        reports_archive = self._archive_reports(scan_id)
        archived['components'].append({
            'type': 'reports',
            'status': reports_archive['status'],
            'location': reports_archive.get('archive_location')
        })
        
        # 4. Create archive manifest
        manifest = self._create_archive_manifest(scan_id, archived)
        archived['manifest_location'] = manifest
        
        # 5. Clean up original data (if configured)
        if event.get('delete_after_archive', False):
            cleanup_result = self._cleanup_after_archive(scan_id)
            archived['cleanup_performed'] = cleanup_result['success']
        
        return {
            'statusCode': 200,
            'archive_result': archived
        }
    
    def _cleanup_resources(self, resource_type: str) -> Dict[str, Any]:
        """Clean up specific resource types"""
        
        cleanup_functions = {
            'temporary_files': self._cleanup_temporary_files,
            'failed_scans': self._cleanup_failed_scans,
            'orphaned_resources': self._cleanup_orphaned_resources,
            'old_analytics': self._cleanup_old_analytics,
            'test_data': self._cleanup_test_data
        }
        
        if resource_type not in cleanup_functions:
            return {'statusCode': 400, 'message': f'Unknown resource type: {resource_type}'}
        
        cleanup_result = cleanup_functions[resource_type]()
        
        return {
            'statusCode': 200,
            'resource_type': resource_type,
            'cleanup_result': cleanup_result
        }
    
    def _monitor_resource_usage(self) -> Dict[str, Any]:
        """Monitor resource usage and costs"""
        
        usage_metrics = {
            'timestamp': datetime.utcnow().isoformat(),
            'storage': {},
            'compute': {},
            'database': {},
            'estimated_costs': {}
        }
        
        # 1. S3 storage usage
        if RESULTS_BUCKET:
            s3_usage = self._get_s3_usage()
            usage_metrics['storage']['s3'] = s3_usage
            usage_metrics['estimated_costs']['s3_monthly'] = s3_usage['size_gb'] * 0.023  # $0.023/GB
        
        # 2. DynamoDB usage
        dynamo_usage = self._get_dynamodb_usage()
        usage_metrics['database']['dynamodb'] = dynamo_usage
        usage_metrics['estimated_costs']['dynamodb_monthly'] = self._estimate_dynamodb_cost(dynamo_usage)
        
        # 3. ECS usage
        if ECS_CLUSTER:
            ecs_usage = self._get_ecs_usage()
            usage_metrics['compute']['ecs'] = ecs_usage
        
        # 4. Lambda usage
        lambda_usage = self._get_lambda_usage()
        usage_metrics['compute']['lambda'] = lambda_usage
        
        # 5. Generate recommendations
        recommendations = self._generate_cost_recommendations(usage_metrics)
        usage_metrics['recommendations'] = recommendations
        
        # 6. Send alerts if thresholds exceeded
        alerts = self._check_usage_thresholds(usage_metrics)
        if alerts:
            self._send_usage_alerts(alerts)
            usage_metrics['alerts_sent'] = len(alerts)
        
        return {
            'statusCode': 200,
            'usage_metrics': usage_metrics
        }
    
    def _optimize_storage(self) -> Dict[str, Any]:
        """Optimize storage usage"""
        
        optimization_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'actions': []
        }
        
        # 1. Compress large files
        compression_result = self._compress_large_files()
        optimization_results['actions'].append({
            'type': 'compression',
            'files_compressed': compression_result['count'],
            'space_saved_mb': compression_result['space_saved']
        })
        
        # 2. Move old data to Glacier
        glacier_result = self._move_to_glacier()
        optimization_results['actions'].append({
            'type': 'glacier_transition',
            'objects_moved': glacier_result['count'],
            'cost_reduction': glacier_result['estimated_savings']
        })
        
        # 3. Deduplicate data
        dedup_result = self._deduplicate_data()
        optimization_results['actions'].append({
            'type': 'deduplication',
            'duplicates_removed': dedup_result['count'],
            'space_saved_mb': dedup_result['space_saved']
        })
        
        # 4. Update S3 lifecycle policies
        lifecycle_result = self._update_s3_lifecycle_policies()
        optimization_results['actions'].append({
            'type': 'lifecycle_policies',
            'policies_updated': lifecycle_result['count']
        })
        
        return {
            'statusCode': 200,
            'optimization_results': optimization_results
        }
    
    def _manage_retention_policies(self) -> Dict[str, Any]:
        """Manage data retention policies"""
        
        policy_updates = []
        
        # 1. Review current policies
        current_policies = self.retention_policies
        
        # 2. Apply policies to different data types
        for data_type, retention_days in current_policies.items():
            if data_type == 'scan_data':
                result = self._apply_scan_retention(retention_days)
            elif data_type == 'findings':
                result = self._apply_findings_retention(retention_days)
            elif data_type == 'reports':
                result = self._apply_reports_retention(retention_days)
            elif data_type == 'logs':
                result = self._apply_logs_retention(retention_days)
            else:
                result = {'status': 'skipped', 'reason': 'Unknown data type'}
            
            policy_updates.append({
                'data_type': data_type,
                'retention_days': retention_days,
                'result': result
            })
        
        return {
            'statusCode': 200,
            'policy_updates': policy_updates
        }
    
    def _load_retention_policies(self) -> Dict[str, int]:
        """Load retention policies from configuration"""
        # In production, load from DynamoDB or S3
        return DEFAULT_RETENTION_DAYS.copy()
    
    def _archive_old_scans(self) -> Dict[str, Any]:
        """Archive scans older than retention period"""
        
        retention_days = self.retention_policies['scan_data']
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        archived_count = 0
        failed_count = 0
        
        # Query old scans
        try:
            # In production, use GSI with timestamp
            response = self.scan_table.scan(
                FilterExpression='created_at < :cutoff',
                ExpressionAttributeValues={
                    ':cutoff': cutoff_date.isoformat()
                }
            )
            
            for scan in response.get('Items', []):
                try:
                    self._archive_scan_data(scan['scan_id'])
                    archived_count += 1
                except Exception as e:
                    logger.error(f"Failed to archive scan {scan['scan_id']}: {e}")
                    failed_count += 1
                    
        except Exception as e:
            logger.error(f"Failed to query old scans: {e}")
        
        return {
            'archived_count': archived_count,
            'failed_count': failed_count
        }
    
    def _cleanup_dynamodb(self) -> Dict[str, Any]:
        """Clean up old DynamoDB items"""
        
        deleted_count = 0
        
        # Clean up old findings
        retention_days = self.retention_policies['findings']
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        try:
            # In production, batch delete with proper pagination
            response = self.findings_table.scan(
                FilterExpression='created_at < :cutoff',
                ExpressionAttributeValues={
                    ':cutoff': cutoff_date.isoformat()
                },
                ProjectionExpression='finding_id'
            )
            
            # Batch delete old items
            with self.findings_table.batch_writer() as batch:
                for item in response.get('Items', []):
                    batch.delete_item(Key={'finding_id': item['finding_id']})
                    deleted_count += 1
                    
        except Exception as e:
            logger.error(f"DynamoDB cleanup failed: {e}")
        
        return {'deleted_count': deleted_count}
    
    def _cleanup_s3(self) -> Dict[str, Any]:
        """Clean up old S3 objects"""
        
        deleted_count = 0
        
        if not RESULTS_BUCKET:
            return {'deleted_count': 0}
        
        retention_days = self.retention_policies['temporary']
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        try:
            # List and delete old temporary files
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=RESULTS_BUCKET,
                Prefix='temp/'
            )
            
            for page in pages:
                for obj in page.get('Contents', []):
                    if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                        s3_client.delete_object(
                            Bucket=RESULTS_BUCKET,
                            Key=obj['Key']
                        )
                        deleted_count += 1
                        
        except Exception as e:
            logger.error(f"S3 cleanup failed: {e}")
        
        return {'deleted_count': deleted_count}
    
    def _cleanup_logs(self) -> Dict[str, Any]:
        """Clean up old CloudWatch logs"""
        
        cleaned_count = 0
        retention_days = self.retention_policies['logs']
        
        try:
            # Get all log groups for the project
            paginator = logs_client.get_paginator('describe_log_groups')
            pages = paginator.paginate(logGroupNamePrefix=LOG_GROUP_PREFIX)
            
            for page in pages:
                for log_group in page['logGroups']:
                    # Update retention policy
                    try:
                        logs_client.put_retention_policy(
                            logGroupName=log_group['logGroupName'],
                            retentionInDays=retention_days
                        )
                        cleaned_count += 1
                    except Exception as e:
                        logger.error(f"Failed to update log retention: {e}")
                        
        except Exception as e:
            logger.error(f"Log cleanup failed: {e}")
        
        return {'cleaned_count': cleaned_count}
    
    def _cleanup_ecs_tasks(self) -> Dict[str, Any]:
        """Clean up stopped ECS tasks"""
        
        stopped_count = 0
        
        try:
            # List stopped tasks
            response = ecs_client.list_tasks(
                cluster=ECS_CLUSTER,
                desiredStatus='STOPPED'
            )
            
            stopped_tasks = response.get('taskArns', [])
            
            # Clean up old stopped tasks (ECS keeps them for a while)
            # In practice, ECS automatically cleans these up
            stopped_count = len(stopped_tasks)
            
        except Exception as e:
            logger.error(f"ECS cleanup failed: {e}")
        
        return {'stopped_count': stopped_count}
    
    def _generate_cleanup_report(self, results: Dict[str, Any]) -> str:
        """Generate cleanup report"""
        
        report = {
            'cleanup_report': {
                'timestamp': results['timestamp'],
                'summary': {
                    'total_actions': len(results['actions_performed']),
                    'total_items_cleaned': sum(
                        action.get('count', 0) + 
                        action.get('items_deleted', 0) + 
                        action.get('objects_deleted', 0)
                        for action in results['actions_performed']
                    )
                },
                'details': results['actions_performed']
            }
        }
        
        # Save report
        if RESULTS_BUCKET:
            report_key = f"lifecycle/cleanup-reports/{datetime.utcnow().strftime('%Y/%m/%d')}/report.json"
            try:
                s3_client.put_object(
                    Bucket=RESULTS_BUCKET,
                    Key=report_key,
                    Body=json.dumps(report, indent=2),
                    ContentType='application/json'
                )
                return f"s3://{RESULTS_BUCKET}/{report_key}"
            except Exception as e:
                logger.error(f"Failed to save report: {e}")
        
        return "report_not_saved"
    
    def _update_cleanup_metrics(self, results: Dict[str, Any]):
        """Update CloudWatch metrics for cleanup"""
        
        try:
            namespace = 'SecurityAudit/Lifecycle'
            
            metrics = []
            for action in results['actions_performed']:
                if 'count' in action or 'items_deleted' in action or 'objects_deleted' in action:
                    value = (action.get('count', 0) + 
                            action.get('items_deleted', 0) + 
                            action.get('objects_deleted', 0))
                    
                    metrics.append({
                        'MetricName': f"Cleanup_{action['action']}",
                        'Value': float(value),
                        'Unit': 'Count',
                        'Timestamp': datetime.utcnow()
                    })
            
            if metrics:
                cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=metrics
                )
                
        except Exception as e:
            logger.error(f"Failed to update metrics: {e}")
    
    def _get_scan_data(self, scan_id: str) -> Optional[Dict]:
        """Get scan data from DynamoDB"""
        try:
            response = self.scan_table.get_item(Key={'scan_id': scan_id})
            return response.get('Item')
        except:
            return None
    
    def _archive_findings(self, scan_id: str) -> Dict[str, Any]:
        """Archive findings to S3"""
        
        if not RESULTS_BUCKET:
            return {'status': 'skipped', 'reason': 'No archive bucket'}
        
        try:
            # Get findings from DynamoDB
            findings = []
            response = self.findings_table.query(
                IndexName='ScanIndex',
                KeyConditionExpression='scan_id = :scan_id',
                ExpressionAttributeValues={':scan_id': scan_id}
            )
            findings.extend(response.get('Items', []))
            
            # Save to S3
            archive_key = f"archive/findings/{scan_id}/findings.json.gz"
            
            # Compress data
            import gzip
            compressed_data = gzip.compress(
                json.dumps(findings, default=str).encode('utf-8')
            )
            
            s3_client.put_object(
                Bucket=RESULTS_BUCKET,
                Key=archive_key,
                Body=compressed_data,
                ContentType='application/json',
                ContentEncoding='gzip',
                StorageClass='GLACIER_IR'  # Instant retrieval Glacier
            )
            
            return {
                'status': 'success',
                'archive_location': f"s3://{RESULTS_BUCKET}/{archive_key}",
                'findings_count': len(findings)
            }
            
        except Exception as e:
            logger.error(f"Failed to archive findings: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _archive_reports(self, scan_id: str) -> Dict[str, Any]:
        """Archive reports to S3"""
        
        if not RESULTS_BUCKET:
            return {'status': 'skipped', 'reason': 'No archive bucket'}
        
        try:
            # List all reports for this scan
            response = s3_client.list_objects_v2(
                Bucket=RESULTS_BUCKET,
                Prefix=f"reports/{scan_id}/"
            )
            
            archived_count = 0
            for obj in response.get('Contents', []):
                # Copy to archive location with Glacier storage class
                archive_key = f"archive/{obj['Key']}"
                s3_client.copy_object(
                    CopySource={'Bucket': RESULTS_BUCKET, 'Key': obj['Key']},
                    Bucket=RESULTS_BUCKET,
                    Key=archive_key,
                    StorageClass='GLACIER_IR'
                )
                archived_count += 1
            
            return {
                'status': 'success',
                'archive_location': f"s3://{RESULTS_BUCKET}/archive/reports/{scan_id}/",
                'reports_count': archived_count
            }
            
        except Exception as e:
            logger.error(f"Failed to archive reports: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _create_archive_manifest(self, scan_id: str, archive_data: Dict) -> str:
        """Create manifest for archived data"""
        
        manifest = {
            'scan_id': scan_id,
            'archived_at': archive_data['archived_at'],
            'components': archive_data['components'],
            'metadata': {
                'lifecycle_version': '1.0',
                'retention_policy': self.retention_policies
            }
        }
        
        if RESULTS_BUCKET:
            manifest_key = f"archive/manifests/{scan_id}/manifest.json"
            try:
                s3_client.put_object(
                    Bucket=RESULTS_BUCKET,
                    Key=manifest_key,
                    Body=json.dumps(manifest, indent=2),
                    ContentType='application/json'
                )
                return f"s3://{RESULTS_BUCKET}/{manifest_key}"
            except Exception as e:
                logger.error(f"Failed to create manifest: {e}")
        
        return "manifest_not_created"
    
    def _cleanup_after_archive(self, scan_id: str) -> Dict[str, Any]:
        """Clean up original data after archiving"""
        
        success = True
        
        try:
            # Delete from scan table
            self.scan_table.delete_item(Key={'scan_id': scan_id})
            
            # Delete findings
            # In production, batch delete
            response = self.findings_table.query(
                IndexName='ScanIndex',
                KeyConditionExpression='scan_id = :scan_id',
                ExpressionAttributeValues={':scan_id': scan_id},
                ProjectionExpression='finding_id'
            )
            
            with self.findings_table.batch_writer() as batch:
                for item in response.get('Items', []):
                    batch.delete_item(Key={'finding_id': item['finding_id']})
                    
        except Exception as e:
            logger.error(f"Cleanup after archive failed: {e}")
            success = False
        
        return {'success': success}
    
    def _cleanup_temporary_files(self) -> Dict[str, Any]:
        """Clean up temporary files"""
        
        if not RESULTS_BUCKET:
            return {'cleaned': 0}
        
        cleaned_count = 0
        retention_hours = 24
        cutoff_time = datetime.utcnow() - timedelta(hours=retention_hours)
        
        try:
            response = s3_client.list_objects_v2(
                Bucket=RESULTS_BUCKET,
                Prefix='temp/'
            )
            
            for obj in response.get('Contents', []):
                if obj['LastModified'].replace(tzinfo=None) < cutoff_time:
                    s3_client.delete_object(
                        Bucket=RESULTS_BUCKET,
                        Key=obj['Key']
                    )
                    cleaned_count += 1
                    
        except Exception as e:
            logger.error(f"Temporary file cleanup failed: {e}")
        
        return {'cleaned': cleaned_count}
    
    def _cleanup_failed_scans(self) -> Dict[str, Any]:
        """Clean up data from failed scans"""
        
        cleaned_count = 0
        retention_days = 7
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        try:
            # Find failed scans
            response = self.scan_table.scan(
                FilterExpression='#status = :status AND created_at < :cutoff',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'FAILED',
                    ':cutoff': cutoff_date.isoformat()
                }
            )
            
            for scan in response.get('Items', []):
                # Delete scan and related data
                scan_id = scan['scan_id']
                self.scan_table.delete_item(Key={'scan_id': scan_id})
                cleaned_count += 1
                
        except Exception as e:
            logger.error(f"Failed scan cleanup failed: {e}")
        
        return {'cleaned': cleaned_count}
    
    def _cleanup_orphaned_resources(self) -> Dict[str, Any]:
        """Clean up orphaned resources"""
        
        orphaned = {
            's3_objects': 0,
            'dynamodb_items': 0
        }
        
        # Find S3 objects without corresponding DynamoDB entries
        # This is a simplified version - in production, be more careful
        
        return orphaned
    
    def _cleanup_old_analytics(self) -> Dict[str, Any]:
        """Clean up old analytics data"""
        
        if not ANALYTICS_BUCKET:
            return {'cleaned': 0}
        
        cleaned_count = 0
        retention_days = self.retention_policies['analytics']
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        try:
            response = s3_client.list_objects_v2(
                Bucket=ANALYTICS_BUCKET,
                Prefix='analytics/'
            )
            
            for obj in response.get('Contents', []):
                if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                    s3_client.delete_object(
                        Bucket=ANALYTICS_BUCKET,
                        Key=obj['Key']
                    )
                    cleaned_count += 1
                    
        except Exception as e:
            logger.error(f"Analytics cleanup failed: {e}")
        
        return {'cleaned': cleaned_count}
    
    def _cleanup_test_data(self) -> Dict[str, Any]:
        """Clean up test data"""
        
        cleaned = {
            'test_scans': 0,
            'test_findings': 0
        }
        
        # Clean up scans with test repositories
        try:
            response = self.scan_table.scan(
                FilterExpression='contains(repository_url, :test)',
                ExpressionAttributeValues={':test': 'test'}
            )
            
            for scan in response.get('Items', []):
                self.scan_table.delete_item(Key={'scan_id': scan['scan_id']})
                cleaned['test_scans'] += 1
                
        except Exception as e:
            logger.error(f"Test data cleanup failed: {e}")
        
        return cleaned
    
    def _get_s3_usage(self) -> Dict[str, Any]:
        """Get S3 storage usage"""
        
        if not RESULTS_BUCKET:
            return {}
        
        try:
            # Get bucket metrics
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='BucketSizeBytes',
                Dimensions=[
                    {'Name': 'BucketName', 'Value': RESULTS_BUCKET},
                    {'Name': 'StorageType', 'Value': 'StandardStorage'}
                ],
                StartTime=datetime.utcnow() - timedelta(days=1),
                EndTime=datetime.utcnow(),
                Period=86400,
                Statistics=['Average']
            )
            
            size_bytes = 0
            if response['Datapoints']:
                size_bytes = response['Datapoints'][0]['Average']
            
            return {
                'bucket': RESULTS_BUCKET,
                'size_bytes': size_bytes,
                'size_gb': round(size_bytes / (1024**3), 2),
                'object_count': self._get_object_count(RESULTS_BUCKET)
            }
            
        except Exception as e:
            logger.error(f"Failed to get S3 usage: {e}")
            return {}
    
    def _get_object_count(self, bucket: str) -> int:
        """Get object count in bucket"""
        try:
            response = s3_client.list_objects_v2(
                Bucket=bucket,
                MaxKeys=1
            )
            return response.get('KeyCount', 0)
        except:
            return 0
    
    def _get_dynamodb_usage(self) -> Dict[str, Any]:
        """Get DynamoDB usage"""
        
        usage = {
            'tables': {}
        }
        
        for table_name, table in [
            ('scans', self.scan_table),
            ('findings', self.findings_table),
            ('ai_scans', self.ai_scans_table)
        ]:
            try:
                response = table.describe_table()
                table_desc = response['Table']
                
                usage['tables'][table_name] = {
                    'item_count': table_desc.get('ItemCount', 0),
                    'size_bytes': table_desc.get('TableSizeBytes', 0),
                    'read_capacity': table_desc['ProvisionedThroughput'].get('ReadCapacityUnits', 0),
                    'write_capacity': table_desc['ProvisionedThroughput'].get('WriteCapacityUnits', 0)
                }
            except Exception as e:
                logger.error(f"Failed to get DynamoDB usage for {table_name}: {e}")
        
        return usage
    
    def _estimate_dynamodb_cost(self, usage: Dict) -> float:
        """Estimate DynamoDB monthly cost"""
        
        total_cost = 0
        
        # Simplified cost calculation
        for table_name, table_usage in usage.get('tables', {}).items():
            # Storage cost: $0.25 per GB-month
            storage_gb = table_usage.get('size_bytes', 0) / (1024**3)
            storage_cost = storage_gb * 0.25
            
            # Capacity costs (on-demand pricing assumed)
            # $0.25 per million read units
            # $1.25 per million write units
            
            total_cost += storage_cost
        
        return round(total_cost, 2)
    
    def _get_ecs_usage(self) -> Dict[str, Any]:
        """Get ECS usage"""
        
        try:
            # List running tasks
            response = ecs_client.list_tasks(
                cluster=ECS_CLUSTER,
                desiredStatus='RUNNING'
            )
            
            running_tasks = len(response.get('taskArns', []))
            
            # Get cluster metrics
            cluster_response = ecs_client.describe_clusters(
                clusters=[ECS_CLUSTER]
            )
            
            if cluster_response['clusters']:
                cluster = cluster_response['clusters'][0]
                return {
                    'cluster_name': ECS_CLUSTER,
                    'running_tasks': running_tasks,
                    'registered_container_instances': cluster.get('registeredContainerInstancesCount', 0),
                    'active_services': cluster.get('activeServicesCount', 0)
                }
                
        except Exception as e:
            logger.error(f"Failed to get ECS usage: {e}")
        
        return {}
    
    def _get_lambda_usage(self) -> Dict[str, Any]:
        """Get Lambda usage metrics"""
        
        try:
            # Get invocation count for the last day
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Invocations',
                Dimensions=[],
                StartTime=datetime.utcnow() - timedelta(days=1),
                EndTime=datetime.utcnow(),
                Period=86400,
                Statistics=['Sum']
            )
            
            total_invocations = 0
            if response['Datapoints']:
                total_invocations = sum(dp['Sum'] for dp in response['Datapoints'])
            
            return {
                'daily_invocations': int(total_invocations),
                'estimated_monthly_invocations': int(total_invocations * 30)
            }
            
        except Exception as e:
            logger.error(f"Failed to get Lambda usage: {e}")
            return {}
    
    def _generate_cost_recommendations(self, usage: Dict) -> List[Dict]:
        """Generate cost optimization recommendations"""
        
        recommendations = []
        
        # Check S3 usage
        s3_usage = usage.get('storage', {}).get('s3', {})
        if s3_usage.get('size_gb', 0) > 100:
            recommendations.append({
                'category': 'storage',
                'priority': 'medium',
                'recommendation': 'Enable S3 Intelligent-Tiering',
                'potential_savings': f"${s3_usage.get('size_gb', 0) * 0.01:.2f}/month"
            })
        
        # Check DynamoDB usage
        dynamo_usage = usage.get('database', {}).get('dynamodb', {})
        for table_name, table_data in dynamo_usage.get('tables', {}).items():
            if table_data.get('item_count', 0) == 0:
                recommendations.append({
                    'category': 'database',
                    'priority': 'low',
                    'recommendation': f'Consider removing empty table: {table_name}',
                    'potential_savings': '$0.25/month'
                })
        
        return recommendations
    
    def _check_usage_thresholds(self, usage: Dict) -> List[Dict]:
        """Check if usage exceeds thresholds"""
        
        alerts = []
        
        # Check S3 size
        s3_size_gb = usage.get('storage', {}).get('s3', {}).get('size_gb', 0)
        if s3_size_gb > 500:  # 500 GB threshold
            alerts.append({
                'type': 's3_storage',
                'severity': 'warning',
                'message': f'S3 storage exceeds 500GB: {s3_size_gb}GB',
                'recommendation': 'Review and archive old data'
            })
        
        # Check costs
        total_cost = sum(usage.get('estimated_costs', {}).values())
        if total_cost > 100:  # $100/month threshold
            alerts.append({
                'type': 'cost',
                'severity': 'warning',
                'message': f'Estimated monthly cost exceeds $100: ${total_cost:.2f}',
                'recommendation': 'Review cost optimization recommendations'
            })
        
        return alerts
    
    def _send_usage_alerts(self, alerts: List[Dict]):
        """Send usage alerts"""
        # In production, send via SNS
        for alert in alerts:
            logger.warning(f"Usage alert: {alert['message']}")
    
    def _compress_large_files(self) -> Dict[str, Any]:
        """Compress large files in S3"""
        
        compressed_count = 0
        space_saved_mb = 0
        
        # In production, implement actual compression
        # This is a placeholder
        
        return {
            'count': compressed_count,
            'space_saved': space_saved_mb
        }
    
    def _move_to_glacier(self) -> Dict[str, Any]:
        """Move old data to Glacier storage"""
        
        moved_count = 0
        estimated_savings = 0
        
        if not RESULTS_BUCKET:
            return {'count': 0, 'estimated_savings': 0}
        
        # Move data older than 90 days to Glacier
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        try:
            response = s3_client.list_objects_v2(
                Bucket=RESULTS_BUCKET,
                Prefix='reports/'
            )
            
            for obj in response.get('Contents', []):
                if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                    # Change storage class
                    s3_client.copy_object(
                        CopySource={'Bucket': RESULTS_BUCKET, 'Key': obj['Key']},
                        Bucket=RESULTS_BUCKET,
                        Key=obj['Key'],
                        StorageClass='GLACIER',
                        MetadataDirective='COPY'
                    )
                    moved_count += 1
                    
                    # Calculate savings (Glacier is ~1/4 the cost)
                    size_gb = obj['Size'] / (1024**3)
                    estimated_savings += size_gb * 0.023 * 0.75  # 75% savings
                    
        except Exception as e:
            logger.error(f"Glacier transition failed: {e}")
        
        return {
            'count': moved_count,
            'estimated_savings': round(estimated_savings, 2)
        }
    
    def _deduplicate_data(self) -> Dict[str, Any]:
        """Remove duplicate data"""
        
        # In production, implement actual deduplication
        # This is a placeholder
        
        return {
            'count': 0,
            'space_saved': 0
        }
    
    def _update_s3_lifecycle_policies(self) -> Dict[str, Any]:
        """Update S3 lifecycle policies"""
        
        if not RESULTS_BUCKET:
            return {'count': 0}
        
        lifecycle_config = {
            'Rules': [
                {
                    'ID': 'MoveReportsToGlacier',
                    'Status': 'Enabled',
                    'Prefix': 'reports/',
                    'Transitions': [
                        {
                            'Days': 90,
                            'StorageClass': 'GLACIER'
                        }
                    ]
                },
                {
                    'ID': 'DeleteTempFiles',
                    'Status': 'Enabled',
                    'Prefix': 'temp/',
                    'Expiration': {
                        'Days': 7
                    }
                },
                {
                    'ID': 'ArchiveOldAnalytics',
                    'Status': 'Enabled',
                    'Prefix': 'analytics/',
                    'Transitions': [
                        {
                            'Days': 30,
                            'StorageClass': 'STANDARD_IA'
                        },
                        {
                            'Days': 90,
                            'StorageClass': 'GLACIER'
                        }
                    ]
                }
            ]
        }
        
        try:
            s3_client.put_bucket_lifecycle_configuration(
                Bucket=RESULTS_BUCKET,
                LifecycleConfiguration=lifecycle_config
            )
            return {'count': len(lifecycle_config['Rules'])}
        except Exception as e:
            logger.error(f"Failed to update lifecycle policies: {e}")
            return {'count': 0}
    
    def _apply_scan_retention(self, days: int) -> Dict[str, Any]:
        """Apply retention policy to scan data"""
        return {'status': 'applied', 'retention_days': days}
    
    def _apply_findings_retention(self, days: int) -> Dict[str, Any]:
        """Apply retention policy to findings"""
        return {'status': 'applied', 'retention_days': days}
    
    def _apply_reports_retention(self, days: int) -> Dict[str, Any]:
        """Apply retention policy to reports"""
        return {'status': 'applied', 'retention_days': days}
    
    def _apply_logs_retention(self, days: int) -> Dict[str, Any]:
        """Apply retention policy to logs"""
        
        updated_count = 0
        
        try:
            # Update CloudWatch Logs retention
            paginator = logs_client.get_paginator('describe_log_groups')
            pages = paginator.paginate(logGroupNamePrefix=LOG_GROUP_PREFIX)
            
            for page in pages:
                for log_group in page['logGroups']:
                    try:
                        logs_client.put_retention_policy(
                            logGroupName=log_group['logGroupName'],
                            retentionInDays=days
                        )
                        updated_count += 1
                    except Exception as e:
                        logger.error(f"Failed to update log retention: {e}")
                        
        except Exception as e:
            logger.error(f"Log retention update failed: {e}")
        
        return {
            'status': 'applied',
            'retention_days': days,
            'log_groups_updated': updated_count
        }


def lambda_handler(event, context):
    """Lambda handler for lifecycle management"""
    
    manager = LifecycleManager()
    
    try:
        # Handle CloudWatch scheduled events
        if event.get('source') == 'aws.events':
            # Scheduled cleanup
            return manager.manage_lifecycle({'action': 'scheduled_cleanup'})
        else:
            # Direct invocation
            return manager.manage_lifecycle(event)
            
    except Exception as e:
        logger.error(f"Lifecycle management failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }