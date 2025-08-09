"""
S3 Lifecycle Manager Lambda - Dynamic tagging based on scan results
"""
import os
import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Environment variables
RESULTS_BUCKET = os.environ['RESULTS_BUCKET']
SCAN_TABLE = os.environ['SCAN_TABLE']


class LifecycleManager:
    """Manages S3 object lifecycle based on scan results and priorities"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(SCAN_TABLE)
        self.results_bucket = RESULTS_BUCKET
        
    def handle_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process lifecycle management event
        Can be triggered by:
        1. CloudWatch Events (scheduled)
        2. S3 Event (new object created)
        3. Direct invocation after scan completion
        """
        try:
            event_source = event.get('source', 'direct')
            
            if event_source == 'aws.s3':
                # Process new S3 object
                return self._process_s3_event(event)
            elif event_source == 'aws.events':
                # Scheduled run to review and update tags
                return self._process_scheduled_event(event)
            else:
                # Direct invocation - process specific scan
                scan_id = event.get('scan_id')
                if scan_id:
                    return self._process_scan_lifecycle(scan_id)
                else:
                    return self._process_all_recent_scans()
                    
        except Exception as e:
            logger.error(f"Lifecycle management failed: {str(e)}", exc_info=True)
            return {
                'statusCode': 500,
                'error': str(e)
            }
    
    def _process_s3_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process S3 object creation event"""
        processed_objects = []
        
        for record in event.get('Records', []):
            if record['eventName'].startswith('ObjectCreated'):
                bucket = record['s3']['bucket']['name']
                key = record['s3']['object']['key']
                
                # Extract scan_id from key
                # Expected format: raw/{scan_id}/agent_type/results.json
                parts = key.split('/')
                if len(parts) >= 3 and parts[0] == 'raw':
                    scan_id = parts[1]
                    
                    # Get scan metadata
                    scan_data = self._get_scan_metadata(scan_id)
                    if scan_data:
                        # Apply tags based on scan priority and results
                        tags = self._determine_object_tags(scan_data, key)
                        self._apply_object_tags(bucket, key, tags)
                        processed_objects.append({
                            'key': key,
                            'tags': tags
                        })
        
        return {
            'statusCode': 200,
            'processed': len(processed_objects),
            'objects': processed_objects
        }
    
    def _process_scheduled_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process scheduled lifecycle review"""
        # Review recent scans and update tags as needed
        days_to_review = event.get('days', 7)
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_review)
        
        # Query recent scans
        response = self.scan_table.scan(
            FilterExpression='created_at > :cutoff',
            ExpressionAttributeValues={
                ':cutoff': cutoff_date.isoformat()
            }
        )
        
        processed_count = 0
        for scan in response.get('Items', []):
            self._update_scan_object_tags(scan)
            processed_count += 1
        
        return {
            'statusCode': 200,
            'reviewed_scans': processed_count,
            'cutoff_date': cutoff_date.isoformat()
        }
    
    def _process_scan_lifecycle(self, scan_id: str) -> Dict[str, Any]:
        """Process lifecycle for a specific scan"""
        scan_data = self._get_scan_metadata(scan_id)
        
        if not scan_data:
            return {
                'statusCode': 404,
                'error': f'Scan {scan_id} not found'
            }
        
        # List all objects for this scan
        prefix = f"raw/{scan_id}/"
        objects = self._list_scan_objects(prefix)
        
        # Apply appropriate tags to each object
        tagged_objects = []
        for obj in objects:
            tags = self._determine_object_tags(scan_data, obj['Key'])
            self._apply_object_tags(self.results_bucket, obj['Key'], tags)
            tagged_objects.append({
                'key': obj['Key'],
                'size': obj['Size'],
                'tags': tags
            })
        
        # Also tag processed reports if they exist
        processed_prefix = f"processed/{scan_id}/"
        processed_objects = self._list_scan_objects(processed_prefix)
        
        for obj in processed_objects:
            tags = {
                'Type': 'processed',
                'Priority': scan_data.get('priority', 'normal'),
                'ScanId': scan_id
            }
            self._apply_object_tags(self.results_bucket, obj['Key'], tags)
        
        return {
            'statusCode': 200,
            'scan_id': scan_id,
            'tagged_raw_objects': len(tagged_objects),
            'tagged_processed_objects': len(processed_objects),
            'total_size_bytes': sum(obj['size'] for obj in tagged_objects)
        }
    
    def _process_all_recent_scans(self) -> Dict[str, Any]:
        """Process all recent scans without specific tags"""
        # Find objects without proper lifecycle tags
        untagged_objects = self._find_untagged_objects()
        
        processed_count = 0
        for obj_key in untagged_objects:
            # Extract scan_id from key
            parts = obj_key.split('/')
            if len(parts) >= 2:
                scan_id = parts[1]
                scan_data = self._get_scan_metadata(scan_id)
                
                if scan_data:
                    tags = self._determine_object_tags(scan_data, obj_key)
                    self._apply_object_tags(self.results_bucket, obj_key, tags)
                    processed_count += 1
        
        return {
            'statusCode': 200,
            'processed_objects': processed_count,
            'untagged_found': len(untagged_objects)
        }
    
    def _get_scan_metadata(self, scan_id: str) -> Dict[str, Any]:
        """Get scan metadata from DynamoDB"""
        try:
            response = self.scan_table.get_item(Key={'scan_id': scan_id})
            return response.get('Item', {})
        except Exception as e:
            logger.error(f"Failed to get scan metadata: {e}")
            return {}
    
    def _determine_object_tags(self, scan_data: Dict[str, Any], object_key: str) -> Dict[str, str]:
        """Determine appropriate tags based on scan data and object type"""
        tags = {
            'ScanId': scan_data.get('scan_id', ''),
            'Priority': scan_data.get('priority', 'normal'),
            'CreatedAt': scan_data.get('created_at', datetime.utcnow().isoformat()),
            'Repository': scan_data.get('repository_url', '').replace('/', '_')
        }
        
        # Determine type based on path
        if '/sast/' in object_key:
            tags['Type'] = 'sast'
        elif '/secrets/' in object_key:
            tags['Type'] = 'secrets'
        elif '/dependency/' in object_key:
            tags['Type'] = 'dependency'
        elif '/iac/' in object_key:
            tags['Type'] = 'iac'
        elif '/error' in object_key:
            tags['Type'] = 'error'
        else:
            tags['Type'] = 'other'
        
        # Check execution plan for critical findings
        execution_plan = json.loads(scan_data.get('execution_plan', '{}'))
        
        # Analyze findings if available
        total_findings = scan_data.get('total_findings', {})
        critical_findings = total_findings.get('critical', 0)
        high_findings = total_findings.get('high', 0)
        
        # Set finding severity tag
        if critical_findings > 0:
            tags['FindingSeverity'] = 'critical'
        elif high_findings > 0:
            tags['FindingSeverity'] = 'high'
        elif total_findings.get('medium', 0) > 0:
            tags['FindingSeverity'] = 'medium'
        else:
            tags['FindingSeverity'] = 'low'
        
        # Add compliance tag if available
        if scan_data.get('compliance_status'):
            tags['ComplianceStatus'] = scan_data['compliance_status']
        
        # Add cost tag if available
        if execution_plan.get('total_estimated_cost'):
            tags['EstimatedCost'] = str(execution_plan['total_estimated_cost'])
        
        return tags
    
    def _apply_object_tags(self, bucket: str, key: str, tags: Dict[str, str]) -> None:
        """Apply tags to S3 object"""
        try:
            tag_set = [{'Key': k, 'Value': v} for k, v in tags.items() if v]
            
            s3_client.put_object_tagging(
                Bucket=bucket,
                Key=key,
                Tagging={'TagSet': tag_set}
            )
            
            logger.info(f"Applied {len(tag_set)} tags to {bucket}/{key}")
            
        except Exception as e:
            logger.error(f"Failed to tag object {bucket}/{key}: {e}")
    
    def _list_scan_objects(self, prefix: str) -> List[Dict[str, Any]]:
        """List all objects for a scan"""
        objects = []
        
        try:
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.results_bucket,
                Prefix=prefix
            )
            
            for page in pages:
                for obj in page.get('Contents', []):
                    objects.append({
                        'Key': obj['Key'],
                        'Size': obj['Size'],
                        'LastModified': obj['LastModified'].isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"Failed to list objects with prefix {prefix}: {e}")
        
        return objects
    
    def _find_untagged_objects(self) -> List[str]:
        """Find objects without lifecycle tags"""
        untagged = []
        
        try:
            # List recent objects
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.results_bucket,
                Prefix='raw/'
            )
            
            for page in pages:
                for obj in page.get('Contents', []):
                    # Check if object has tags
                    try:
                        response = s3_client.get_object_tagging(
                            Bucket=self.results_bucket,
                            Key=obj['Key']
                        )
                        
                        tags = {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
                        
                        # Check if essential tags are present
                        if 'Priority' not in tags or 'FindingSeverity' not in tags:
                            untagged.append(obj['Key'])
                            
                    except Exception as e:
                        logger.warning(f"Failed to get tags for {obj['Key']}: {e}")
                        untagged.append(obj['Key'])
                        
        except Exception as e:
            logger.error(f"Failed to find untagged objects: {e}")
        
        return untagged[:100]  # Limit to 100 objects per run
    
    def _update_scan_object_tags(self, scan_data: Dict[str, Any]) -> None:
        """Update tags for all objects in a scan based on latest metadata"""
        scan_id = scan_data.get('scan_id')
        if not scan_id:
            return
        
        # List all objects for this scan
        prefix = f"raw/{scan_id}/"
        objects = self._list_scan_objects(prefix)
        
        for obj in objects:
            # Get current tags
            try:
                response = s3_client.get_object_tagging(
                    Bucket=self.results_bucket,
                    Key=obj['Key']
                )
                
                current_tags = {tag['Key']: tag['Value'] for tag in response.get('TagSet', [])}
                
                # Determine new tags
                new_tags = self._determine_object_tags(scan_data, obj['Key'])
                
                # Only update if tags have changed
                if current_tags != new_tags:
                    self._apply_object_tags(self.results_bucket, obj['Key'], new_tags)
                    
            except Exception as e:
                logger.error(f"Failed to update tags for {obj['Key']}: {e}")


def lambda_handler(event, context):
    """AWS Lambda handler function"""
    manager = LifecycleManager()
    return manager.handle_event(event)