"""
ECR Scanning Enabler Lambda - Enables vulnerability scanning on ECR repositories
"""
import json
import logging
import boto3
from typing import Dict, Any, List

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ecr_client = boto3.client('ecr')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Process ECR events to enable scanning on repositories
    
    This function handles:
    1. New image pushes - triggers vulnerability scans
    2. New repository creation - enables scan-on-push
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Determine event type
        detail_type = event.get('detail-type', '')
        
        if detail_type == 'ECR Image Action':
            # Handle image push events
            return handle_image_push(event)
        elif detail_type == 'AWS API Call via CloudTrail':
            # Handle repository creation events
            return handle_repository_creation(event)
        else:
            logger.warning(f"Unknown event type: {detail_type}")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Event type not handled'})
            }
            
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def handle_image_push(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle ECR image push events"""
    detail = event.get('detail', {})
    repository_name = detail.get('repository-name')
    image_digest = detail.get('image-digest')
    image_tags = detail.get('image-tags', [])
    
    if not repository_name:
        logger.error("Repository name not found in event")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Repository name not found'})
        }
    
    logger.info(f"Processing image push for repository: {repository_name}")
    logger.info(f"Image digest: {image_digest}")
    logger.info(f"Image tags: {image_tags}")
    
    # Start vulnerability scan
    scan_results = []
    if image_digest:
        try:
            response = ecr_client.start_image_scan(
                repositoryName=repository_name,
                imageId={
                    'imageDigest': image_digest
                }
            )
            scan_results.append({
                'digest': image_digest,
                'status': response['imageScanStatus']['status']
            })
            logger.info(f"Started scan for image {image_digest}")
        except ecr_client.exceptions.ImageNotFoundException:
            logger.warning(f"Image not found: {image_digest}")
        except Exception as e:
            logger.error(f"Error starting scan for {image_digest}: {str(e)}")
    
    # Also scan by tags if available
    for tag in image_tags[:5]:  # Limit to 5 tags to avoid throttling
        try:
            response = ecr_client.start_image_scan(
                repositoryName=repository_name,
                imageId={
                    'imageTag': tag
                }
            )
            scan_results.append({
                'tag': tag,
                'status': response['imageScanStatus']['status']
            })
            logger.info(f"Started scan for image with tag {tag}")
        except ecr_client.exceptions.ImageNotFoundException:
            logger.warning(f"Image not found with tag: {tag}")
        except ecr_client.exceptions.UnsupportedImageTypeException:
            logger.warning(f"Unsupported image type for tag: {tag}")
        except Exception as e:
            logger.error(f"Error starting scan for tag {tag}: {str(e)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Image scans initiated',
            'repository': repository_name,
            'scanResults': scan_results
        })
    }


def handle_repository_creation(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle repository creation events"""
    detail = event.get('detail', {})
    event_name = detail.get('eventName')
    
    if event_name != 'CreateRepository':
        logger.info(f"Ignoring non-creation event: {event_name}")
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Not a repository creation event'})
        }
    
    # Extract repository name from response elements
    response_elements = detail.get('responseElements', {})
    repository = response_elements.get('repository', {})
    repository_name = repository.get('repositoryName')
    
    if not repository_name:
        # Try to get from request parameters
        request_params = detail.get('requestParameters', {})
        repository_name = request_params.get('repositoryName')
    
    if not repository_name:
        logger.error("Could not extract repository name from event")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Repository name not found'})
        }
    
    logger.info(f"Enabling scan-on-push for repository: {repository_name}")
    
    try:
        # Enable scan-on-push for the repository
        ecr_client.put_image_scanning_configuration(
            repositoryName=repository_name,
            imageScanningConfiguration={
                'scanOnPush': True
            }
        )
        logger.info(f"Successfully enabled scan-on-push for {repository_name}")
        
        # Also set lifecycle policy for automatic cleanup
        lifecycle_policy = {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "Keep last 10 images",
                    "selection": {
                        "tagStatus": "any",
                        "countType": "imageCountMoreThan",
                        "countNumber": 10
                    },
                    "action": {
                        "type": "expire"
                    }
                },
                {
                    "rulePriority": 2,
                    "description": "Expire untagged images after 7 days",
                    "selection": {
                        "tagStatus": "untagged",
                        "countType": "sinceImagePushed",
                        "countUnit": "days",
                        "countNumber": 7
                    },
                    "action": {
                        "type": "expire"
                    }
                }
            ]
        }
        
        ecr_client.put_lifecycle_policy(
            repositoryName=repository_name,
            lifecyclePolicyText=json.dumps(lifecycle_policy)
        )
        logger.info(f"Set lifecycle policy for {repository_name}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Repository configuration updated',
                'repository': repository_name,
                'scanOnPush': True,
                'lifecyclePolicy': 'applied'
            })
        }
        
    except Exception as e:
        logger.error(f"Error configuring repository {repository_name}: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'repository': repository_name
            })
        }


def get_scan_findings_summary(repository_name: str, image_digest: str) -> Dict[str, Any]:
    """Get scan findings summary for an image"""
    try:
        response = ecr_client.describe_image_scan_findings(
            repositoryName=repository_name,
            imageId={
                'imageDigest': image_digest
            },
            maxResults=1000
        )
        
        findings = response.get('imageScanFindings', {})
        finding_counts = findings.get('findingSeverityCounts', {})
        
        return {
            'scanStatus': response.get('imageScanStatus', {}).get('status'),
            'findingSeverityCounts': finding_counts,
            'vulnerabilitySourceUpdatedAt': str(findings.get('vulnerabilitySourceUpdatedAt', ''))
        }
        
    except Exception as e:
        logger.error(f"Error getting scan findings: {str(e)}")
        return {
            'error': str(e)
        }