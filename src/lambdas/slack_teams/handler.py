"""
Slack/Teams Lambda - Send notifications to Slack or Microsoft Teams
"""
import json
import os
import boto3
import urllib3
from datetime import datetime
from typing import Dict, List, Any, Optional


http = urllib3.PoolManager()
ssm_client = boto3.client('ssm')


def handler(event, context):
    """
    Send security scan notifications to Slack or Teams
    
    Args:
        event: Lambda event containing notification details
        context: Lambda context
        
    Returns:
        Notification status
    """
    try:
        # Extract notification details
        notification_type = event.get('type', 'scan_complete')
        scan_id = event.get('scan_id')
        findings_summary = event.get('findings_summary', {})
        repository = event.get('repository', 'Unknown')
        channel = event.get('channel', 'slack')  # 'slack' or 'teams'
        
        # Get webhook URL from SSM Parameter Store
        webhook_url = get_webhook_url(channel)
        
        if not webhook_url:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'No webhook URL configured for {channel}'})
            }
        
        # Create message based on channel
        if channel == 'slack':
            message = create_slack_message(
                notification_type, scan_id, repository, findings_summary
            )
        else:  # teams
            message = create_teams_message(
                notification_type, scan_id, repository, findings_summary
            )
        
        # Send notification
        response = send_notification(webhook_url, message)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'channel': channel,
                'notification_sent': True,
                'response': response
            })
        }
        
    except Exception as e:
        print(f"Error sending notification: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def get_webhook_url(channel: str) -> Optional[str]:
    """Get webhook URL from SSM Parameter Store"""
    try:
        parameter_name = f"/security-audit/{channel}-webhook-url"
        response = ssm_client.get_parameter(
            Name=parameter_name,
            WithDecryption=True
        )
        return response['Parameter']['Value']
    except ssm_client.exceptions.ParameterNotFound:
        print(f"Webhook URL not found for {channel}")
        return None
    except Exception as e:
        print(f"Error getting webhook URL: {str(e)}")
        return None


def create_slack_message(notification_type: str, scan_id: str, 
                        repository: str, findings_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Create Slack message format"""
    
    # Determine emoji and color based on severity
    total_findings = findings_summary.get('total_findings', 0)
    critical_findings = findings_summary.get('critical_findings', 0)
    high_findings = findings_summary.get('high_findings', 0)
    
    if critical_findings > 0:
        emoji = "🚨"
        color = "danger"
    elif high_findings > 0:
        emoji = "⚠️"
        color = "warning"
    elif total_findings > 0:
        emoji = "ℹ️"
        color = "good"
    else:
        emoji = "✅"
        color = "good"
    
    # Build message
    message = {
        "attachments": [{
            "color": color,
            "pretext": f"{emoji} Security Scan {notification_type.replace('_', ' ').title()}",
            "title": f"Repository: {repository}",
            "title_link": f"https://console.aws.amazon.com/securityaudit/scan/{scan_id}",
            "fields": [
                {
                    "title": "Scan ID",
                    "value": scan_id,
                    "short": True
                },
                {
                    "title": "Total Findings",
                    "value": str(total_findings),
                    "short": True
                },
                {
                    "title": "Critical",
                    "value": str(critical_findings),
                    "short": True
                },
                {
                    "title": "High",
                    "value": str(high_findings),
                    "short": True
                },
                {
                    "title": "Business Risk Score",
                    "value": f"{findings_summary.get('business_risk_score', 0):.1f}/100",
                    "short": True
                },
                {
                    "title": "AI Confidence",
                    "value": f"{findings_summary.get('ai_confidence_score', 0):.1%}",
                    "short": True
                }
            ],
            "footer": "AI Security Audit Framework",
            "footer_icon": "https://example.com/security-icon.png",
            "ts": int(datetime.utcnow().timestamp())
        }]
    }
    
    # Add action buttons if critical findings
    if critical_findings > 0:
        message["attachments"][0]["actions"] = [
            {
                "type": "button",
                "text": "View Report",
                "url": f"https://console.aws.amazon.com/securityaudit/report/{scan_id}"
            },
            {
                "type": "button",
                "text": "Create Ticket",
                "url": f"https://jira.example.com/create?scan_id={scan_id}",
                "style": "danger"
            }
        ]
    
    return message


def create_teams_message(notification_type: str, scan_id: str,
                        repository: str, findings_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Create Microsoft Teams message format"""
    
    # Determine theme color based on severity
    critical_findings = findings_summary.get('critical_findings', 0)
    high_findings = findings_summary.get('high_findings', 0)
    
    if critical_findings > 0:
        theme_color = "FF0000"  # Red
    elif high_findings > 0:
        theme_color = "FFA500"  # Orange
    else:
        theme_color = "00FF00"  # Green
    
    message = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Security Scan {notification_type.replace('_', ' ').title()}",
        "sections": [{
            "activityTitle": f"Security Scan Results for {repository}",
            "activitySubtitle": f"Scan ID: {scan_id}",
            "facts": [
                {
                    "name": "Total Findings",
                    "value": str(findings_summary.get('total_findings', 0))
                },
                {
                    "name": "Critical",
                    "value": str(findings_summary.get('critical_findings', 0))
                },
                {
                    "name": "High",
                    "value": str(findings_summary.get('high_findings', 0))
                },
                {
                    "name": "Business Risk Score",
                    "value": f"{findings_summary.get('business_risk_score', 0):.1f}/100"
                },
                {
                    "name": "AI Confidence",
                    "value": f"{findings_summary.get('ai_confidence_score', 0):.1%}"
                }
            ],
            "markdown": True
        }],
        "potentialAction": []
    }
    
    # Add actions
    if critical_findings > 0:
        message["potentialAction"] = [
            {
                "@type": "OpenUri",
                "name": "View Report",
                "targets": [{
                    "os": "default",
                    "uri": f"https://console.aws.amazon.com/securityaudit/report/{scan_id}"
                }]
            },
            {
                "@type": "OpenUri",
                "name": "Create Ticket",
                "targets": [{
                    "os": "default",
                    "uri": f"https://jira.example.com/create?scan_id={scan_id}"
                }]
            }
        ]
    
    return message


def send_notification(webhook_url: str, message: Dict[str, Any]) -> Dict[str, Any]:
    """Send notification to webhook"""
    try:
        encoded_msg = json.dumps(message).encode('utf-8')
        
        response = http.request(
            'POST',
            webhook_url,
            body=encoded_msg,
            headers={'Content-Type': 'application/json'}
        )
        
        return {
            'status': response.status,
            'data': response.data.decode('utf-8')
        }
        
    except Exception as e:
        print(f"Error sending webhook: {str(e)}")
        return {
            'status': 500,
            'error': str(e)
        }