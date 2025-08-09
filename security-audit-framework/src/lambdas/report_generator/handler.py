"""
AI-Enhanced Report Generator - Creates comprehensive security reports from AI findings in DynamoDB
"""
import os
import sys
import json
import boto3
from typing import Dict, List, Any
from datetime import datetime
import base64
from io import BytesIO
from pathlib import Path
from decimal import Decimal

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
bedrock_runtime = boto3.client('bedrock-runtime')
lambda_client = boto3.client('lambda')


class AIReportGenerator:
    """Generates executive and technical reports from AI security findings in DynamoDB"""
    
    def __init__(self):
        # AI Components
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        
        # S3 buckets
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        
        # DynamoDB tables
        self.scan_table = dynamodb.Table(os.environ.get('SCAN_TABLE', 'SecurityScans'))
        self.ai_scans_table = dynamodb.Table(os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans'))
        self.ai_findings_table = dynamodb.Table(os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings'))
        
        # Configuration
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
    
    def generate_report(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive security report using AI insights from DynamoDB"""
        
        # Extract scan IDs
        scan_id = event.get('scan_id')
        ai_scan_id = event.get('ai_scan_id')
        aggregated_results = event.get('aggregated_results', {})
        
        # Get scan metadata from DynamoDB
        scan_info = self._get_scan_info(scan_id)
        ai_scan_info = self._get_ai_scan_info(ai_scan_id) if ai_scan_id else {}
        
        # If no aggregated results provided, fetch from S3
        if not aggregated_results and ai_scan_id:
            aggregated_results = self._fetch_aggregated_results(ai_scan_id)
        
        # Generate executive summary using AI
        executive_summary = self._generate_executive_summary(aggregated_results, ai_scan_info)
        
        # Generate technical report sections
        technical_sections = {
            'findings_analysis': self._analyze_findings_with_explainability(aggregated_results),
            'attack_path_analysis': self._analyze_attack_paths(aggregated_results),
            'risk_assessment': self._assess_risks_with_business_context(aggregated_results),
            'remediation_roadmap': self._create_ai_powered_remediation_roadmap(aggregated_results),
            'compliance_impact': self._assess_compliance_impact(aggregated_results),
            'ai_insights_analysis': self._analyze_ai_insights(aggregated_results)
        }
        
        # Generate visualizations data
        visualizations = self._generate_enhanced_visualization_data(aggregated_results)
        
        # Create full report
        report = {
            'report_id': f"{scan_id}-report-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'scan_id': scan_id,
            'ai_scan_id': ai_scan_id,
            'generated_at': datetime.utcnow().isoformat(),
            'repository': scan_info.get('repository_url', ai_scan_info.get('repository', 'Unknown')),
            'branch': scan_info.get('branch', ai_scan_info.get('branch', 'main')),
            'scan_type': ai_scan_info.get('scan_type', 'unknown'),
            'executive_summary': executive_summary,
            'statistics': aggregated_results.get('statistics', {}),
            'technical_report': technical_sections,
            'visualizations': visualizations,
            'ai_metadata': {
                'model_used': self.model_id,
                'explainability_summary': aggregated_results.get('explainability_summary', {}),
                'confidence_metrics': self._calculate_confidence_metrics(aggregated_results)
            },
            'recommendations': self._generate_ai_powered_recommendations(aggregated_results),
            'next_steps': self._generate_prioritized_next_steps(aggregated_results, executive_summary)
        }
        
        # Save report to S3
        report_urls = self._save_comprehensive_report(scan_id, report)
        
        # Transform data for Athena compatibility
        self._invoke_data_transformer(scan_id)
        
        # Ensure Athena tables are set up
        self._invoke_athena_setup()
        
        # Generate QuickSight dashboard
        dashboard_url = self._invoke_quicksight_dashboard(scan_id, scan_info)
        
        # Update scan records with report location
        self._update_scan_records(scan_id, ai_scan_id, report_urls)
        
        return {
            'report_id': report['report_id'],
            'report_urls': report_urls,
            'summary': executive_summary,
            'total_findings': report['statistics'].get('total_findings', 0),
            'risk_level': executive_summary.get('risk_level', 'UNKNOWN'),
            'dashboard_url': dashboard_url
        }
    
    def _get_ai_scan_info(self, ai_scan_id: str) -> Dict[str, Any]:
        """Get AI scan information from DynamoDB"""
        try:
            response = self.ai_scans_table.get_item(Key={'scan_id': ai_scan_id})
            return response.get('Item', {})
        except:
            return {}
    
    def _fetch_aggregated_results(self, ai_scan_id: str) -> Dict[str, Any]:
        """Fetch aggregated results from S3"""
        try:
            response = s3_client.get_object(
                Bucket=self.results_bucket,
                Key=f"aggregated/{ai_scan_id}/results.json"
            )
            return json.loads(response['Body'].read())
        except:
            return {}
    
    def _generate_executive_summary(self, results: Dict[str, Any], ai_scan_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered executive summary with business context"""
        
        statistics = results.get('statistics', {})
        ai_insights = results.get('ai_insights', {})
        top_findings = self._get_top_findings_with_context(results.get('findings', []), 5)
        
        # Include business risk in prompt
        prompt = f"""Generate an executive summary for this AI-powered security scan report.

Statistics:
- Total vulnerabilities: {statistics.get('total_findings', 0)}
- Critical: {statistics.get('by_severity', {}).get('CRITICAL', 0)}
- High: {statistics.get('by_severity', {}).get('HIGH', 0)}
- Business Risk Score: {statistics.get('business_risk_score', 0)}/100
- AI Confidence Score: {statistics.get('ai_confidence_score', 0)}
- False Positive Rate: {statistics.get('false_positive_rate', 0)}

Top Critical Findings with Business Context:
{json.dumps(top_findings, indent=2)}

AI Insights:
{json.dumps(ai_insights, indent=2)}

Scan Context:
- Repository: {ai_scan_info.get('repository', 'Unknown')}
- Scan Type: {ai_scan_info.get('scan_type', 'full')}

Create an executive summary that includes:
1. Overall security posture assessment (2-3 sentences)
2. Key business risks identified (prioritized by impact)
3. AI confidence assessment
4. Critical vulnerabilities requiring immediate action
5. Strategic security recommendations
6. Comparison to industry standards

Format as JSON:
{{
    "overall_posture": "detailed assessment",
    "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "business_risks": [
        {{
            "risk": "description",
            "impact": "business impact",
            "likelihood": "HIGH|MEDIUM|LOW"
        }}
    ],
    "ai_confidence_assessment": "assessment of AI findings reliability",
    "immediate_actions": ["action1", "action2"],
    "strategic_recommendations": ["recommendation1", "recommendation2"],
    "industry_comparison": "how this compares to industry standards"
}}"""

        try:
            response = bedrock_runtime.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 3000,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body.get('content', [{}])[0].get('text', '{}')
            
            # Parse AI response
            import re
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                summary = json.loads(json_match.group())
                return summary
                
        except Exception as e:
            print(f"AI summary generation failed: {str(e)}")
        
        # Fallback summary
        return self._generate_fallback_summary(statistics, ai_insights)
    
    def _get_top_findings_with_context(self, findings: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        """Get top findings with business context"""
        # Sort by priority score if available, otherwise by severity
        sorted_findings = sorted(
            findings,
            key=lambda x: (
                x.get('priority_score', 0),
                {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(x.get('severity', 'MEDIUM'), 2),
                x.get('business_risk_score', 0)
            ),
            reverse=True
        )
        
        # Include only essential fields for summary
        top_findings = []
        for finding in sorted_findings[:limit]:
            top_findings.append({
                'type': finding.get('finding_type', 'unknown'),
                'severity': finding.get('severity', 'MEDIUM'),
                'business_risk_score': finding.get('business_risk_score', 0),
                'asset_criticality': finding.get('asset_criticality', 'normal'),
                'description': finding.get('description', '')[:200],
                'file': finding.get('file_path', ''),
                'ai_confidence': finding.get('confidence', 0),
                'has_evidence': len(finding.get('evidence', [])) > 0
            })
        
        return top_findings
    
    def _analyze_findings_with_explainability(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze findings with AI explainability metrics"""
        findings = results.get('findings', [])
        explainability_summary = results.get('explainability_summary', {})
        
        analysis = {
            'total_findings': len(findings),
            'by_severity': self._count_by_field(findings, 'severity'),
            'by_category': self._count_by_field(findings, 'finding_type'),
            'by_confidence_level': self._count_by_field(findings, 'confidence_level'),
            'by_file_type': self._analyze_file_types(findings),
            'common_vulnerabilities': self._identify_common_patterns(findings),
            'ai_detection_metrics': {
                'average_confidence': explainability_summary.get('average_confidence', 0),
                'findings_with_evidence': explainability_summary.get('findings_with_evidence', 0),
                'findings_with_reasoning': explainability_summary.get('findings_with_reasoning', 0),
                'potential_false_positives': explainability_summary.get('potential_false_positives', 0)
            },
            'business_impact_distribution': self._analyze_business_impact(findings)
        }
        
        return analysis
    
    def _assess_risks_with_business_context(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive risk assessment with business context"""
        statistics = results.get('statistics', {})
        findings = results.get('findings', [])
        
        risk_assessment = {
            'overall_risk_score': statistics.get('business_risk_score', 0),
            'technical_risk_score': statistics.get('risk_score', 0),
            'risk_level': self._determine_risk_level(statistics),
            'risk_factors': {
                'vulnerability_density': self._calculate_vulnerability_density(results),
                'criticality_ratio': self._calculate_criticality_ratio(statistics),
                'attack_surface': self._assess_attack_surface(results),
                'exploitability': self._assess_exploitability(results),
                'business_exposure': self._assess_business_exposure(findings)
            },
            'risk_trends': self._analyze_risk_trends(results),
            'comparative_analysis': self._comparative_risk_analysis(statistics),
            'risk_mitigation_priority': self._calculate_mitigation_priority(findings)
        }
        
        return risk_assessment
    
    def _create_ai_powered_remediation_roadmap(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create AI-powered remediation roadmap with effort estimation"""
        remediation_plan = results.get('remediation_plan', {})
        findings = results.get('findings', [])
        ai_insights = results.get('ai_insights', {})
        
        roadmap = {
            'immediate': self._enhance_remediation_actions(
                remediation_plan.get('immediate_actions', []), findings
            ),
            'short_term': self._enhance_remediation_actions(
                remediation_plan.get('short_term', []), findings
            ),
            'long_term': remediation_plan.get('long_term', []),
            'estimated_effort': self._estimate_remediation_effort_with_ai(findings),
            'resource_requirements': self._estimate_resources(remediation_plan),
            'priority_matrix': self._create_enhanced_priority_matrix(findings),
            'automation_opportunities': self._identify_automation_opportunities(findings),
            'success_metrics': self._define_success_metrics(findings, ai_insights)
        }
        
        return roadmap
    
    def _analyze_ai_insights(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze and structure AI insights"""
        ai_insights = results.get('ai_insights', {})
        
        return {
            'executive_summary': ai_insights.get('executive_summary', 'No AI insights available'),
            'key_recommendations': ai_insights.get('key_recommendations', []),
            'risk_assessment': ai_insights.get('risk_assessment', 'Unknown'),
            'industry_comparison': ai_insights.get('industry_comparison', 'No comparison available'),
            'remediation_priorities': ai_insights.get('remediation_priorities', []),
            'confidence_in_analysis': self._assess_ai_confidence(results)
        }
    
    def _generate_enhanced_visualization_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate enhanced visualization data with AI insights"""
        findings = results.get('findings', [])
        statistics = results.get('statistics', {})
        
        return {
            'severity_distribution': statistics.get('by_severity', {}),
            'category_distribution': statistics.get('by_category', {}),
            'confidence_distribution': statistics.get('by_confidence_level', {}),
            'risk_score_gauge': {
                'technical_risk': statistics.get('risk_score', 0),
                'business_risk': statistics.get('business_risk_score', 0),
                'ai_confidence': statistics.get('ai_confidence_score', 0) * 100
            },
            'findings_timeline': self._create_timeline_data(findings),
            'attack_path_graph': self._create_attack_graph_data(results.get('attack_scenarios', [])),
            'heatmap_data': self._create_business_impact_heatmap(findings),
            'false_positive_analysis': {
                'rate': statistics.get('false_positive_rate', 0),
                'indicators': self._analyze_false_positive_patterns(findings)
            },
            'remediation_effort_chart': self._create_effort_visualization(findings)
        }
    
    def _generate_ai_powered_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-powered prioritized recommendations"""
        recommendations = []
        
        statistics = results.get('statistics', {})
        findings = results.get('findings', [])
        ai_insights = results.get('ai_insights', {})
        
        # Critical findings recommendations
        critical_count = statistics.get('by_severity', {}).get('CRITICAL', 0)
        if critical_count > 0:
            recommendations.append({
                'priority': 'IMMEDIATE',
                'title': f'Address {critical_count} Critical Vulnerabilities',
                'description': 'Critical vulnerabilities with high business impact require immediate remediation',
                'impact': 'Prevents potential data breach and business disruption',
                'effort': 'High',
                'automation_possible': self._check_automation_possible(findings, 'CRITICAL')
            })
        
        # AI-generated recommendations
        for rec in ai_insights.get('key_recommendations', [])[:3]:
            recommendations.append({
                'priority': 'HIGH',
                'title': rec,
                'description': 'AI-recommended security improvement',
                'impact': 'Significant risk reduction',
                'effort': 'Medium',
                'source': 'AI Analysis'
            })
        
        # Pattern-based recommendations
        patterns = self._identify_security_patterns(findings)
        for pattern in patterns:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': f'Address {pattern["type"]} Pattern',
                'description': pattern['description'],
                'impact': pattern['impact'],
                'effort': pattern['effort'],
                'affected_files': pattern['count']
            })
        
        # Add strategic recommendations
        if statistics.get('false_positive_rate', 0) > 0.2:
            recommendations.append({
                'priority': 'LOW',
                'title': 'Tune AI Security Policies',
                'description': 'High false positive rate suggests need for policy refinement',
                'impact': 'Improved accuracy and reduced noise',
                'effort': 'Low'
            })
        
        return recommendations
    
    def _generate_prioritized_next_steps(self, results: Dict[str, Any], executive_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate prioritized next steps with timelines"""
        next_steps = []
        
        risk_level = executive_summary.get('risk_level', 'MEDIUM')
        immediate_actions = executive_summary.get('immediate_actions', [])
        
        # Immediate steps (within 24 hours)
        if risk_level in ['CRITICAL', 'HIGH']:
            next_steps.append({
                'timeline': 'Within 24 hours',
                'actions': immediate_actions or ['Emergency security review required'],
                'responsible': 'Security Team + Development Team'
            })
        
        # Short-term steps (within 1 week)
        next_steps.append({
            'timeline': 'Within 1 week',
            'actions': [
                'Implement fixes for all critical vulnerabilities',
                'Review and validate AI findings with high business impact',
                'Update security policies based on findings'
            ],
            'responsible': 'Development Team'
        })
        
        # Medium-term steps (within 1 month)
        next_steps.append({
            'timeline': 'Within 1 month',
            'actions': [
                'Address all high-severity findings',
                'Implement recommended security controls',
                'Conduct follow-up AI security scan',
                'Review and update security training'
            ],
            'responsible': 'Security Team'
        })
        
        # Long-term steps (quarterly)
        next_steps.append({
            'timeline': 'Quarterly',
            'actions': [
                'Regular AI security scans',
                'Security policy reviews',
                'Dependency updates',
                'Security awareness training'
            ],
            'responsible': 'CISO/Security Leadership'
        })
        
        return next_steps
    
    def _save_comprehensive_report(self, scan_id: str, report: Dict[str, Any]) -> Dict[str, str]:
        """Save comprehensive report in multiple formats"""
        urls = {}
        
        if self.results_bucket:
            # Save JSON report
            json_key = f"reports/{scan_id}/report.json"
            s3_client.put_object(
                Bucket=self.results_bucket,
                Key=json_key,
                Body=json.dumps(report, indent=2, default=str),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            urls['json'] = f"s3://{self.results_bucket}/{json_key}"
            
            # Generate and save HTML report
            html_report = self._generate_enhanced_html_report(report)
            html_key = f"reports/{scan_id}/report.html"
            s3_client.put_object(
                Bucket=self.results_bucket,
                Key=html_key,
                Body=html_report,
                ContentType='text/html',
                ServerSideEncryption='AES256'
            )
            urls['html'] = f"s3://{self.results_bucket}/{html_key}"
            
            # Generate and save executive PDF summary (placeholder)
            # In production, use a PDF library like reportlab
            pdf_key = f"reports/{scan_id}/executive_summary.pdf"
            urls['pdf'] = f"s3://{self.results_bucket}/{pdf_key}"
        
        return urls
    
    def _generate_enhanced_html_report(self, report: Dict[str, Any]) -> str:
        """Generate enhanced HTML report with AI insights"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI Security Scan Report - {report['scan_id']}</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 0; 
            padding: 0;
            background: #f5f5f5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ 
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); 
            color: white; 
            padding: 30px; 
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .section {{ 
            background: white;
            margin: 20px 0; 
            padding: 30px; 
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .metric-card {{
            display: inline-block;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 10px;
            min-width: 150px;
            text-align: center;
        }}
        .metric-value {{ font-size: 36px; font-weight: bold; margin: 10px 0; }}
        .critical {{ color: #e74c3c; }}
        .high {{ color: #e67e22; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #95a5a6; }}
        .risk-gauge {{
            width: 200px;
            height: 100px;
            margin: 20px auto;
            position: relative;
        }}
        .confidence-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
        }}
        .confidence-high {{ background: #27ae60; color: white; }}
        .confidence-medium {{ background: #f39c12; color: white; }}
        .confidence-low {{ background: #e74c3c; color: white; }}
        .finding-card {{
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 15px 0;
            background: #f8f9fa;
        }}
        .ai-insight {{
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 AI-Powered Security Scan Report</h1>
            <p>Generated: {report['generated_at']}</p>
            <p>Repository: {report['repository']} | Branch: {report['branch']}</p>
            <p>Scan Type: {report['scan_type']} | AI Model: Claude 3</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric-card">
                <div class="metric-value {report['executive_summary'].get('risk_level', '').lower()}">
                    {report['executive_summary'].get('risk_level', 'UNKNOWN')}
                </div>
                <div>Overall Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report['statistics'].get('total_findings', 0)}</div>
                <div>Total Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report['statistics'].get('business_risk_score', 0):.0f}</div>
                <div>Business Risk Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{report['statistics'].get('ai_confidence_score', 0)*100:.0f}%</div>
                <div>AI Confidence</div>
            </div>
            
            <div class="ai-insight">
                <h3>AI Assessment</h3>
                <p>{report['executive_summary'].get('overall_posture', '')}</p>
                <p><strong>AI Confidence:</strong> {report['executive_summary'].get('ai_confidence_assessment', '')}</p>
            </div>
            
            <h3>Key Business Risks</h3>
            <ul>
                {''.join(f"<li><strong>{risk.get('risk', '')}</strong> - {risk.get('impact', '')} (Likelihood: {risk.get('likelihood', '')})</li>" 
                         for risk in report['executive_summary'].get('business_risks', [])[:5])}
            </ul>
            
            <h3>Immediate Actions Required</h3>
            <ul>
                {''.join(f"<li>{action}</li>" for action in report['executive_summary'].get('immediate_actions', []))}
            </ul>
        </div>
        
        <div class="section">
            <h2>Finding Statistics</h2>
            <h3>By Severity</h3>
            <div>
                <span class="metric-card">
                    <div class="metric-value critical">{report['statistics'].get('by_severity', {}).get('CRITICAL', 0)}</div>
                    <div>Critical</div>
                </span>
                <span class="metric-card">
                    <div class="metric-value high">{report['statistics'].get('by_severity', {}).get('HIGH', 0)}</div>
                    <div>High</div>
                </span>
                <span class="metric-card">
                    <div class="metric-value medium">{report['statistics'].get('by_severity', {}).get('MEDIUM', 0)}</div>
                    <div>Medium</div>
                </span>
                <span class="metric-card">
                    <div class="metric-value low">{report['statistics'].get('by_severity', {}).get('LOW', 0)}</div>
                    <div>Low</div>
                </span>
            </div>
            
            <h3>AI Explainability Metrics</h3>
            <p>Average Confidence: {report['ai_metadata']['explainability_summary'].get('average_confidence', 0)*100:.1f}%</p>
            <p>Findings with Evidence: {report['ai_metadata']['explainability_summary'].get('findings_with_evidence', 0)}</p>
            <p>Potential False Positives: {report['statistics'].get('false_positive_rate', 0)*100:.1f}%</p>
        </div>
        
        <div class="section">
            <h2>AI-Powered Recommendations</h2>
            {self._format_recommendations_html(report.get('recommendations', []))}
        </div>
        
        <div class="section">
            <h2>Next Steps</h2>
            {self._format_next_steps_html(report.get('next_steps', []))}
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _format_recommendations_html(self, recommendations: List[Dict[str, Any]]) -> str:
        """Format recommendations as HTML"""
        html_parts = []
        for rec in recommendations[:5]:
            priority_class = rec.get('priority', 'MEDIUM').lower()
            html_parts.append(f"""
            <div class="finding-card">
                <h4>{rec.get('title', '')}</h4>
                <span class="confidence-badge confidence-{priority_class}">
                    {rec.get('priority', 'MEDIUM')}
                </span>
                <p>{rec.get('description', '')}</p>
                <p><strong>Impact:</strong> {rec.get('impact', '')}</p>
                <p><strong>Effort:</strong> {rec.get('effort', 'Unknown')}</p>
            </div>
            """)
        return ''.join(html_parts)
    
    def _format_next_steps_html(self, next_steps: List[Dict[str, Any]]) -> str:
        """Format next steps as HTML"""
        html_parts = []
        for step in next_steps:
            html_parts.append(f"""
            <h3>{step.get('timeline', '')}</h3>
            <ul>
                {''.join(f"<li>{action}</li>" for action in step.get('actions', []))}
            </ul>
            <p><em>Responsible: {step.get('responsible', '')}</em></p>
            """)
        return ''.join(html_parts)
    
    def _update_scan_records(self, scan_id: str, ai_scan_id: str, report_urls: Dict[str, str]):
        """Update both scan records with report URLs"""
        timestamp = datetime.utcnow().isoformat()
        
        # Update legacy scan table
        if scan_id:
            try:
                self.scan_table.update_item(
                    Key={'scan_id': scan_id},
                    UpdateExpression='SET report_urls = :urls, report_generated_at = :time',
                    ExpressionAttributeValues={
                        ':urls': report_urls,
                        ':time': timestamp
                    }
                )
            except Exception as e:
                print(f"Error updating scan record: {e}")
        
        # Update AI scan table
        if ai_scan_id:
            try:
                self.ai_scans_table.update_item(
                    Key={'scan_id': ai_scan_id},
                    UpdateExpression='SET report_generated = :generated, report_urls = :urls',
                    ExpressionAttributeValues={
                        ':generated': True,
                        ':urls': report_urls
                    }
                )
            except Exception as e:
                print(f"Error updating AI scan record: {e}")
    
    # Helper methods
    def _get_scan_info(self, scan_id: str) -> Dict[str, Any]:
        """Get scan information from DynamoDB"""
        try:
            response = self.scan_table.get_item(Key={'scan_id': scan_id})
            return response.get('Item', {})
        except:
            return {}
    
    def _generate_fallback_summary(self, statistics: Dict[str, Any], ai_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback summary if AI fails"""
        risk_level = self._determine_risk_level(statistics)
        
        return {
            'overall_posture': f"Security scan identified {statistics.get('total_findings', 0)} vulnerabilities with business risk score of {statistics.get('business_risk_score', 0)}/100",
            'risk_level': risk_level,
            'business_risks': [
                {
                    'risk': 'Security vulnerabilities detected',
                    'impact': 'Potential data breach or service disruption',
                    'likelihood': 'HIGH' if risk_level in ['CRITICAL', 'HIGH'] else 'MEDIUM'
                }
            ],
            'ai_confidence_assessment': f"AI analysis confidence: {statistics.get('ai_confidence_score', 0)*100:.0f}%",
            'immediate_actions': ['Review critical findings', 'Implement security patches'],
            'strategic_recommendations': ai_insights.get('key_recommendations', ['Enhance security practices']),
            'industry_comparison': 'Unable to generate comparison'
        }
    
    def _determine_risk_level(self, statistics: Dict[str, Any]) -> str:
        """Determine overall risk level based on business risk score"""
        risk_score = statistics.get('business_risk_score', statistics.get('risk_score', 0))
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _count_by_field(self, items: List[Dict[str, Any]], field: str) -> Dict[str, int]:
        """Count items by field value"""
        from collections import defaultdict
        counts = defaultdict(int)
        for item in items:
            value = item.get(field, 'unknown')
            counts[value] += 1
        return dict(counts)
    
    def _analyze_file_types(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze findings by file type"""
        file_types = {}
        for finding in findings:
            file_path = finding.get('file_path', '')
            if file_path:
                ext = os.path.splitext(file_path)[1].lower()
                file_types[ext] = file_types.get(ext, 0) + 1
        return file_types
    
    def _identify_common_patterns(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Identify common vulnerability patterns"""
        from collections import defaultdict
        patterns = defaultdict(int)
        for finding in findings:
            pattern = finding.get('finding_type', 'unknown')
            patterns[pattern] += 1
        
        # Return top 5 patterns
        sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
        return [f"{p[0]} ({p[1]} occurrences)" for p in sorted_patterns[:5]]
    
    def _analyze_business_impact(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze distribution of business impact"""
        impact_dist = {
            'critical_assets': 0,
            'high_value_assets': 0,
            'normal_assets': 0
        }
        
        for finding in findings:
            criticality = finding.get('asset_criticality', 'normal')
            if criticality == 'critical':
                impact_dist['critical_assets'] += 1
            elif criticality == 'high':
                impact_dist['high_value_assets'] += 1
            else:
                impact_dist['normal_assets'] += 1
        
        return impact_dist
    
    def _calculate_vulnerability_density(self, results: Dict[str, Any]) -> float:
        """Calculate vulnerability density"""
        findings = results.get('findings', [])
        unique_files = set(f.get('file_path', '') for f in findings if f.get('file_path'))
        
        if not unique_files:
            return 0.0
        
        return round(len(findings) / len(unique_files), 2)
    
    def _calculate_criticality_ratio(self, statistics: Dict[str, Any]) -> float:
        """Calculate ratio of critical/high findings"""
        total = statistics.get('total_findings', 0)
        if total == 0:
            return 0.0
        
        critical_high = (
            statistics.get('by_severity', {}).get('CRITICAL', 0) + 
            statistics.get('by_severity', {}).get('HIGH', 0)
        )
        return round(critical_high / total, 2)
    
    def _assess_attack_surface(self, results: Dict[str, Any]) -> str:
        """Assess attack surface"""
        categories = results.get('statistics', {}).get('by_category', {})
        attack_vectors = len([c for c in categories if categories[c] > 0])
        
        if attack_vectors > 5:
            return 'LARGE'
        elif attack_vectors > 3:
            return 'MEDIUM'
        else:
            return 'SMALL'
    
    def _assess_exploitability(self, results: Dict[str, Any]) -> str:
        """Assess overall exploitability"""
        findings = results.get('findings', [])
        high_confidence_critical = [
            f for f in findings 
            if f.get('severity') == 'CRITICAL' and f.get('confidence', 0) > 0.8
        ]
        
        if len(high_confidence_critical) > 3:
            return 'HIGH'
        elif len(high_confidence_critical) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_business_exposure(self, findings: List[Dict[str, Any]]) -> str:
        """Assess business exposure level"""
        critical_asset_vulns = [
            f for f in findings 
            if f.get('asset_criticality') == 'critical' and 
            f.get('severity') in ['CRITICAL', 'HIGH']
        ]
        
        if len(critical_asset_vulns) > 5:
            return 'SEVERE'
        elif len(critical_asset_vulns) > 0:
            return 'HIGH'
        else:
            return 'MODERATE'
    
    def _analyze_risk_trends(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk trends (placeholder for historical comparison)"""
        return {
            'trend': 'No historical data',
            'change_from_last_scan': 0,
            'improvement_areas': [],
            'degradation_areas': []
        }
    
    def _comparative_risk_analysis(self, statistics: Dict[str, Any]) -> Dict[str, Any]:
        """Compare to industry benchmarks"""
        risk_score = statistics.get('business_risk_score', 0)
        
        return {
            'industry_percentile': self._calculate_percentile(risk_score),
            'benchmark': 'Industry Average',
            'comparison': 'Above average' if risk_score > 50 else 'Below average',
            'recommendation': 'Continue security improvements'
        }
    
    def _calculate_percentile(self, risk_score: float) -> int:
        """Calculate industry percentile (mock)"""
        # In production, compare against real industry data
        if risk_score >= 80:
            return 90  # Top 10% risk
        elif risk_score >= 60:
            return 70
        elif risk_score >= 40:
            return 50
        else:
            return 30
    
    def _calculate_mitigation_priority(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Calculate mitigation priorities"""
        priorities = []
        
        # Group by asset criticality and severity
        critical_assets = [f for f in findings if f.get('asset_criticality') == 'critical']
        if critical_assets:
            priorities.append('Critical business assets at risk - prioritize immediately')
        
        # Check for easily exploitable vulnerabilities
        easy_exploits = [f for f in findings if 'injection' in f.get('finding_type', '').lower()]
        if easy_exploits:
            priorities.append('Easily exploitable vulnerabilities detected - patch urgently')
        
        return priorities
    
    def _enhance_remediation_actions(self, actions: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance remediation actions with AI insights"""
        enhanced = []
        
        for action in actions:
            # Add automation recommendations
            action['automation_available'] = self._check_automation_available(action.get('action', ''))
            
            # Add confidence level
            action['ai_confidence'] = 'high'  # Placeholder
            
            # Add business justification
            action['business_justification'] = self._generate_business_justification(action)
            
            enhanced.append(action)
        
        return enhanced
    
    def _estimate_remediation_effort_with_ai(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate remediation effort using AI analysis"""
        effort_by_severity = {
            'CRITICAL': {'hours': 0, 'count': 0},
            'HIGH': {'hours': 0, 'count': 0},
            'MEDIUM': {'hours': 0, 'count': 0},
            'LOW': {'hours': 0, 'count': 0}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            hours = self._estimate_hours_for_finding(finding)
            effort_by_severity[severity]['hours'] += hours
            effort_by_severity[severity]['count'] += 1
        
        total_hours = sum(e['hours'] for e in effort_by_severity.values())
        
        return {
            'total_hours': total_hours,
            'by_severity': effort_by_severity,
            'team_size_recommendation': self._recommend_team_size(total_hours),
            'timeline': self._estimate_timeline(total_hours)
        }
    
    def _estimate_hours_for_finding(self, finding: Dict[str, Any]) -> float:
        """Estimate hours to fix a finding"""
        base_hours = {
            'CRITICAL': 8,
            'HIGH': 4,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        hours = base_hours.get(finding.get('severity', 'MEDIUM'), 2)
        
        # Adjust based on finding type
        if 'configuration' in finding.get('finding_type', '').lower():
            hours *= 0.5  # Config changes are usually quicker
        elif 'architecture' in finding.get('finding_type', '').lower():
            hours *= 2  # Architecture changes take longer
        
        return hours
    
    def _create_enhanced_priority_matrix(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create enhanced priority matrix"""
        matrix = []
        
        for finding in findings[:20]:  # Top 20 findings
            matrix.append({
                'finding': finding.get('description', '')[:100],
                'severity': finding.get('severity', 'MEDIUM'),
                'business_impact': finding.get('business_risk_score', 0),
                'effort': self._estimate_hours_for_finding(finding),
                'priority_score': self._calculate_priority_score(finding),
                'automation_possible': self._check_specific_automation(finding)
            })
        
        # Sort by priority score
        return sorted(matrix, key=lambda x: x['priority_score'], reverse=True)
    
    def _identify_automation_opportunities(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify opportunities for automated remediation"""
        opportunities = []
        
        # Check for configuration issues
        config_issues = [f for f in findings if 'configuration' in f.get('finding_type', '').lower()]
        if config_issues:
            opportunities.append({
                'type': 'Configuration Management',
                'description': 'Automate security configuration with Infrastructure as Code',
                'applicable_findings': len(config_issues),
                'effort_savings': f"{len(config_issues) * 2} hours"
            })
        
        # Check for dependency issues
        dep_issues = [f for f in findings if 'dependency' in f.get('finding_type', '').lower()]
        if dep_issues:
            opportunities.append({
                'type': 'Dependency Management',
                'description': 'Implement automated dependency updates with security scanning',
                'applicable_findings': len(dep_issues),
                'effort_savings': f"{len(dep_issues) * 1} hours"
            })
        
        return opportunities
    
    def _define_success_metrics(self, findings: List[Dict[str, Any]], ai_insights: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Define success metrics for remediation"""
        current_stats = {
            'total': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'CRITICAL']),
            'high': len([f for f in findings if f.get('severity') == 'HIGH'])
        }
        
        return [
            {
                'metric': 'Critical Vulnerabilities',
                'current': current_stats['critical'],
                'target': 0,
                'timeline': '24 hours'
            },
            {
                'metric': 'High Severity Findings',
                'current': current_stats['high'],
                'target': 0,
                'timeline': '1 week'
            },
            {
                'metric': 'Business Risk Score',
                'current': self._calculate_current_risk_score(findings),
                'target': 20,
                'timeline': '1 month'
            },
            {
                'metric': 'False Positive Rate',
                'current': self._calculate_false_positive_rate(findings),
                'target': 0.05,
                'timeline': 'Ongoing'
            }
        ]
    
    def _assess_ai_confidence(self, results: Dict[str, Any]) -> str:
        """Assess overall AI confidence in analysis"""
        avg_confidence = results.get('statistics', {}).get('ai_confidence_score', 0)
        
        if avg_confidence > 0.9:
            return 'Very High - AI findings are highly reliable'
        elif avg_confidence > 0.8:
            return 'High - Most findings are accurate'
        elif avg_confidence > 0.7:
            return 'Moderate - Some findings may need validation'
        else:
            return 'Low - Manual review recommended'
    
    def _create_timeline_data(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create timeline visualization data"""
        # Group findings by estimated fix time
        timeline = [
            {
                'phase': 'Immediate (24 hours)',
                'findings': len([f for f in findings if f.get('severity') == 'CRITICAL']),
                'effort_hours': sum(self._estimate_hours_for_finding(f) for f in findings if f.get('severity') == 'CRITICAL')
            },
            {
                'phase': 'Short-term (1 week)',
                'findings': len([f for f in findings if f.get('severity') == 'HIGH']),
                'effort_hours': sum(self._estimate_hours_for_finding(f) for f in findings if f.get('severity') == 'HIGH')
            },
            {
                'phase': 'Medium-term (1 month)',
                'findings': len([f for f in findings if f.get('severity') == 'MEDIUM']),
                'effort_hours': sum(self._estimate_hours_for_finding(f) for f in findings if f.get('severity') == 'MEDIUM')
            }
        ]
        
        return timeline
    
    def _create_attack_graph_data(self, attack_scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create attack graph visualization data"""
        if not attack_scenarios:
            return {'nodes': [], 'edges': []}
        
        nodes = []
        edges = []
        node_id = 0
        
        for scenario in attack_scenarios[:3]:  # Top 3 scenarios
            scenario_root = {
                'id': f"node_{node_id}",
                'label': scenario.get('name', 'Attack'),
                'type': 'root',
                'severity': scenario.get('severity', 'HIGH')
            }
            nodes.append(scenario_root)
            root_id = node_id
            node_id += 1
            
            # Add steps as nodes
            for i, step in enumerate(scenario.get('steps', [])[:5]):
                step_node = {
                    'id': f"node_{node_id}",
                    'label': step.get('vulnerability', 'Step'),
                    'type': 'step',
                    'file': step.get('file', '')
                }
                nodes.append(step_node)
                
                # Add edge
                edges.append({
                    'source': f"node_{root_id}" if i == 0 else f"node_{node_id-1}",
                    'target': f"node_{node_id}"
                })
                
                node_id += 1
        
        return {'nodes': nodes, 'edges': edges}
    
    def _create_business_impact_heatmap(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create heatmap data for business impact"""
        from collections import defaultdict
        
        # Group by file and severity
        file_severity_map = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
        
        for finding in findings:
            file_path = finding.get('file_path', 'unknown')
            severity = finding.get('severity', 'MEDIUM')
            business_score = finding.get('business_risk_score', 0)
            
            # Weight by business risk
            weight = 1 + (business_score / 100)
            file_severity_map[file_path][severity] += weight
        
        # Convert to heatmap format
        heatmap_data = []
        for file_path, severities in list(file_severity_map.items())[:20]:  # Top 20 files
            heatmap_data.append({
                'file': os.path.basename(file_path),
                'critical': severities['CRITICAL'],
                'high': severities['HIGH'],
                'medium': severities['MEDIUM'],
                'low': severities['LOW'],
                'total_risk': sum(severities.values())
            })
        
        # Sort by total risk
        return sorted(heatmap_data, key=lambda x: x['total_risk'], reverse=True)
    
    def _analyze_false_positive_patterns(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze patterns in false positive indicators"""
        from collections import defaultdict
        patterns = defaultdict(int)
        
        for finding in findings:
            for indicator in finding.get('false_positive_indicators', []):
                patterns[indicator] += 1
        
        return dict(patterns)
    
    def _create_effort_visualization(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create effort visualization data"""
        effort_by_category = defaultdict(float)
        
        for finding in findings:
            category = finding.get('finding_type', 'unknown')
            hours = self._estimate_hours_for_finding(finding)
            effort_by_category[category] += hours
        
        # Convert to chart format
        return {
            'categories': list(effort_by_category.keys()),
            'hours': list(effort_by_category.values()),
            'total_hours': sum(effort_by_category.values())
        }
    
    def _check_automation_possible(self, findings: List[Dict[str, Any]], severity: str) -> bool:
        """Check if automation is possible for findings of given severity"""
        severity_findings = [f for f in findings if f.get('severity') == severity]
        
        # Check if most are configuration or dependency issues
        automatable_types = ['configuration', 'dependency', 'missing_header', 'permission']
        automatable_count = sum(
            1 for f in severity_findings 
            if any(t in f.get('finding_type', '').lower() for t in automatable_types)
        )
        
        return automatable_count > len(severity_findings) * 0.5
    
    def _check_automation_available(self, action: str) -> bool:
        """Check if specific action can be automated"""
        automatable_keywords = ['configuration', 'update', 'patch', 'permission', 'header', 'dependency']
        return any(keyword in action.lower() for keyword in automatable_keywords)
    
    def _generate_business_justification(self, action: Dict[str, Any]) -> str:
        """Generate business justification for action"""
        if action.get('priority') == 'IMMEDIATE':
            return 'Critical business risk - immediate action prevents potential breach'
        elif action.get('priority') == 'HIGH':
            return 'High business impact - reduces significant security exposure'
        else:
            return 'Improves overall security posture and compliance'
    
    def _recommend_team_size(self, total_hours: float) -> str:
        """Recommend team size based on effort"""
        if total_hours > 160:
            return '3-5 developers'
        elif total_hours > 80:
            return '2-3 developers'
        else:
            return '1-2 developers'
    
    def _estimate_timeline(self, total_hours: float) -> str:
        """Estimate project timeline"""
        # Assuming 6 productive hours per day per developer
        days = total_hours / (6 * 2)  # Assuming 2 developers
        
        if days > 20:
            return f"{int(days/20)} months"
        elif days > 5:
            return f"{int(days/5)} weeks"
        else:
            return f"{int(days)} days"
    
    def _calculate_priority_score(self, finding: Dict[str, Any]) -> int:
        """Calculate priority score for finding"""
        severity_scores = {'CRITICAL': 40, 'HIGH': 30, 'MEDIUM': 20, 'LOW': 10}
        
        score = severity_scores.get(finding.get('severity', 'MEDIUM'), 20)
        score += finding.get('business_risk_score', 0) * 0.5
        score += (1 - len(finding.get('false_positive_indicators', [])) * 0.1) * 10
        
        return int(score)
    
    def _check_specific_automation(self, finding: Dict[str, Any]) -> bool:
        """Check if specific finding can be automated"""
        automatable_types = ['configuration', 'dependency', 'missing_header', 'permission', 'update']
        finding_type = finding.get('finding_type', '').lower()
        
        return any(t in finding_type for t in automatable_types)
    
    def _calculate_current_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate current risk score from findings"""
        if not findings:
            return 0
        
        total_risk = sum(f.get('business_risk_score', 0) for f in findings)
        return round(total_risk / len(findings), 1)
    
    def _calculate_false_positive_rate(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate false positive rate"""
        if not findings:
            return 0
        
        potential_fps = len([f for f in findings if f.get('false_positive_indicators')])
        return round(potential_fps / len(findings), 3)
    
    def _calculate_confidence_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate AI confidence metrics"""
        explainability = results.get('explainability_summary', {})
        
        return {
            'overall_confidence': results.get('statistics', {}).get('ai_confidence_score', 0),
            'high_confidence_findings': explainability.get('confidence_distribution', {}).get('very_high', 0) +
                                      explainability.get('confidence_distribution', {}).get('high', 0),
            'evidence_coverage': explainability.get('findings_with_evidence', 0) / 
                               results.get('statistics', {}).get('total_findings', 1) if results.get('statistics', {}).get('total_findings', 0) > 0 else 0,
            'explainability_score': (explainability.get('findings_with_reasoning', 0) / 
                                   results.get('statistics', {}).get('total_findings', 1)) if results.get('statistics', {}).get('total_findings', 0) > 0 else 0
        }
    
    def _identify_security_patterns(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify security patterns from findings"""
        from collections import defaultdict
        
        pattern_groups = defaultdict(list)
        
        # Group by finding type
        for finding in findings:
            finding_type = finding.get('finding_type', 'unknown')
            pattern_groups[finding_type].append(finding)
        
        patterns = []
        for pattern_type, group in pattern_groups.items():
            if len(group) >= 3:  # Pattern threshold
                patterns.append({
                    'type': pattern_type,
                    'count': len(group),
                    'description': f'Multiple {pattern_type} vulnerabilities detected',
                    'impact': 'Systematic security weakness',
                    'effort': 'Medium - requires framework-level changes'
                })
        
        return patterns[:5]  # Top 5 patterns
    
    def _invoke_athena_setup(self):
        """Invoke Athena setup Lambda to ensure tables are created"""
        try:
            athena_lambda_name = os.environ.get('ATHENA_SETUP_LAMBDA_NAME', 'AthenaSetupLambda')
            
            response = lambda_client.invoke(
                FunctionName=athena_lambda_name,
                InvocationType='RequestResponse',
                Payload=json.dumps({
                    'action': 'setup_all'
                })
            )
            
            result = json.loads(response['Payload'].read())
            if result.get('statusCode') == 200:
                print("Athena tables setup successful")
            else:
                print(f"Athena setup warning: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"Error invoking Athena setup: {e}")
            # Continue even if Athena setup fails
    
    def _invoke_quicksight_dashboard(self, scan_id: str, scan_metadata: Dict[str, Any]) -> str:
        """Invoke QuickSight dashboard Lambda to create visualization"""
        try:
            quicksight_lambda_name = os.environ.get('QUICKSIGHT_LAMBDA_NAME', 'QuickSightDashboardLambda')
            
            response = lambda_client.invoke(
                FunctionName=quicksight_lambda_name,
                InvocationType='RequestResponse',
                Payload=json.dumps({
                    'scan_id': scan_id,
                    'scan_metadata': scan_metadata
                })
            )
            
            result = json.loads(response['Payload'].read())
            if result.get('statusCode') == 200:
                print(f"QuickSight dashboard created: {result.get('dashboard_url')}")
                return result.get('dashboard_url', '')
            else:
                print(f"QuickSight dashboard creation failed: {result.get('error', 'Unknown error')}")
                return ''
                
        except Exception as e:
            print(f"Error invoking QuickSight dashboard: {e}")
            return ''
    
    def _invoke_data_transformer(self, scan_id: str):
        """Invoke data transformer Lambda to prepare data for Athena"""
        try:
            data_transformer_lambda = os.environ.get('DATA_TRANSFORMER_LAMBDA_NAME', 'DataTransformerLambda')
            
            response = lambda_client.invoke(
                FunctionName=data_transformer_lambda,
                InvocationType='RequestResponse',  # Synchronous - wait for completion
                Payload=json.dumps({
                    'scan_id': scan_id
                })
            )
            
            result = json.loads(response['Payload'].read())
            if result.get('statusCode') == 200:
                print(f"Data transformation successful: {result.get('findings_count')} findings processed")
            else:
                print(f"Data transformation warning: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"Error invoking data transformer: {e}")
            # Continue even if transformation fails


def handler(event, context):
    """Lambda handler for AI report generation"""
    generator = AIReportGenerator()
    
    # Generate report
    report_result = generator.generate_report(event)
    
    return {
        'statusCode': 200,
        'body': json.dumps(report_result)
    }