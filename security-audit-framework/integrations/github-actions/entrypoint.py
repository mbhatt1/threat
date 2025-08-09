#!/usr/bin/env python3
"""
GitHub Action entrypoint for AI Security Scanner
"""
import os
import sys
import json
import subprocess
import time
from typing import Dict, Any, Optional
import requests
import boto3
from ai_security_scanner import AISecurityScanner

class GitHubActionRunner:
    """Run AI security scan in GitHub Actions context"""
    
    def __init__(self):
        # GitHub environment
        self.github_token = os.environ.get('GITHUB_TOKEN')
        self.github_repository = os.environ.get('GITHUB_REPOSITORY')
        self.github_sha = os.environ.get('GITHUB_SHA')
        self.github_ref = os.environ.get('GITHUB_REF')
        self.github_event_name = os.environ.get('GITHUB_EVENT_NAME')
        self.github_workspace = os.environ.get('GITHUB_WORKSPACE', '/github/workspace')
        
        # PR information
        self.github_event_path = os.environ.get('GITHUB_EVENT_PATH')
        self.pr_number = None
        self.base_branch = os.environ.get('INPUT_BASE-BRANCH', 'main')
        
        # Action inputs
        self.scan_type = os.environ.get('INPUT_SCAN-TYPE', 'pr')
        self.fail_on_critical = os.environ.get('INPUT_FAIL-ON-CRITICAL', 'true').lower() == 'true'
        self.fail_on_high = os.environ.get('INPUT_FAIL-ON-HIGH', 'false').lower() == 'true'
        self.business_context = os.environ.get('INPUT_BUSINESS-CONTEXT', 'normal')
        self.comment_on_pr = os.environ.get('INPUT_COMMENT-ON-PR', 'true').lower() == 'true'
        self.upload_sarif = os.environ.get('INPUT_UPLOAD-SARIF', 'true').lower() == 'true'
        
        # Initialize scanner
        self.scanner = AISecurityScanner()
        
        # Load PR event data
        self._load_pr_data()
    
    def _load_pr_data(self):
        """Load PR data from GitHub event"""
        if self.github_event_path and os.path.exists(self.github_event_path):
            with open(self.github_event_path, 'r') as f:
                event_data = json.load(f)
                
            if self.github_event_name == 'pull_request':
                self.pr_number = event_data.get('pull_request', {}).get('number')
                self.base_branch = event_data.get('pull_request', {}).get('base', {}).get('ref', self.base_branch)
    
    def run(self) -> int:
        """Run the security scan"""
        try:
            print("🤖 AI Security Scanner - GitHub Action")
            print(f"Repository: {self.github_repository}")
            print(f"Scan Type: {self.scan_type}")
            print(f"Business Context: {self.business_context}")
            
            # Configure scan
            scan_config = {
                'repository_url': f"https://github.com/{self.github_repository}",
                'branch': self._get_branch_name(),
                'commit_hash': self.github_sha,
                'scan_options': {
                    'scan_type': self.scan_type,
                    'business_context': self.business_context,
                    'triggered_by': 'github_actions',
                    'pr_number': self.pr_number,
                    'base_branch': self.base_branch if self.scan_type == 'pr' else None
                }
            }
            
            # Run scan
            print("\n📊 Starting AI security scan...")
            scan_result = self.scanner.run_scan(
                repository_path=self.github_workspace,
                scan_config=scan_config
            )
            
            # Process results
            print(f"\n✅ Scan completed: {scan_result['scan_id']}")
            print(f"Total Findings: {scan_result['total_findings']}")
            print(f"Critical: {scan_result['critical_findings']}")
            print(f"High: {scan_result['high_findings']}")
            print(f"Business Risk Score: {scan_result['business_risk_score']}/100")
            
            # Set outputs
            self._set_outputs(scan_result)
            
            # Comment on PR if enabled
            if self.comment_on_pr and self.pr_number:
                self._comment_on_pr(scan_result)
            
            # Upload SARIF if enabled
            if self.upload_sarif:
                self._upload_sarif_results(scan_result)
            
            # Determine exit code
            if self.fail_on_critical and scan_result['critical_findings'] > 0:
                print("\n❌ Build failed: Critical vulnerabilities found")
                return 1
            elif self.fail_on_high and scan_result['high_findings'] > 0:
                print("\n❌ Build failed: High vulnerabilities found")
                return 1
            else:
                print("\n✅ Security scan passed")
                return 0
                
        except Exception as e:
            print(f"\n❌ Error running security scan: {str(e)}")
            return 2
    
    def _get_branch_name(self) -> str:
        """Extract branch name from GitHub ref"""
        if self.github_ref:
            if self.github_ref.startswith('refs/heads/'):
                return self.github_ref.replace('refs/heads/', '')
            elif self.github_ref.startswith('refs/pull/'):
                # For PRs, use the PR branch
                return f"pr-{self.pr_number}"
        return 'unknown'
    
    def _set_outputs(self, scan_result: Dict[str, Any]):
        """Set GitHub Action outputs"""
        outputs = {
            'scan-id': scan_result['scan_id'],
            'total-findings': str(scan_result['total_findings']),
            'critical-findings': str(scan_result['critical_findings']),
            'high-findings': str(scan_result['high_findings']),
            'business-risk-score': str(scan_result['business_risk_score']),
            'report-url': scan_result.get('report_url', '')
        }
        
        # Write to GITHUB_OUTPUT if available (new method)
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                for key, value in outputs.items():
                    f.write(f"{key}={value}\n")
        else:
            # Fallback to old method
            for key, value in outputs.items():
                print(f"::set-output name={key}::{value}")
    
    def _comment_on_pr(self, scan_result: Dict[str, Any]):
        """Post scan results as PR comment"""
        if not self.github_token:
            print("⚠️  No GITHUB_TOKEN available, skipping PR comment")
            return
        
        # Generate comment content
        comment = self._generate_pr_comment(scan_result)
        
        # Post comment via GitHub API
        api_url = f"https://api.github.com/repos/{self.github_repository}/issues/{self.pr_number}/comments"
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        try:
            response = requests.post(api_url, json={'body': comment}, headers=headers)
            response.raise_for_status()
            print("✅ Posted scan results to PR")
        except Exception as e:
            print(f"⚠️  Failed to post PR comment: {str(e)}")
    
    def _generate_pr_comment(self, scan_result: Dict[str, Any]) -> str:
        """Generate PR comment content"""
        risk_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '📊',
            'LOW': '✅'
        }
        
        risk_level = scan_result.get('risk_level', 'UNKNOWN')
        emoji = risk_emoji.get(risk_level, '📊')
        
        comment = f"""## {emoji} AI Security Scan Results

**Scan ID:** `{scan_result['scan_id']}`
**Risk Level:** **{risk_level}**
**Business Risk Score:** {scan_result['business_risk_score']}/100
**AI Confidence:** {scan_result.get('ai_confidence_score', 0)*100:.0f}%

### 📊 Finding Summary

| Severity | Count |
|----------|-------|
| 🚨 Critical | {scan_result['critical_findings']} |
| ⚠️  High | {scan_result['high_findings']} |
| 📊 Medium | {scan_result.get('medium_findings', 0)} |
| ✅ Low | {scan_result.get('low_findings', 0)} |
| **Total** | **{scan_result['total_findings']}** |

### 🤖 AI Insights

{scan_result.get('executive_summary', 'AI analysis in progress...')}

### 📋 Top Recommendations

"""
        
        # Add top recommendations
        recommendations = scan_result.get('recommendations', [])
        for i, rec in enumerate(recommendations[:3], 1):
            comment += f"{i}. {rec}\n"
        
        # Add report link if available
        if scan_result.get('report_url'):
            comment += f"\n### 📄 Full Report\n\n[View detailed security report]({scan_result['report_url']})\n"
        
        # Add scan metadata
        comment += f"\n---\n*Scanned by AI Security Scanner powered by Claude 3 • "
        comment += f"[Learn more](https://github.com/{self.github_repository}/security)*"
        
        return comment
    
    def _upload_sarif_results(self, scan_result: Dict[str, Any]):
        """Convert and upload results in SARIF format"""
        try:
            # Generate SARIF from scan results
            sarif_data = self._generate_sarif(scan_result)
            
            # Save SARIF file
            sarif_path = os.path.join(self.github_workspace, 'ai-security-scan.sarif')
            with open(sarif_path, 'w') as f:
                json.dump(sarif_data, f, indent=2)
            
            print(f"✅ Generated SARIF file: {sarif_path}")
            
            # Upload to GitHub Security tab
            if self.github_token:
                self._upload_to_code_scanning(sarif_path)
            
        except Exception as e:
            print(f"⚠️  Failed to generate SARIF: {str(e)}")
    
    def _generate_sarif(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SARIF format from scan results"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AI Security Scanner",
                        "version": "2.0.0",
                        "fullName": "AI Security Scanner powered by Claude 3",
                        "informationUri": "https://github.com/ai-security-scanner",
                        "rules": self._generate_sarif_rules(scan_result)
                    }
                },
                "results": self._generate_sarif_results(scan_result),
                "properties": {
                    "scan_id": scan_result['scan_id'],
                    "business_risk_score": scan_result['business_risk_score'],
                    "ai_confidence_score": scan_result.get('ai_confidence_score', 0)
                }
            }]
        }
        
        return sarif
    
    def _generate_sarif_rules(self, scan_result: Dict[str, Any]) -> list:
        """Generate SARIF rules from findings"""
        rules = []
        rule_map = {}
        
        # Extract unique rules from findings
        for finding in scan_result.get('findings', []):
            rule_id = finding.get('type', 'UNKNOWN')
            if rule_id not in rule_map:
                rule = {
                    "id": rule_id,
                    "name": finding.get('category', rule_id),
                    "shortDescription": {
                        "text": finding.get('description', '')[:100]
                    },
                    "fullDescription": {
                        "text": finding.get('description', '')
                    },
                    "help": {
                        "text": finding.get('remediation', 'Review and fix the security issue'),
                        "markdown": f"**Remediation:** {finding.get('remediation', 'Review and fix')}"
                    },
                    "properties": {
                        "security-severity": self._get_security_severity(finding.get('severity', 'MEDIUM'))
                    }
                }
                rules.append(rule)
                rule_map[rule_id] = len(rules) - 1
        
        return rules
    
    def _generate_sarif_results(self, scan_result: Dict[str, Any]) -> list:
        """Generate SARIF results from findings"""
        results = []
        
        for finding in scan_result.get('findings', [])[:100]:  # Limit to 100 findings
            result = {
                "ruleId": finding.get('type', 'UNKNOWN'),
                "ruleIndex": 0,  # Would need to map to actual rule index
                "level": self._map_severity_to_level(finding.get('severity', 'MEDIUM')),
                "message": {
                    "text": finding.get('description', 'Security issue detected')
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get('file_path', 'unknown'),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": finding.get('line_numbers', [1])[0] if finding.get('line_numbers') else 1
                        }
                    }
                }],
                "properties": {
                    "ai_confidence": finding.get('confidence', 0),
                    "business_risk_score": finding.get('business_risk_score', 0),
                    "false_positive_indicators": finding.get('false_positive_indicators', [])
                }
            }
            results.append(result)
        
        return results
    
    def _get_security_severity(self, severity: str) -> str:
        """Map severity to security-severity score"""
        mapping = {
            'CRITICAL': '9.0',
            'HIGH': '7.0',
            'MEDIUM': '5.0',
            'LOW': '3.0'
        }
        return mapping.get(severity.upper(), '5.0')
    
    def _map_severity_to_level(self, severity: str) -> str:
        """Map severity to SARIF level"""
        mapping = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note'
        }
        return mapping.get(severity.upper(), 'warning')
    
    def _upload_to_code_scanning(self, sarif_path: str):
        """Upload SARIF to GitHub Code Scanning"""
        try:
            # Use GitHub CLI if available
            subprocess.run([
                'gh', 'api',
                f'/repos/{self.github_repository}/code-scanning/sarifs',
                '-f', f'commit_sha={self.github_sha}',
                '-f', f'ref={self.github_ref}',
                '-f', f'sarif=@{sarif_path}',
                '--method', 'POST'
            ], check=True)
            print("✅ Uploaded results to GitHub Security tab")
        except subprocess.CalledProcessError:
            print("⚠️  Failed to upload to Code Scanning (gh CLI not available)")
        except Exception as e:
            print(f"⚠️  Failed to upload to Code Scanning: {str(e)}")


def main():
    """Main entry point"""
    runner = GitHubActionRunner()
    sys.exit(runner.run())


if __name__ == '__main__':
    main()