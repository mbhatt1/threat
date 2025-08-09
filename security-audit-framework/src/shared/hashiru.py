"""
HASHIRU Framework - Heuristic Analysis and Strategic Hierarchical Intelligence
for Resource Utilization
"""
import os
import subprocess
import json
from typing import Dict, List, Tuple, Any, Optional
from collections import defaultdict
import boto3
from datetime import datetime, timedelta
import logging
from decimal import Decimal
import hashlib

from .sub_ceo import SubCEOAgent, FilePriority

logger = logging.getLogger(__name__)


class CostOptimizer:
    """Economic model for cost optimization decisions with enhanced Cost Explorer integration"""
    
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.ce_client = boto3.client('ce', region_name=region)
        self.pricing_client = boto3.client('pricing', region_name='us-east-1')  # Pricing API only in us-east-1
        self.ec2_client = boto3.client('ec2', region_name=region)
        self._pricing_cache = {}
        self._cache_ttl = 3600  # Cache pricing for 1 hour
        self.account_id = boto3.client('sts').get_caller_identity()['Account']
        
    def get_fargate_spot_pricing(self) -> Dict[str, float]:
        """Get actual current Fargate Spot pricing from AWS"""
        cache_key = f"fargate_spot_{self.region}"
        
        # Check cache
        if cache_key in self._pricing_cache:
            cached_data, timestamp = self._pricing_cache[cache_key]
            if (datetime.utcnow() - timestamp).seconds < self._cache_ttl:
                return cached_data
        
        try:
            # Get Fargate pricing from AWS Pricing API
            response = self.pricing_client.get_products(
                ServiceCode='AmazonECS',
                Filters=[
                    {
                        'Type': 'TERM_MATCH',
                        'Field': 'location',
                        'Value': self._get_region_name(self.region)
                    },
                    {
                        'Type': 'TERM_MATCH',
                        'Field': 'launchType',
                        'Value': 'Fargate'
                    },
                    {
                        'Type': 'TERM_MATCH',
                        'Field': 'capacityStatus',
                        'Value': 'Spot'
                    }
                ],
                MaxResults=100
            )
            
            pricing = {
                'vcpu_per_hour': 0.0,
                'memory_gb_per_hour': 0.0
            }
            
            for price_item in response['PriceList']:
                price_data = json.loads(price_item)
                
                # Extract pricing dimensions
                on_demand = price_data.get('terms', {}).get('OnDemand', {})
                for term_key, term_data in on_demand.items():
                    for price_dim_key, price_dim in term_data.get('priceDimensions', {}).items():
                        if 'vCPU' in price_dim.get('description', ''):
                            pricing['vcpu_per_hour'] = float(price_dim['pricePerUnit']['USD'])
                        elif 'GB' in price_dim.get('description', '') and 'memory' in price_dim.get('description', '').lower():
                            pricing['memory_gb_per_hour'] = float(price_dim['pricePerUnit']['USD'])
            
            # Apply Spot discount (typically 70% off on-demand)
            pricing['vcpu_per_hour'] *= 0.3
            pricing['memory_gb_per_hour'] *= 0.3
            
            # Cache the result
            self._pricing_cache[cache_key] = (pricing, datetime.utcnow())
            
            return pricing
            
        except Exception as e:
            logger.error(f"Failed to get AWS pricing: {e}")
            # Return default pricing as fallback
            return {
                'vcpu_per_hour': 0.04048,
                'memory_gb_per_hour': 0.004445
            }
    
    def _get_region_name(self, region_code: str) -> str:
        """Convert region code to human-readable name for pricing API"""
        region_names = {
            'us-east-1': 'US East (N. Virginia)',
            'us-east-2': 'US East (Ohio)',
            'us-west-1': 'US West (N. California)',
            'us-west-2': 'US West (Oregon)',
            'eu-west-1': 'EU (Ireland)',
            'eu-central-1': 'EU (Frankfurt)',
            'ap-southeast-1': 'Asia Pacific (Singapore)',
            'ap-northeast-1': 'Asia Pacific (Tokyo)',
            # Add more regions as needed
        }
        return region_names.get(region_code, 'US East (N. Virginia)')
    
    def get_current_budget_usage(self, budget_name: str) -> Dict[str, Any]:
        """Get current budget usage from AWS Budgets"""
        try:
            budgets_client = boto3.client('budgets')
            account_id = boto3.client('sts').get_caller_identity()['Account']
            
            response = budgets_client.describe_budget(
                AccountId=account_id,
                BudgetName=budget_name
            )
            
            budget = response['Budget']
            
            # Get actual spend
            ce_response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': budget['TimePeriod']['Start'].strftime('%Y-%m-%d'),
                    'End': datetime.utcnow().strftime('%Y-%m-%d')
                },
                Granularity='DAILY',
                Metrics=['UnblendedCost']
            )
            
            total_cost = sum(
                float(day['Total']['UnblendedCost']['Amount'])
                for day in ce_response['ResultsByTime']
            )
            
            budget_limit = float(budget['BudgetLimit']['Amount'])
            
            return {
                'budget_name': budget_name,
                'limit': budget_limit,
                'actual_spend': total_cost,
                'percentage_used': (total_cost / budget_limit) * 100,
                'remaining': budget_limit - total_cost
            }
            
        except Exception as e:
            logger.error(f"Failed to get budget usage: {e}")
            return None
    
    def estimate_task_cost(self, vcpus: float, memory_gb: float, 
                          estimated_runtime_seconds: int, use_spot: bool = True) -> float:
        """Estimate the cost of running a Fargate task"""
        pricing = self.get_fargate_spot_pricing()
        
        if not use_spot:
            # On-demand pricing (remove Spot discount)
            pricing['vcpu_per_hour'] /= 0.3
            pricing['memory_gb_per_hour'] /= 0.3
        
        runtime_hours = estimated_runtime_seconds / 3600
        
        cost = (vcpus * pricing['vcpu_per_hour'] + 
                memory_gb * pricing['memory_gb_per_hour']) * runtime_hours
        
        # Fargate minimum billing is 1 minute
        min_cost = (vcpus * pricing['vcpu_per_hour'] + 
                    memory_gb * pricing['memory_gb_per_hour']) / 60
        
        return round(max(cost, min_cost), 4)
    
    def get_spot_interruption_rate(self) -> float:
        """Get historical Spot interruption rate for Fargate in the region"""
        try:
            # Query CloudWatch metrics for Spot interruptions
            cw_client = boto3.client('cloudwatch', region_name=self.region)
            
            response = cw_client.get_metric_statistics(
                Namespace='AWS/ECS',
                MetricName='SpotInterruptions',
                Dimensions=[
                    {
                        'Name': 'LaunchType',
                        'Value': 'FARGATE_SPOT'
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(days=7),
                EndTime=datetime.utcnow(),
                Period=86400,  # Daily
                Statistics=['Average']
            )
            
            if response['Datapoints']:
                avg_interruptions = sum(dp['Average'] for dp in response['Datapoints']) / len(response['Datapoints'])
                return avg_interruptions
            else:
                return 0.02  # Default 2% interruption rate
                
        except Exception as e:
            logger.error(f"Failed to get interruption rate: {e}")
            return 0.02
    
    def should_use_spot(self, task_priority: str, deadline_minutes: int, 
                       max_interruption_tolerance: float = 0.05) -> bool:
        """Determine if Spot instances should be used based on priority, deadline, and interruption tolerance"""
        if task_priority == 'critical':
            return False
            
        if deadline_minutes < 30:
            return False
            
        # Check interruption rate
        interruption_rate = self.get_spot_interruption_rate()
        if interruption_rate > max_interruption_tolerance:
            logger.warning(f"Spot interruption rate {interruption_rate} exceeds tolerance {max_interruption_tolerance}")
            return False
            
        return True
    
    def get_cost_forecast(self, days: int = 30) -> Dict[str, Any]:
        """Get cost forecast using Cost Explorer API"""
        try:
            start_date = datetime.utcnow().date()
            end_date = (start_date + timedelta(days=days))
            
            response = self.ce_client.get_cost_forecast(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Metric='UNBLENDED_COST',
                Granularity='DAILY'
            )
            
            forecast_data = []
            for result in response.get('ForecastResultsByTime', []):
                forecast_data.append({
                    'date': result['TimePeriod']['Start'],
                    'amount': float(result['MeanValue']),
                    'lower_bound': float(result.get('PredictionIntervalLowerBound', 0)),
                    'upper_bound': float(result.get('PredictionIntervalUpperBound', 0))
                })
            
            total_forecast = sum(f['amount'] for f in forecast_data)
            
            return {
                'forecast_period_days': days,
                'total_forecast': round(total_forecast, 2),
                'daily_forecast': forecast_data,
                'average_daily_cost': round(total_forecast / days, 2)
            }
            
        except Exception as e:
            logger.error(f"Failed to get cost forecast: {e}")
            return None
    
    def get_cost_anomalies(self) -> List[Dict[str, Any]]:
        """Detect cost anomalies using Cost Explorer API"""
        try:
            # First create an anomaly detector if it doesn't exist
            ce_anomaly_client = boto3.client('ce', region_name='us-east-1')
            
            # Get existing monitors
            monitors = ce_anomaly_client.get_anomaly_monitors()
            
            if not monitors.get('AnomalyMonitors'):
                # Create a new anomaly monitor
                ce_anomaly_client.create_anomaly_monitor(
                    AnomalyMonitor={
                        'MonitorName': 'SecurityAuditFramework-Monitor',
                        'MonitorType': 'DIMENSIONAL',
                        'MonitorDimension': 'SERVICE'
                    }
                )
            
            # Get anomalies
            response = ce_anomaly_client.get_anomalies(
                DateInterval={
                    'StartDate': (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d'),
                    'EndDate': datetime.utcnow().strftime('%Y-%m-%d')
                }
            )
            
            anomalies = []
            for anomaly in response.get('Anomalies', []):
                anomalies.append({
                    'anomaly_id': anomaly['AnomalyId'],
                    'start_date': anomaly['AnomalyStartDate'],
                    'end_date': anomaly.get('AnomalyEndDate'),
                    'dimension': anomaly.get('DimensionValue'),
                    'max_impact': float(anomaly.get('MaxImpact', 0)),
                    'total_impact': float(anomaly.get('TotalImpact', 0))
                })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Failed to get cost anomalies: {e}")
            return []
    
    def get_resource_cost_breakdown(self, start_date: str = None, end_date: str = None) -> Dict[str, Any]:
        """Get detailed cost breakdown by resource using tags"""
        try:
            if not start_date:
                start_date = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')
            if not end_date:
                end_date = datetime.utcnow().strftime('%Y-%m-%d')
            
            # Get cost by service
            service_response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='DAILY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ]
            )
            
            # Get cost by tags (for security audit framework)
            tag_response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='DAILY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'TAG',
                        'Key': 'Project'
                    },
                    {
                        'Type': 'TAG',
                        'Key': 'Environment'
                    }
                ],
                Filter={
                    'Tags': {
                        'Key': 'Project',
                        'Values': ['SecurityAuditFramework']
                    }
                }
            )
            
            # Process results
            service_costs = defaultdict(float)
            for result in service_response['ResultsByTime']:
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    service_costs[service] += cost
            
            framework_costs = defaultdict(float)
            for result in tag_response['ResultsByTime']:
                for group in result.get('Groups', []):
                    tags = group['Keys']
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    tag_key = f"{tags[0]}_{tags[1]}" if len(tags) > 1 else tags[0]
                    framework_costs[tag_key] += cost
            
            return {
                'period': {
                    'start': start_date,
                    'end': end_date
                },
                'service_breakdown': dict(service_costs),
                'framework_costs': dict(framework_costs),
                'total_cost': sum(service_costs.values())
            }
            
        except Exception as e:
            logger.error(f"Failed to get resource cost breakdown: {e}")
            return None
    
    def get_cost_recommendations(self) -> List[Dict[str, Any]]:
        """Get cost optimization recommendations from Cost Explorer"""
        try:
            recommendations = []
            
            # Get rightsizing recommendations
            rightsizing_response = self.ce_client.get_rightsizing_recommendation(
                Service='EC2',
                Configuration={
                    'BenefitsConsidered': False,
                    'RecommendationTarget': 'SAME_INSTANCE_FAMILY'
                }
            )
            
            for rec in rightsizing_response.get('RightsizingRecommendations', []):
                recommendations.append({
                    'type': 'rightsizing',
                    'resource_id': rec['ResourceId'],
                    'current_instance': rec['CurrentInstance'],
                    'recommended_instance': rec['ModifyRecommendationDetail']['TargetInstances'][0] if rec.get('ModifyRecommendationDetail') else None,
                    'estimated_monthly_savings': float(rec.get('EstimatedMonthlySavings', {}).get('Value', 0))
                })
            
            # Get Reserved Instance recommendations
            ri_response = self.ce_client.get_reservation_purchase_recommendation(
                Service='EC2',
                AccountScope='PAYER',
                LookbackPeriodInDays='THIRTY_DAYS',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT'
            )
            
            for rec in ri_response.get('Recommendations', []):
                recommendations.append({
                    'type': 'reserved_instance',
                    'service': 'EC2',
                    'instance_family': rec.get('InstanceDetails', {}).get('InstanceFamily'),
                    'estimated_monthly_savings': float(rec.get('EstimatedMonthlySavings', 0))
                })
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to get cost recommendations: {e}")
            return []
    
    def analyze_scan_cost_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyze cost trends specifically for security scans"""
        try:
            end_date = datetime.utcnow().date()
            start_date = end_date - timedelta(days=days)
            
            # Get costs grouped by scan ID tag
            response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='DAILY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'TAG',
                        'Key': 'ScanId'
                    }
                ],
                Filter={
                    'Tags': {
                        'Key': 'Project',
                        'Values': ['SecurityAuditFramework']
                    }
                }
            )
            
            # Process scan costs
            scan_costs = defaultdict(float)
            daily_costs = defaultdict(float)
            
            for result in response['ResultsByTime']:
                date = result['TimePeriod']['Start']
                for group in result.get('Groups', []):
                    scan_id = group['Keys'][0] if group['Keys'][0] else 'untagged'
                    cost = float(group['Metrics']['UnblendedCost']['Amount'])
                    scan_costs[scan_id] += cost
                    daily_costs[date] += cost
            
            # Calculate trends
            costs_list = list(daily_costs.values())
            avg_daily_cost = sum(costs_list) / len(costs_list) if costs_list else 0
            
            # Simple trend calculation
            if len(costs_list) > 1:
                first_half_avg = sum(costs_list[:len(costs_list)//2]) / (len(costs_list)//2)
                second_half_avg = sum(costs_list[len(costs_list)//2:]) / (len(costs_list) - len(costs_list)//2)
                trend_percentage = ((second_half_avg - first_half_avg) / first_half_avg * 100) if first_half_avg > 0 else 0
            else:
                trend_percentage = 0
            
            return {
                'period_days': days,
                'total_cost': sum(scan_costs.values()),
                'average_daily_cost': round(avg_daily_cost, 2),
                'trend_percentage': round(trend_percentage, 2),
                'scan_costs': dict(scan_costs),
                'daily_breakdown': dict(daily_costs),
                'most_expensive_scan': max(scan_costs.items(), key=lambda x: x[1]) if scan_costs else None,
                'total_scans': len(scan_costs)
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze scan cost trends: {e}")
            return None


class RepositoryAnalyzer:
    """Analyzes repository structure to determine required security agents"""
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.file_stats = defaultdict(int)
        self.total_lines = 0
        self.analysis_results = {}
        
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive repository analysis"""
        logger.info(f"Analyzing repository at {self.repo_path}")
        
        # Run cloc for language statistics
        try:
            cloc_result = subprocess.run(
                ['cloc', '--json', self.repo_path],
                capture_output=True,
                text=True,
                check=True
            )
            cloc_data = json.loads(cloc_result.stdout)
            
            # Process language statistics
            languages = {}
            total_code_lines = 0
            
            for lang, stats in cloc_data.items():
                if lang not in ['header', 'SUM']:
                    languages[lang] = {
                        'files': stats['nFiles'],
                        'lines': stats['code'],
                        'percentage': 0  # Will calculate after
                    }
                    total_code_lines += stats['code']
            
            # Calculate percentages
            for lang in languages:
                languages[lang]['percentage'] = round(
                    (languages[lang]['lines'] / total_code_lines) * 100, 2
                )
            
            self.analysis_results['languages'] = languages
            self.analysis_results['total_lines'] = total_code_lines
            
        except subprocess.CalledProcessError as e:
            logger.error(f"cloc failed: {e}")
            # Fallback to basic file analysis
            self._basic_file_analysis()
        
        # Analyze for specific security-relevant patterns
        self._analyze_security_patterns()
        
        # Determine required agents
        self.analysis_results['recommended_agents'] = self._recommend_agents()
        
        return self.analysis_results
    
    def _basic_file_analysis(self):
        """Basic file analysis when cloc is not available"""
        for root, dirs, files in os.walk(self.repo_path):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
                
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                self.file_stats[ext] += 1
                
                # Count lines in text files
                if ext in ['.py', '.js', '.java', '.go', '.rs', '.c', '.cpp', '.h']:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            self.total_lines += len(f.readlines())
                    except:
                        pass
        
        self.analysis_results['file_extensions'] = dict(self.file_stats)
        self.analysis_results['total_lines'] = self.total_lines
    
    def _analyze_security_patterns(self):
        """Analyze for security-relevant patterns"""
        patterns = {
            'iac_files': {
                'terraform': ['.tf', '.tfvars'],
                'cloudformation': ['.yaml', '.yml', '.json'],
                'kubernetes': ['deployment.yaml', 'k8s.yaml', '.helm'],
                'docker': ['Dockerfile', 'docker-compose.yml']
            },
            'config_files': {
                'env': ['.env', '.env.example'],
                'properties': ['.properties', '.ini', '.cfg'],
                'secrets': ['secrets.yml', 'credentials.json']
            },
            'dependency_files': {
                'python': ['requirements.txt', 'Pipfile', 'pyproject.toml'],
                'node': ['package.json', 'yarn.lock', 'package-lock.json'],
                'java': ['pom.xml', 'build.gradle'],
                'go': ['go.mod', 'go.sum'],
                'rust': ['Cargo.toml', 'Cargo.lock']
            }
        }
        
        found_patterns = defaultdict(list)
        
        for root, dirs, files in os.walk(self.repo_path):
            if '.git' in dirs:
                dirs.remove('.git')
                
            for file in files:
                for category, subcategories in patterns.items():
                    for subcat, file_patterns in subcategories.items():
                        for pattern in file_patterns:
                            if file.endswith(pattern) or pattern in file:
                                found_patterns[category].append({
                                    'type': subcat,
                                    'file': os.path.relpath(os.path.join(root, file), self.repo_path)
                                })
        
        self.analysis_results['security_patterns'] = dict(found_patterns)
    
    def _recommend_agents(self) -> List[Dict[str, Any]]:
        """Recommend security agents based on analysis"""
        recommendations = []
        
        # Always include SAST for code analysis
        if self.analysis_results.get('total_lines', 0) > 0:
            recommendations.append({
                'agent': 'SAST',
                'priority': 'high',
                'reason': 'Source code detected',
                'estimated_runtime': self._estimate_runtime('SAST')
            })
        
        # Check for dependencies
        if 'dependency_files' in self.analysis_results.get('security_patterns', {}):
            recommendations.append({
                'agent': 'DEPENDENCY',
                'priority': 'high',
                'reason': 'Dependency files detected',
                'estimated_runtime': self._estimate_runtime('DEPENDENCY')
            })
        
        # Always run secrets detection
        recommendations.append({
            'agent': 'SECRETS',
            'priority': 'critical',
            'reason': 'Essential for all repositories',
            'estimated_runtime': self._estimate_runtime('SECRETS')
        })
        
        # Check for IaC files
        if 'iac_files' in self.analysis_results.get('security_patterns', {}):
            recommendations.append({
                'agent': 'IAC',
                'priority': 'high',
                'reason': 'Infrastructure as Code files detected',
                'estimated_runtime': self._estimate_runtime('IAC')
            })
        
        # Always include Autonomous agent for pattern learning (runs after initial scan)
        recommendations.append({
            'agent': 'AUTONOMOUS',
            'priority': 'medium',
            'reason': 'Machine learning analysis for pattern detection and tool creation',
            'estimated_runtime': self._estimate_runtime('AUTONOMOUS')
        })
        
        return recommendations
    
    def _estimate_runtime(self, agent_type: str) -> int:
        """Estimate runtime in seconds based on repository size and agent type"""
        base_times = {
            'SAST': 300,  # 5 minutes base
            'DEPENDENCY': 180,  # 3 minutes base
            'SECRETS': 120,  # 2 minutes base
            'IAC': 240,  # 4 minutes base
            'AUTONOMOUS': 600  # 10 minutes base
        }
        
        base_time = base_times.get(agent_type, 300)
        
        # Adjust based on repository size
        total_lines = self.analysis_results.get('total_lines', 0)
        if total_lines > 100000:
            multiplier = 3
        elif total_lines > 50000:
            multiplier = 2
        elif total_lines > 10000:
            multiplier = 1.5
        else:
            multiplier = 1
        
        return int(base_time * multiplier)


class ExecutionPlanner:
    """Plans and optimizes the execution of security analysis tasks"""
    
    def __init__(self, scan_id: str, max_budget: float = 10.0, repo_path: str = None):
        self.scan_id = scan_id
        self.max_budget = max_budget
        self.cost_optimizer = CostOptimizer()
        self.repo_path = repo_path
        self.sub_ceo_agent = None
        if repo_path:
            self.sub_ceo_agent = SubCEOAgent(repo_path)
        
    async def create_execution_plan(self, repo_analysis: Dict[str, Any],
                            priority: str = 'normal') -> Dict[str, Any]:
        """Create an optimized execution plan based on repository analysis and agent performance"""
        recommendations = repo_analysis.get('recommended_agents', [])
        
        # Get top performing agents
        top_performers = await self.performance_manager.get_top_performers()
        top_performer_types = {p['agent_type'] for p in top_performers}
        
        # Check agent employment status
        agent_statuses = {}
        for rec in recommendations:
            agent_type = rec['agent']
            history = self.performance_manager._get_agent_history(agent_type)
            if history:
                latest = history[0]
                status = self.performance_manager._evaluate_employment_status(latest)
                agent_statuses[agent_type] = status
        
        # Use Sub-CEO agent for file prioritization if available
        file_analysis = None
        if self.sub_ceo_agent:
            try:
                file_analysis = self.sub_ceo_agent.analyze_and_group_files()
                logger.info(f"Sub-CEO analysis complete: {file_analysis['total_groups']} file groups created")
            except Exception as e:
                logger.error(f"Sub-CEO analysis failed: {e}")
        
        tasks = []
        total_estimated_cost = 0
        total_estimated_time = 0
        
        for rec in recommendations:
            agent_type = rec['agent']
            runtime = rec['estimated_runtime']
            
            # Determine resource allocation based on agent type
            resources = self._get_agent_resources(agent_type)
            
            # Determine if we should use Spot
            use_spot = self.cost_optimizer.should_use_spot(
                task_priority=rec['priority'],
                deadline_minutes=60  # Default 1 hour deadline
            )
            
            # Estimate cost
            task_cost = self.cost_optimizer.estimate_task_cost(
                vcpus=resources['vcpus'],
                memory_gb=resources['memory_gb'],
                estimated_runtime_seconds=runtime,
                use_spot=use_spot
            )
            
            if total_estimated_cost + task_cost > self.max_budget:
                logger.warning(f"Skipping {agent_type} due to budget constraints")
                continue
            
            # Check if agent is "fired" or on probation
            agent_status = agent_statuses.get(agent_type, {})
            if agent_status.get('status') == 'fired':
                logger.warning(f"Skipping {agent_type} - Agent fired for poor performance")
                continue
            
            # Adjust priority based on performance
            task_priority = rec['priority']
            if agent_type in top_performer_types:
                task_priority = 'high' if task_priority == 'normal' else task_priority
                logger.info(f"Promoting {agent_type} to higher priority - top performer")
            elif agent_status.get('status') == 'probation':
                task_priority = 'low'
                logger.warning(f"Demoting {agent_type} to low priority - on probation")
            
            # Adjust resources for top performers
            if agent_type in top_performer_types:
                resources['vcpus'] *= 1.5  # Give 50% more CPU
                resources['memory_gb'] *= 1.5  # Give 50% more memory
                logger.info(f"Allocating extra resources to top performer {agent_type}")
            
            tasks.append({
                'agent_type': agent_type,
                'priority': task_priority,
                'resources': resources,
                'use_spot': use_spot,
                'estimated_runtime': runtime,
                'estimated_cost': task_cost,
                'config': self._get_agent_config(agent_type),
                'performance_status': agent_status.get('status', 'new'),
                'is_top_performer': agent_type in top_performer_types
            })
            
            total_estimated_cost += task_cost
            total_estimated_time = max(total_estimated_time, runtime)  # Parallel execution
        
        # Sort tasks by priority
        priority_order = {'critical': 0, 'high': 1, 'normal': 2, 'low': 3}
        tasks.sort(key=lambda x: priority_order.get(x['priority'], 99))
        
        return {
            'scan_id': self.scan_id,
            'tasks': tasks,
            'total_estimated_cost': round(total_estimated_cost, 4),
            'total_estimated_time': total_estimated_time,
            'max_parallel_tasks': min(len(tasks), 5),  # Limit parallelism
            'execution_strategy': 'parallel' if len(tasks) > 1 else 'sequential',
            'performance_optimized': True,
            'top_performers': [t['agent_type'] for t in tasks if t.get('is_top_performer')],
            'agents_on_probation': [t['agent_type'] for t in tasks if t.get('performance_status') == 'probation']
        }
    
    def _get_agent_resources(self, agent_type: str) -> Dict[str, float]:
        """Get resource allocation for each agent type"""
        # Based on agent requirements and AWS Fargate constraints
        resources = {
            'SAST': {'vcpus': 1.0, 'memory_gb': 2.0},
            'DEPENDENCY': {'vcpus': 0.5, 'memory_gb': 1.0},
            'SECRETS': {'vcpus': 0.5, 'memory_gb': 1.0},
            'IAC': {'vcpus': 1.0, 'memory_gb': 2.0}
        }
        return resources.get(agent_type, {'vcpus': 0.5, 'memory_gb': 1.0})
    
    def _get_agent_config(self, agent_type: str) -> Dict[str, Any]:
        """Get default configuration for each agent type"""
        configs = {
            'SAST': {
                'ai_analysis_mode': 'comprehensive',
                'include_test_files': False,
                'severity_threshold': 'medium'
            },
            'DEPENDENCY': {
                'check_licenses': True,
                'fail_on_cvss': 7.0,
                'include_dev_dependencies': True
            },
            'SECRETS': {
                'entropy_threshold': 3.5,
                'verify_secrets': True,
                'excluded_paths': ['.git', 'node_modules', '__pycache__']
            },
            'IAC': {
                'frameworks': ['terraform', 'cloudformation', 'kubernetes'],
                'skip_suppressions': False,
                'compact_output': True
            }
        }
        return configs.get(agent_type, {})