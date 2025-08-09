"""
AWS Step Functions Stack for AI-Based Security Scanning Workflow
"""
from aws_cdk import (
    Stack,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_lambda as lambda_,
    aws_ecs as ecs,
    aws_sns as sns,
    Duration
)
from constructs import Construct
import json


class StepFunctionStack(Stack):
    """Step Functions for orchestrating AI-powered security scanning with multiple autonomous agents"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 ceo_agent_lambda,
                 ecs_cluster,
                 sns_topic,
                 aggregator_lambda,
                 report_generator_lambda,
                 remediation_lambda,
                 autonomous_task_definition,
                 bedrock_unified_task_definition,
                 autonomous_code_analyzer_task_definition,
                 autonomous_threat_intel_task_definition,
                 autonomous_infra_security_task_definition,
                 autonomous_supply_chain_task_definition,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Clone repository task
        clone_repo_task = tasks.LambdaInvoke(
            self, "CloneRepository",
            lambda_function=lambda_.Function.from_function_name(
                self, "CloneRepoFn",
                "repository-cloner"
            ),
            payload_response_only=True,
            result_path="$.repository"
        )
        
        # CEO Agent decides which agents to run
        ceo_decision = tasks.LambdaInvoke(
            self, "CEOAgentDecision",
            lambda_function=ceo_agent_lambda,
            payload=sfn.TaskInput.from_object({
                "scan_id": sfn.JsonPath.string_at("$.scan_id"),
                "repository_path": sfn.JsonPath.string_at("$.repository.path"),
                "scan_config": sfn.JsonPath.object_at("$.scan_config")
            }),
            result_path="$.execution_plan"
        )
        
        # Create parallel execution for all autonomous agents
        parallel_agents = sfn.Parallel(
            self, "ParallelAutonomousAgents",
            result_path="$.agent_results"
        )
        
        # Bedrock Unified Security Scanner
        bedrock_unified_scan = self._create_ecs_task(
            "BedrockUnifiedScan",
            bedrock_unified_task_definition,
            ecs_cluster,
            "bedrock_unified"
        )
        parallel_agents.branch(bedrock_unified_scan)
        
        # Autonomous Dynamic Tool Creation Agent
        autonomous_agent_scan = self._create_ecs_task(
            "AutonomousAgentScan",
            autonomous_task_definition,
            ecs_cluster,
            "autonomous"
        )
        parallel_agents.branch(autonomous_agent_scan)
        
        # Autonomous Code Analyzer
        code_analyzer_scan = self._create_ecs_task(
            "AutonomousCodeAnalyzer",
            autonomous_code_analyzer_task_definition,
            ecs_cluster,
            "autonomous_code_analyzer"
        )
        parallel_agents.branch(code_analyzer_scan)
        
        # Autonomous Threat Intelligence
        threat_intel_scan = self._create_ecs_task(
            "AutonomousThreatIntel",
            autonomous_threat_intel_task_definition,
            ecs_cluster,
            "autonomous_threat_intel"
        )
        parallel_agents.branch(threat_intel_scan)
        
        # Autonomous Infrastructure Security
        infra_security_scan = self._create_ecs_task(
            "AutonomousInfraSecurity",
            autonomous_infra_security_task_definition,
            ecs_cluster,
            "autonomous_infra_security"
        )
        parallel_agents.branch(infra_security_scan)
        
        # Autonomous Supply Chain Security
        supply_chain_scan = self._create_ecs_task(
            "AutonomousSupplyChain",
            autonomous_supply_chain_task_definition,
            ecs_cluster,
            "autonomous_supply_chain"
        )
        parallel_agents.branch(supply_chain_scan)
        
        # AI-powered aggregation of all results
        aggregate_results = tasks.LambdaInvoke(
            self, "AggregateAIResults",
            lambda_function=aggregator_lambda,
            payload=sfn.TaskInput.from_object({
                "scan_id": sfn.JsonPath.string_at("$.scan_id"),
                "agent_results": sfn.JsonPath.object_at("$.agent_results"),
                "execution_plan": sfn.JsonPath.object_at("$.execution_plan")
            }),
            result_path="$.aggregated_results"
        )
        
        # Generate comprehensive AI report
        generate_report = tasks.LambdaInvoke(
            self, "GenerateAIReport",
            lambda_function=report_generator_lambda,
            payload=sfn.TaskInput.from_object({
                "scan_id": sfn.JsonPath.string_at("$.scan_id"),
                "aggregated_results": sfn.JsonPath.object_at("$.aggregated_results")
            }),
            result_path="$.report"
        )
        
        # Check if automatic remediation is needed
        check_remediation = sfn.Choice(
            self, "CheckRemediationNeeded"
        ).when(
            sfn.Condition.and_(
                sfn.Condition.number_greater_than("$.aggregated_results.risk_score", 80),
                sfn.Condition.boolean_equals("$.scan_config.auto_remediate", True)
            ),
            tasks.LambdaInvoke(
                self, "TriggerRemediation",
                lambda_function=remediation_lambda,
                payload=sfn.TaskInput.from_object({
                    "scan_id": sfn.JsonPath.string_at("$.scan_id"),
                    "critical_findings": sfn.JsonPath.object_at("$.aggregated_results.critical_findings"),
                    "remediation_plan": sfn.JsonPath.object_at("$.aggregated_results.remediation_plan")
                }),
                result_path="$.remediation_result"
            ).next(self._create_notification_task(sns_topic, "COMPLETED_WITH_REMEDIATION"))
        ).otherwise(
            self._create_notification_task(sns_topic, "COMPLETED")
        )
        
        # Success state
        success = sfn.Succeed(
            self, "ScanComplete",
            comment="AI-powered security scan completed successfully"
        )
        
        # Failure state
        failure = sfn.Fail(
            self, "ScanFailed",
            cause="Security scan failed",
            error="ScanError"
        )
        
        # Error handler
        error_handler = tasks.SnsPublish(
            self, "NotifyError",
            topic=sns_topic,
            message=sfn.TaskInput.from_object({
                "scan_id": sfn.JsonPath.string_at("$.scan_id"),
                "status": "FAILED",
                "error": sfn.JsonPath.object_at("$.error")
            })
        ).next(failure)
        
        # Build the state machine
        definition = clone_repo_task \
            .next(ceo_decision) \
            .next(parallel_agents) \
            .next(aggregate_results) \
            .next(generate_report) \
            .next(check_remediation) \
            .next(success)
        
        # Add error handling
        for state in [clone_repo_task, ceo_decision, parallel_agents, aggregate_results, generate_report]:
            state.add_catch(error_handler, result_path="$.error")
        
        # Create the state machine
        self.state_machine = sfn.StateMachine(
            self, "AISecurityScanStateMachine",
            definition=definition,
            timeout=Duration.hours(4),  # Increased for multiple AI agents
            tracing_enabled=True,
            state_machine_name="ai-autonomous-security-scan-orchestrator"
        )
    
    def _create_ecs_task(self, name: str, task_definition: ecs.TaskDefinition, 
                        ecs_cluster: ecs.Cluster, agent_name: str) -> tasks.EcsRunTask:
        """Create an ECS task for an autonomous agent"""
        return tasks.EcsRunTask(
            self, name,
            integration_pattern=sfn.IntegrationPattern.RUN_JOB,
            cluster=ecs_cluster,
            task_definition=task_definition,
            assign_public_ip=False,
            container_overrides=[
                tasks.ContainerOverride(
                    container_definition=task_definition.default_container,
                    environment=[
                        tasks.TaskEnvironmentVariable(
                            name="SCAN_ID",
                            value=sfn.JsonPath.string_at("$.scan_id")
                        ),
                        tasks.TaskEnvironmentVariable(
                            name="REPOSITORY_PATH",
                            value=sfn.JsonPath.string_at("$.repository.path")
                        ),
                        tasks.TaskEnvironmentVariable(
                            name="SCAN_CONFIG",
                            value=sfn.JsonPath.json_to_string(sfn.JsonPath.object_at("$.scan_config"))
                        ),
                        tasks.TaskEnvironmentVariable(
                            name="EXECUTION_PLAN",
                            value=sfn.JsonPath.json_to_string(sfn.JsonPath.object_at("$.execution_plan"))
                        )
                    ]
                )
            ],
            result_path=f"$.{agent_name}_results"
        )
    
    def _create_notification_task(self, sns_topic: sns.Topic, status: str) -> tasks.SnsPublish:
        """Create notification task"""
        return tasks.SnsPublish(
            self, f"Notify{status}",
            topic=sns_topic,
            message=sfn.TaskInput.from_object({
                "scan_id": sfn.JsonPath.string_at("$.scan_id"),
                "status": status,
                "risk_score": sfn.JsonPath.number_at("$.aggregated_results.overall_risk_score"),
                "critical_findings": sfn.JsonPath.number_at("$.aggregated_results.critical_count"),
                "high_findings": sfn.JsonPath.number_at("$.aggregated_results.high_count"),
                "report_url": sfn.JsonPath.string_at("$.report.report_url"),
                "total_agents_run": 6,  # All autonomous agents
                "scan_duration": sfn.JsonPath.string_at("$.report.scan_duration")
            })
        )