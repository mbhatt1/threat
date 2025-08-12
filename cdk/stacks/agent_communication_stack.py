"""
Agent Communication Stack - SQS queues and SNS topics for inter-agent messaging
"""
from aws_cdk import (
    Stack,
    aws_sqs as sqs,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_kms as kms,
    Duration,
    RemovalPolicy
)
from constructs import Construct
from typing import Dict


class AgentCommunicationStack(Stack):
    """Manages communication channels between security agents"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 kms_key: kms.Key = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Dead Letter Queue for failed messages
        self.dlq = sqs.Queue(
            self, "AgentDLQ",
            queue_name="security-agent-dlq",
            retention_period=Duration.days(14),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )
        
        # Agent Request Queue - for work distribution
        self.agent_request_queue = sqs.Queue(
            self, "AgentRequestQueue",
            queue_name="security-agent-requests",
            visibility_timeout=Duration.minutes(30),  # Long timeout for processing
            retention_period=Duration.days(7),
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=self.dlq
            ),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )
        
        # Agent Response Queue - for results
        self.agent_response_queue = sqs.Queue(
            self, "AgentResponseQueue",
            queue_name="security-agent-responses",
            visibility_timeout=Duration.minutes(5),
            retention_period=Duration.days(7),
            dead_letter_queue=sqs.DeadLetterQueue(
                max_receive_count=3,
                queue=self.dlq
            ),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )
        
        # Priority Queue for critical findings
        self.priority_queue = sqs.Queue(
            self, "PriorityQueue",
            queue_name="security-priority-findings",
            visibility_timeout=Duration.minutes(5),
            retention_period=Duration.days(1),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )
        
        # Agent-specific queues
        self.agent_queues: Dict[str, sqs.Queue] = {}
        
        agents = [
            "sast",
            "dependency",
            "secrets",
            "container",
            "iac",
            "threat-intel",
            "supply-chain",
            "infra-security",
            "code-analyzer"
        ]
        
        for agent in agents:
            queue = sqs.Queue(
                self, f"{agent.title().replace('-', '')}Queue",
                queue_name=f"security-agent-{agent}",
                visibility_timeout=Duration.minutes(15),
                retention_period=Duration.days(3),
                dead_letter_queue=sqs.DeadLetterQueue(
                    max_receive_count=2,
                    queue=self.dlq
                ),
                encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
                encryption_master_key=kms_key if kms_key else None
            )
            self.agent_queues[agent] = queue
        
        # SNS Topics for broadcast messaging
        self.agent_broadcast_topic = sns.Topic(
            self, "AgentBroadcastTopic",
            topic_name="security-agent-broadcast",
            display_name="Security Agent Broadcast Messages",
            master_key=kms_key if kms_key else None
        )
        
        # Critical findings topic
        self.critical_findings_topic = sns.Topic(
            self, "CriticalFindingsTopic",
            topic_name="security-critical-findings",
            display_name="Critical Security Findings",
            master_key=kms_key if kms_key else None
        )
        
        # Remediation topic
        self.remediation_topic = sns.Topic(
            self, "RemediationTopic",
            topic_name="security-remediation",
            display_name="Security Remediation Actions",
            master_key=kms_key if kms_key else None
        )
        
        # Subscribe priority queue to critical findings
        self.critical_findings_topic.add_subscription(
            subscriptions.SqsSubscription(
                self.priority_queue,
                raw_message_delivery=True
            )
        )
        
        # FIFO Queue for ordered processing
        self.ordered_processing_queue = sqs.Queue(
            self, "OrderedProcessingQueue",
            queue_name="security-ordered-processing.fifo",
            fifo=True,
            content_based_deduplication=True,
            visibility_timeout=Duration.minutes(10),
            retention_period=Duration.days(3),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )
        
        # Cross-agent coordination queue
        self.coordination_queue = sqs.Queue(
            self, "CoordinationQueue",
            queue_name="security-agent-coordination",
            visibility_timeout=Duration.minutes(5),
            retention_period=Duration.days(1),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )
        
        # Metrics queue for agent performance
        self.metrics_queue = sqs.Queue(
            self, "MetricsQueue",
            queue_name="security-agent-metrics",
            visibility_timeout=Duration.minutes(1),
            retention_period=Duration.hours(6),
            encryption=sqs.QueueEncryption.KMS if kms_key else sqs.QueueEncryption.MANAGED,
            encryption_master_key=kms_key if kms_key else None
        )