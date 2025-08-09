This document details a **Dynamic, Hierarchical, Multi-Agent Security Auditing Framework** for Git repositories. It is built entirely on AWS services and Open-Source Software (OSS), orchestrated by a central intelligence layer defined by the conceptual **HASHIRU** (Heuristic Analysis and Strategic Hierarchical Intelligence for Resource Utilization) and **Strands** frameworks.

Your task is to implement this production ready repository. 

-----

## 1\. Executive Vision & Core Principles

This system is engineered to function as an autonomous Security Operations Center (SOC) analyst specifically for source code. It moves beyond simple CI/CATE-INFRA-1002-INTG checks to provide deep, context-aware, and economically optimized security reviews.

  * **Principle of Autonomy:** The system requires minimal human intervention from request to report. It independently provisions, executes, analyzes, and terminates resources.
  * **Principle of Economic Optimization (HASHIRU):** Every action is weighed against its computational cost. The system leverages AWS Spot Instances aggressively and scales down resources when not in use, governed by a real-time economic model.
  * **Principle of Dynamic Specialization:** The system does not use a monolithic scanner. It dynamically assembles a team of specialized "agents," each an expert in a specific domain (SAST, secrets, IaC, etc.), tailored to the repository being analyzed.
  * **Principle of Extensibility:** The architecture is designed for growth. The "Autonomous Dynamic Tool Creation Agent" ensures that as new technologies and file types appear, the system can teach itself how to analyze them.

-----

## 2\. Core Concepts: HASHIRU & Strands Frameworks Defined

To understand the architecture, we must first define the behavior of its conceptual frameworks.

### HASHIRU: The Central Nervous System

**HASHIRU** is not a single piece of software, but a set of logical principles implemented within AWS Lambda functions and Step Function orchestrations. It governs the "why," "what," and "how" of the entire operation.

  * **Planning & Reasoning Engine:** Before execution, the HASHIRU CEO Agent generates a dynamic execution plan. It performs a shallow clone of the repo to analyze the file type distribution, language breakdown, and presence of IaC files. Based on this, it decides which analysis agents are necessary.
      * *Example:* A repository containing 95% Python and 5% Terraform will trigger the SAST (Semgrep), Dependency (Snyk), and IaC (Checkov) agents, but not the mobile security agent.
  * **Economic Model:** HASHIRU is directly integrated with the AWS Cost Explorer and Budgets APIs.
      * **Proactive Costing:** It fetches current Fargate Spot prices to decide between Spot and On-Demand instances for critical path tasks.
      * **Reactive Budgeting:** It operates within a `max_budget_per_scan` parameter. A CloudWatch alarm on billing tags triggers a HASHIRU "panic" function if costs escalate, which can pause the Step Function and alert an operator.
  * **Sub-CEO Delegation:** HASHIRU logic is distributed. The main CEO plans the overall strategy, but each agent group (e.g., all SAST agents) runs a "Sub-CEO" to manage and prioritize its own tasks. For instance, a SAST Sub-CEO might prioritize scanning files named `auth.py` or `payment_processing.java`.

### Strands: The Agent Communication Protocol

**Strands** defines the state and communication schema for all agents. It ensures that disparate containerized tools can work together seamlessly. Every message passed between components (e.g., via SQS or Step Function inputs) adheres to the Strands JSON schema.

**Standard Strands Message Schema:**

```json
{
  "scan_id": "uuid-v4-generated-per-scan",
  "task_id": "uuid-v4-generated-per-task",
  "agent_type": "SAST | DAST | IAC | SECRETS | DEPENDENCY | ...",
  "status": "PENDING | RUNNING | COMPLETED | FAILED | TIMEOUT",
  "timestamp_utc": "ISO-8601-timestamp",
  "payload": {
    "repository_url": "git-clone-url",
    "commit_hash": "specific-commit-sha",
    "credentials_secret_arn": "arn:aws:secretsmanager:...",
    "config": {
      "semgrep_rules": "p/ci",
      "snyk_severity_threshold": "high",
      "...",
      "max_runtime_seconds": 3600
    }
  },
  "results": {
    "output_s3_path": "s3://bucket/scan_id/task_id/results.json",
    "error_log_s3_path": "s3://bucket/scan_id/task_id/error.log",
    "metrics": {
      "execution_time_seconds": 123.45,
      "cost_usd": 0.08
    }
  }
}
```

-----

## 3\. Detailed Architecture & End-to-End Workflow

The system is orchestrated by a master AWS Step Function. This provides visibility, error handling, and state management for the entire workflow.

### Workflow State Machine:

1.  **StartScan (API Gateway -\> Lambda):**

      * A user-facing REST API endpoint receives a request: `{ "repo_url": "...", "branch": "main" }`.
      * An initial Lambda function validates the input, generates a unique `scan_id`, stores initial metadata in DynamoDB, and starts the Step Function execution.

2.  **State: `GenerateExecutionPlan` (Lambda Function):**

      * **HASHIRU CEO Logic:** This is the brain.
      * **Input:** `scan_id`, `repo_url`.
      * **Actions:**
        1.  Retrieves credentials from AWS Secrets Manager.
        2.  Executes a `git clone --depth 1` in the Lambda's temporary storage.
        3.  Uses `cloc` (Count Lines of Code) and simple file extension analysis to profile the repository.
        4.  Queries AWS Cost Explorer for current Fargate Spot pricing in the region.
        5.  **Output:** A JSON array of tasks for the next state.
            ```json
            {
              "tasks": [
                { "agent_type": "SAST", "config": { ... } },
                { "agent_type": "DEPENDENCY", "config": { ... } },
                { "agent_type": "SECRETS", "config": { ... } }
              ]
            }
            ```

3.  **State: `RunParallelAnalysis` (Map State):**

      * This state iterates over the `tasks` array from the previous step. For each task, it invokes an ECS Task.
      * It uses the **Fargate Spot task type** for maximum cost savings. The `Map` state allows all independent analyses to run in parallel, dramatically reducing wall-clock time.
      * Each task execution is passed the relevant `Strands` payload.

4.  **State: `AggregateResults` (Lambda Function):**

      * This state only runs after all parallel tasks in the `Map` state have succeeded.
      * **Input:** An array of `Strands` messages from the completed tasks.
      * **Actions:**
        1.  Iterates through the input array, reading each `results.json` file from its S3 path.
        2.  Consolidates all findings into a single, unified `aggregated_results.json` file.
        3.  De-duplicates findings based on a hash of (file, line number, vulnerability type).
        4.  Pushes findings into **AWS Security Hub** using the `BatchImportFindings` API call for native integration.
        5.  Saves the aggregated results to `s3://bucket/scan_id/processed/`.

5.  **State: `GenerateReportAndNotify` (Lambda Function):**

      * **Input:** S3 path to `aggregated_results.json`.
      * **Actions:**
        1.  Reads the aggregated results.
        2.  Generates a human-readable Markdown report.
        3.  Generates data for visualization (e.g., a summary JSON for QuickSight).
        4.  Saves both artifacts to S3.
        5.  Publishes a message to an **AWS SNS topic**.
        6.  An **AWS SES** subscription on the topic emails a notification to stakeholders with a pre-signed S3 URL to the report.
        7.  An **AWS Chatbot** subscription can post the summary to a Slack/Chime channel.

-----

## 4\. Deep Dive: Agent Specifications

Each agent is a Docker container stored in **AWS ECR**, designed to perform one task perfectly. They are invoked by the Step Function's `Map` state.

### Common Agent Structure (Dockerfile)

```dockerfile
# Use a lean base image
FROM python:3.11-slim

# Set up working directory
WORKDIR /app

# Install common utilities and the specific tool
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent's entrypoint script
COPY agent.py .

# Define the entrypoint
ENTRYPOINT ["python", "agent.py"]
```

### Agent 1: Static Application Security Testing (SAST)

  * **OSS Tool:** **Semgrep**. Chosen for its speed, low memory footprint, and YAML-based custom rule system.
  * **Container Logic (`agent.py`):**
    1.  Parses the `Strands` input from `os.environ` or command-line arguments.
    2.  Clones the specific `commit_hash` of the repository.
    3.  Runs the Semgrep command: `semgrep scan --config "p/ci" --json -o results.json .`
    4.  Parses the `results.json`, transforms it into the standard findings schema, and uploads it to the `output_s3_path` specified in the `Strands` message.
  * **Output Schema (per finding):**
    ```json
    {
      "finding_id": "sha256-of-finding-details",
      "type": "SAST",
      "severity": "HIGH | MEDIUM | LOW | INFO",
      "confidence": "HIGH | MEDIUM | LOW",
      "message": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      "file_path": "src/web/handlers.py",
      "start_line": 123,
      "end_line": 125,
      "code_snippet": "return f'<h1>Hello, {user_input}</h1>'",
      "remediation_suggestion": "Use a templating engine like Jinja2 or escape user input with html.escape()."
    }
    ```

### Agent 2: Dependency Analysis

  * **OSS Tool:** **OWASP Dependency-Check** or **Snyk CLI** (if a license is available). We will specify Dependency-Check for the pure OSS path.
  * **Container Logic (`agent.py`):**
    1.  Clones the repository.
    2.  Executes the Dependency-Check script: `dependency-check.sh --project "MyProject" --scan . --format JSON --out results/`
    3.  Parses the generated JSON report.
    4.  For each vulnerable dependency, it creates a finding record, mapping CVE data to the standard schema.
    5.  Uploads the standardized JSON to S3.

### Agent 3: Secrets Detection

  * **OSS Tool:** **TruffleHog**. Chosen for its high entropy checks and ability to verify findings against services like AWS.
  * **Container Logic (`agent.py`):**
    1.  Clones the repository.
    2.  Runs TruffleHog: `trufflehog git file:///path/to/repo --json > results.json`
    3.  Parses the output and transforms it to the standard findings schema.
    4.  **Immediate Remediation Trigger:** If a finding is verified with high confidence (e.g., a live AWS key), this agent can send a direct, high-priority message to a separate SQS queue monitored by a remediation Lambda, which could trigger a secret rotation in Secrets Manager.

-----

## 5\. Data, Analytics, and Reporting Layer

  * **Storage:** **AWS S3** is the source of truth.

      * **Bucket Structure:**
        ```
        s3://<security-scan-results-bucket>/
        ├── raw/
        │   └── <scan_id>/
        │       ├── sast/results.json
        │       └── dependency/results.json
        ├── processed/
        │   └── <scan_id>/
        │       └── aggregated_findings.json
        └── reports/
            └── <scan_id>/
                ├── security_report.md
                └── quicksight_summary.json
        ```
      * **Lifecycle Policy:** Use **S3 Intelligent-Tiering** to automatically move older scan data to cheaper storage classes.

  * **Querying:** **AWS Athena**

      * Athena allows for serverless SQL queries directly on the JSON data in S3. This is incredibly powerful for ad-hoc analysis and building dashboards without a database.
      * **Example Athena Table DDL:**
        ```sql
        CREATE EXTERNAL TABLE security_findings (
          scan_id STRING,
          finding_id STRING,
          type STRING,
          severity STRING,
          message STRING,
          file_path STRING,
          start_line INT
        )
        PARTITIONED BY (scan_date DATE)
        ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
        LOCATION 's3://<security-scan-results-bucket>/processed/';
        ```

  * **Visualization:** **AWS QuickSight**

      * Dashboards connect directly to Athena as a data source.
      * **Visuals:**
          * Time-series charts showing new vulnerabilities per day/week.
          * Pie charts breaking down vulnerabilities by severity or type (SAST vs. Dependency).
          * Tables showing the "Top 10 Most Vulnerable Files."
          * Cost-per-scan tracking dashboard.

-----

## 6\. AWS CDK Implementation (Python)

This section provides a blueprint for the Infrastructure as Code using the AWS CDK.

### `app.py` (Main Stack Definition)

```python
#!/usr/bin/env python3
import aws_cdk as cdk
from stacks.network_stack import NetworkStack
from stacks.iam_stack import IamStack
from stacks.ecs_stack import EcsStack
from stacks.step_function_stack import StepFunctionStack

app = cdk.App()

# Foundational Stacks
network = NetworkStack(app, "SecurityAgentNetwork")
iam = IamStack(app, "SecurityAgentIamRoles")

# ECS Cluster and Task Definitions
ecs = EcsStack(app, "SecurityAgentEcs",
    vpc=network.vpc,
    sast_task_role=iam.ecs_task_role,
    # ... other roles
)

# The Main Orchestrator
StepFunctionStack(app, "SecurityAgentOrchestrator",
    vpc=network.vpc,
    sast_task_definition=ecs.sast_task_definition,
    # ... other task definitions and lambda functions
    ecs_cluster=ecs.cluster
)

app.synth()
```

### `stacks/step_function_stack.py` (Orchestration Logic)

```python
from aws_cdk import (
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as sfn_tasks,
    aws_ecs as ecs,
    aws_lambda as _lambda,
    Stack,
)
from constructs import Construct

class StepFunctionStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Reference Lambda functions and ECS Task Definitions passed from other stacks
        plan_generator_lambda = kwargs["plan_generator_lambda"]
        result_aggregator_lambda = kwargs["result_aggregator_lambda"]
        sast_task_definition = kwargs["sast_task_definition"]
        ecs_cluster = kwargs["ecs_cluster"]

        # Define Step Function States
        generate_plan = sfn_tasks.LambdaInvoke(
            self, "GenerateExecutionPlan",
            lambda_function=plan_generator_lambda,
            output_path="$.Payload"
        )

        # This task will run an ECS Fargate task using a definition
        run_sast_agent = sfn_tasks.EcsRunTask(
            self, "RunSastAnalysisAgent",
            integration_pattern=sfn.IntegrationPattern.RUN_JOB, # Waits for completion
            cluster=ecs_cluster,
            task_definition=sast_task_definition,
            launch_target=sfn_tasks.EcsFargateLaunchTarget(
                platform_version=ecs.FargatePlatformVersion.LATEST
            ),
            # Dynamically set container overrides from the map state's item
            container_overrides=[sfn_tasks.ContainerOverride(
                container_definition=sast_task_definition.default_container,
                environment=[sfn_tasks.TaskEnvironmentVariable(
                    name="STRANDS_PAYLOAD",
                    value=sfn.JsonPath.string_at("$") # Pass the whole item as an env var
                )]
            )],
            # Use Spot capacity for cost savings
            capacity_provider_strategy=[ecs.CapacityProviderStrategy(
                capacity_provider="FARGATE_SPOT",
                weight=1
            )]
        )

        # Parallel Map State to run all agents
        parallel_analysis = sfn.Map(
            self, "RunParallelAnalysis",
            items_path=sfn.JsonPath.string_at("$.tasks"),
            max_concurrency=5 # Limit concurrent tasks
        )
        parallel_analysis.iterator(run_sast_agent) # Simplified; would use a Choice state to select the right agent

        aggregate_results = sfn_tasks.LambdaInvoke(
            self, "AggregateAndReport",
            lambda_function=result_aggregator_lambda,
            output_path="$.Payload"
        )

        # Define the chain of execution
        definition = generate_plan.next(parallel_analysis).next(aggregate_results)

        # Create the State Machine
        sfn.StateMachine(
            self, "GitCodebaseSecurityReviewStateMachine",
            definition=definition,
            state_machine_name="GitCodebaseSecurityReviewer"
        )
```

This CDK code provides a tangible, deployable starting point. It defines the core state machine, demonstrates how to invoke a Lambda function, how to run parallel tasks on ECS Fargate Spot, and how to pass state between each step. It is the literal translation of the architectural diagram into code.