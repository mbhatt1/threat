# Dynamic Tool Creation API

## Overview

The Autonomous Agent supports dynamic tool creation requests from other agents in the system. This allows agents to request new security tools based on emerging patterns, specific needs, or new threat intelligence.

## How It Works

Other agents can request dynamic tool creation by sending a `TASK_ASSIGNMENT` message to the Autonomous Agent with a specific context structure.

## Request Format

To request dynamic tool creation, send a StrandsMessage with the following structure:

```python
from shared.strands import StrandsProtocol, MessageType

protocol = StrandsProtocol()

# Create tool creation request
message = protocol.create_task_assignment(
    task_id="tool-creation-001",
    sender_id="YOUR_AGENT_ID",
    recipient_id="AUTONOMOUS",
    context={
        "action": "create_dynamic_tool",
        "tool_request": {
            "tool_type": "custom_vulnerability_detector",
            "specification": {
                "target_agent": "ai_code",  # Which agent type will use this tool
                "description": "Detect custom vulnerability pattern",
                "default_severity": "HIGH",
                "pattern_type": "code_analysis",
                "detection_logic": {
                    "focus_areas": ["authentication", "authorization"],
                    "languages": ["python", "javascript"],
                    "frameworks": ["django", "express"]
                }
            },
            "training_data": [  # Optional: provide examples
                {
                    "type": "insecure_authentication",
                    "severity": "HIGH",
                    "description": "Weak authentication mechanism",
                    "metadata": {
                        "cwe_id": "CWE-287",
                        "example_code": "if password == 'admin123':"
                    }
                }
            ]
        }
    }
)

# Send the message (implementation depends on your agent's setup)
protocol.send_message(message)
```

## Request Parameters

### Required Fields

- `action`: Must be set to `"create_dynamic_tool"`
- `tool_request.tool_type`: Unique identifier for the tool type
- `tool_request.specification`: Tool specification object containing:
  - `target_agent`: Agent type that will use this tool (e.g., "ai_code", "dependency", "secrets", "iac")
  - `description`: Human-readable description of the tool

### Optional Fields

- `tool_request.specification.default_severity`: Default severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `tool_request.specification.pattern_type`: Type of pattern to detect
- `tool_request.specification.detection_logic`: Custom logic parameters
- `tool_request.training_data`: Array of example findings to train the tool

## Response Format

The Autonomous Agent will respond with a `RESULT` message containing:

```json
{
    "tool_created": true,
    "tool_type": "custom_vulnerability_detector",
    "agent_type": "ai_code",
    "rules_generated": 5,
    "rules_deployed": 5,
    "deployed_to": ["ai_code"]
}
```

## Error Handling

If the tool creation fails, you'll receive an `ERROR` message with details:

```json
{
    "message_type": "ERROR",
    "error": "Failed to create tool: Invalid specification"
}
```

## Example: Creating a Custom SQL Injection Detector

```python
# Agent requesting a specialized SQL injection detector
message = protocol.create_task_assignment(
    task_id="sql-tool-001",
    sender_id="SAST_AGENT",
    recipient_id="AUTONOMOUS",
    context={
        "action": "create_dynamic_tool",
        "tool_request": {
            "tool_type": "advanced_sql_injection_detector",
            "specification": {
                "target_agent": "ai_code",
                "description": "Detect complex SQL injection patterns in ORM code",
                "default_severity": "CRITICAL",
                "pattern_type": "sql_injection",
                "detection_logic": {
                    "focus_on_orms": true,
                    "frameworks": ["sqlalchemy", "django-orm", "sequelize"],
                    "detect_second_order": true
                }
            },
            "training_data": [
                {
                    "type": "orm_sql_injection",
                    "severity": "CRITICAL",
                    "description": "Raw SQL in ORM query",
                    "metadata": {
                        "framework": "sqlalchemy",
                        "example": "session.execute(f'SELECT * FROM users WHERE id = {user_id}')"
                    }
                }
            ]
        }
    }
)
```

## Integration with Existing Agents

### For Lambda-based Agents

```python
# In your Lambda handler
def request_tool_creation(tool_spec):
    protocol = StrandsProtocol()
    
    message = protocol.create_task_assignment(
        task_id=f"tool-{datetime.utcnow().timestamp()}",
        sender_id=os.environ.get('AGENT_ID', 'LAMBDA_AGENT'),
        recipient_id="AUTONOMOUS",
        context={
            "action": "create_dynamic_tool",
            "tool_request": tool_spec
        }
    )
    
    # Send via SQS, SNS, or direct invocation
    # Implementation depends on your infrastructure
    return send_to_autonomous_agent(message)
```

### For ECS-based Agents

```python
# In your ECS agent
class MyAgent:
    def request_new_tool(self, findings_pattern):
        # Analyze patterns and determine tool needs
        tool_spec = self.analyze_tool_needs(findings_pattern)
        
        # Request tool creation
        message = self.protocol.create_task_assignment(
            task_id=str(uuid.uuid4()),
            sender_id=self.agent_id,
            recipient_id="AUTONOMOUS",
            context={
                "action": "create_dynamic_tool",
                "tool_request": tool_spec
            }
        )
        
        return self.send_message(message)
```

## Best Practices

1. **Provide Clear Specifications**: The more detailed your tool specification, the better the generated tool will be.

2. **Include Training Data**: When possible, provide example findings to help the autonomous agent understand the pattern you want to detect.

3. **Target the Right Agent**: Ensure the `target_agent` field matches the agent type that will use the tool.

4. **Monitor Responses**: Always handle both success and error responses appropriately.

5. **Avoid Duplicates**: Check if a similar tool already exists before requesting creation.

## Limitations

- Tool creation is subject to validation and may fail if the specification is invalid
- Generated tools are deployed to S3 and picked up by agents on their next scan
- Complex tool logic may require multiple iterations to refine

## See Also

- [Strands Protocol Documentation](./ARCHITECTURE.md#strands-protocol)
- [Autonomous Agent Architecture](./DETAILED_ARCHITECTURE.md#autonomous-agent)
- [Agent Communication Patterns](./DEVELOPER_GUIDE.md#agent-communication)