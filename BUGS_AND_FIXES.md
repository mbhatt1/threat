# Bugs and Integration Issues Found

## 1. CLI Import Path Issues

**Bug**: The CLI imports use relative imports that won't work when installed as a package:
```python
from shared.ai_orchestrator import AISecurityOrchestrator, run_ai_scan
```

**Fix**: Update imports to use absolute paths:
```python
from src.shared.ai_orchestrator import AISecurityOrchestrator, run_ai_scan
```

## 2. Missing Shared Modules

**Bug**: Multiple files import modules that don't exist:
- `shared.ai_orchestrator`
- `shared.incremental_scanner`
- `shared.ai_explainability`
- `shared.business_context`

**Fix**: Create stub implementations for these modules.

## 3. Script Stack Name Mismatch

**Bug**: `deploy.sh` line 124 uses wrong stack name pattern:
```bash
--stack-name SecurityAudit-${ENV}-API
```

**Fix**: Should match CDK app.py pattern:
```bash
--stack-name ${stack_prefix}-API
```

## 4. Event Loop Conflict in CLI

**Bug**: `run_ai_scan` creates new event loop which conflicts with existing loops:
```python
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
```

**Fix**: Use `asyncio.run()` or check for existing loop:
```python
try:
    loop = asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
```

## 5. API Gateway Custom Authorizer Not Connected

**Bug**: Custom authorizer Lambda is created in security_services_stack but not used in api_stack.

**Fix**: Add authorizer to API methods in api_stack.py.

## 6. GitHub Actions Integration Missing File

**Bug**: `integrations/github-actions/entrypoint.py` imports non-existent `ai_security_scanner.py`:
```python
from ai_security_scanner import SecurityScanner
```

**Fix**: Create the missing scanner implementation or update import.

## 7. AWS Credentials Not Checked in test-api.sh

**Bug**: Script uses AWS SigV4 but doesn't verify credentials exist.

**Fix**: Add credential check:
```bash
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    print_error "AWS credentials not set"
    exit 1
fi
```

## 8. ECR Scanning Lambda Never Invoked

**Bug**: ECR scanning enabler Lambda is created but never triggered.

**Fix**: Add EventBridge rule or manual invocation after deployment.

## 9. Security Services Stack Not in Deployment Script

**Bug**: New security services stack not included in deployment verification.

**Fix**: Update post_deployment() to check security services stack outputs.

## 10. MCP Server Path Issues

**Bug**: MCP server imports use incorrect paths:
```python
from shared.ai_orchestrator import AISecurityOrchestrator
```

**Fix**: Update to correct import path or add to PYTHONPATH.