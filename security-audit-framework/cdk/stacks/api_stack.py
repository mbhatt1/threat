"""
API Stack - API Gateway for Security Audit Framework
"""
from aws_cdk import (
    Stack,
    aws_apigateway as apigw,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_stepfunctions as sfn,
    aws_dynamodb as dynamodb,
    aws_logs as logs,
    Duration,
    RemovalPolicy,
    CfnOutput
)
from constructs import Construct
import json


class APIStack(Stack):
    """API Gateway for Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 api_role: iam.Role,
                 state_machine: sfn.StateMachine,
                 scan_table: dynamodb.Table,
                 ai_security_analyzer_lambda: lambda_.Function,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # CloudWatch Logs for API Gateway
        api_log_group = logs.LogGroup(
            self, "ApiLogGroup",
            log_group_name="/aws/apigateway/security-audit",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Create REST API
        self.api = apigw.RestApi(
            self, "SecurityAuditAPI",
            rest_api_name="security-audit-api",
            description="API for triggering and managing security scans",
            deploy_options=apigw.StageOptions(
                stage_name="v1",
                logging_level=apigw.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True,
                throttling_rate_limit=100,
                throttling_burst_limit=200,
                access_log_destination=apigw.LogGroupLogDestination(api_log_group),
                access_log_format=apigw.AccessLogFormat.json_with_standard_fields()
            ),
            default_cors_preflight_options=apigw.CorsOptions(
                allow_origins=apigw.Cors.ALL_ORIGINS,
                allow_methods=apigw.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "Authorization"]
            )
        )
        
        # Request Validator
        request_validator = apigw.RequestValidator(
            self, "RequestValidator",
            rest_api=self.api,
            validate_request_body=True,
            validate_request_parameters=True
        )
        
        # Models for request/response validation
        scan_request_model = apigw.Model(
            self, "ScanRequestModel",
            rest_api=self.api,
            content_type="application/json",
            model_name="ScanRequest",
            schema=apigw.JsonSchema(
                type=apigw.JsonSchemaType.OBJECT,
                required=["repo_url"],
                properties={
                    "repo_url": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING,
                        pattern="^https?://.+"
                    ),
                    "branch": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING,
                        default="main"
                    ),
                    "commit_hash": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING
                    ),
                    "priority": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING,
                        enum=["low", "normal", "high", "critical"],
                        default="normal"
                    ),
                    "credentials_secret_arn": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING,
                        pattern="^arn:aws:secretsmanager:.+"
                    )
                }
            )
        )
        
        scan_response_model = apigw.Model(
            self, "ScanResponseModel",
            rest_api=self.api,
            content_type="application/json",
            model_name="ScanResponse",
            schema=apigw.JsonSchema(
                type=apigw.JsonSchemaType.OBJECT,
                properties={
                    "scan_id": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                    "status": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                    "message": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING)
                }
            )
        )
        
        # Create API resources
        scans_resource = self.api.root.add_resource("scans")
        scan_resource = scans_resource.add_resource("{scan_id}")
        
        # Integration with Step Functions for starting scans
        sfn_integration = apigw.AwsIntegration(
            service="states",
            action="StartExecution",
            integration_http_method="POST",
            options=apigw.IntegrationOptions(
                credentials_role=api_role,
                request_templates={
                    "application/json": json.dumps({
                        "stateMachineArn": state_machine.state_machine_arn,
                        "input": "$util.escapeJavaScript($input.body)"
                    })
                },
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": json.dumps({
                                "scan_id": "$input.json('$.executionArn').split(':').get(7)",
                                "status": "STARTED",
                                "message": "Security scan initiated successfully"
                            })
                        }
                    ),
                    apigw.IntegrationResponse(
                        status_code="400",
                        selection_pattern="4\\d{2}",
                        response_templates={
                            "application/json": json.dumps({
                                "error": "$input.json('$.message')"
                            })
                        }
                    )
                ]
            )
        )
        
        # POST /scans - Start a new scan
        scans_resource.add_method(
            "POST",
            sfn_integration,
            request_validator=request_validator,
            request_models={
                "application/json": scan_request_model
            },
            method_responses=[
                apigw.MethodResponse(
                    status_code="200",
                    response_models={
                        "application/json": scan_response_model
                    }
                ),
                apigw.MethodResponse(
                    status_code="400"
                )
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
        
        # Integration with DynamoDB for getting scan status
        get_scan_integration = apigw.AwsIntegration(
            service="dynamodb",
            action="GetItem",
            integration_http_method="POST",
            options=apigw.IntegrationOptions(
                credentials_role=api_role,
                request_templates={
                    "application/json": json.dumps({
                        "TableName": scan_table.table_name,
                        "Key": {
                            "scan_id": {
                                "S": "$input.params('scan_id')"
                            }
                        }
                    })
                },
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": """
                            #set($item = $input.json('$.Item'))
                            #if($item == "")
                            {
                                "error": "Scan not found"
                            }
                            #else
                            {
                                "scan_id": "$item.scan_id.S",
                                "status": "$item.status.S",
                                "repository_url": "$item.repository_url.S",
                                "created_at": "$item.created_at.S",
                                #if($item.total_findings)
                                "total_findings": $item.total_findings.N,
                                #end
                                #if($item.execution_plan)
                                "execution_plan": $util.parseJson($item.execution_plan.S),
                                #end
                                #if($item.completed_at)
                                "completed_at": "$item.completed_at.S"
                                #end
                            }
                            #end
                            """
                        }
                    ),
                    apigw.IntegrationResponse(
                        status_code="404",
                        selection_pattern=".*ResourceNotFoundException.*",
                        response_templates={
                            "application/json": json.dumps({
                                "error": "Scan not found"
                            })
                        }
                    )
                ]
            )
        )
        
        # GET /scans/{scan_id} - Get scan status
        scan_resource.add_method(
            "GET",
            get_scan_integration,
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="404")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
        
        # List scans integration
        list_scans_integration = apigw.AwsIntegration(
            service="dynamodb",
            action="Query",
            integration_http_method="POST",
            options=apigw.IntegrationOptions(
                credentials_role=api_role,
                request_parameters={
                    "integration.request.querystring.status": "method.request.querystring.status",
                    "integration.request.querystring.limit": "method.request.querystring.limit"
                },
                request_templates={
                    "application/json": """
                    #if($input.params('status'))
                    {
                        "TableName": "${scan_table.table_name}",
                        "IndexName": "status-index",
                        "KeyConditionExpression": "#status = :status",
                        "ExpressionAttributeNames": {
                            "#status": "status"
                        },
                        "ExpressionAttributeValues": {
                            ":status": {
                                "S": "$input.params('status')"
                            }
                        },
                        "Limit": #if($input.params('limit')) $input.params('limit') #else 20 #end,
                        "ScanIndexForward": false
                    }
                    #else
                    {
                        "TableName": "${scan_table.table_name}",
                        "Limit": #if($input.params('limit')) $input.params('limit') #else 20 #end
                    }
                    #end
                    """
                },
                integration_responses=[
                    apigw.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": """
                            {
                                "scans": [
                                    #foreach($item in $input.json('$.Items'))
                                    {
                                        "scan_id": "$item.scan_id.S",
                                        "status": "$item.status.S",
                                        "repository_url": "$item.repository_url.S",
                                        "created_at": "$item.created_at.S"
                                        #if($item.total_findings),
                                        "total_findings": $item.total_findings.N
                                        #end
                                    }#if($foreach.hasNext),#end
                                    #end
                                ],
                                #if($input.json('$.LastEvaluatedKey'))
                                "next_token": "$util.base64Encode($input.json('$.LastEvaluatedKey'))"
                                #end
                            }
                            """
                        }
                    )
                ]
            )
        )
        
        # GET /scans - List scans
        scans_resource.add_method(
            "GET",
            list_scans_integration,
            request_parameters={
                "method.request.querystring.status": False,
                "method.request.querystring.limit": False
            },
            method_responses=[
                apigw.MethodResponse(status_code="200")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
        
        # AI Security Analyzer endpoints
        ai_resource = self.api.root.add_resource("ai")
        
        # AI Security Analyzer Lambda integration
        ai_integration = apigw.LambdaIntegration(
            ai_security_analyzer_lambda,
            request_templates={
                "application/json": "$input.body"
            }
        )
            
        # Define request model for AI analysis
        ai_request_model = apigw.Model(
            self, "AIAnalysisRequestModel",
            rest_api=self.api,
            content_type="application/json",
            model_name="AIAnalysisRequest",
            schema=apigw.JsonSchema(
                type=apigw.JsonSchemaType.OBJECT,
                required=["action", "payload"],
                properties={
                    "action": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.STRING,
                        enum=["analyze_sql", "threat_intel", "root_cause", "pure_ai", "sandbox"]
                    ),
                    "payload": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.OBJECT
                    )
                }
            )
        )
            
        # SQL Injection Analysis endpoint
        sql_resource = ai_resource.add_resource("sql-analysis")
        sql_resource.add_method(
            "POST",
            ai_integration,
            request_models={"application/json": ai_request_model},
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="400"),
                apigw.MethodResponse(status_code="500")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
            
        # Threat Intelligence endpoint
        threat_resource = ai_resource.add_resource("threat-intelligence")
        threat_resource.add_method(
            "POST",
            ai_integration,
            request_models={"application/json": ai_request_model},
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="400"),
                apigw.MethodResponse(status_code="500")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
            
        # Root Cause Analysis endpoint
        root_cause_resource = ai_resource.add_resource("root-cause")
        root_cause_resource.add_method(
            "POST",
            ai_integration,
            request_models={"application/json": ai_request_model},
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="400"),
                apigw.MethodResponse(status_code="500")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
            
        # Pure AI Detection endpoint
        pure_ai_resource = ai_resource.add_resource("pure-detection")
        pure_ai_resource.add_method(
            "POST",
            ai_integration,
            request_models={"application/json": ai_request_model},
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="400"),
                apigw.MethodResponse(status_code="500")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
            
        # Sandbox Testing endpoint
        sandbox_resource = ai_resource.add_resource("sandbox")
        sandbox_resource.add_method(
            "POST",
            ai_integration,
            request_models={"application/json": ai_request_model},
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="400"),
                apigw.MethodResponse(status_code="500")
            ],
            authorization_type=apigw.AuthorizationType.IAM
        )
        
        # API Key for basic access (optional)
        api_key = apigw.ApiKey(
            self, "SecurityAuditApiKey",
            api_key_name="security-audit-default-key",
            description="Default API key for Security Audit Framework"
        )
        
        # Usage Plan
        usage_plan = apigw.UsagePlan(
            self, "SecurityAuditUsagePlan",
            name="security-audit-standard",
            description="Standard usage plan for Security Audit API",
            api_stages=[apigw.UsagePlanPerApiStage(
                api=self.api,
                stage=self.api.deployment_stage
            )],
            throttle=apigw.ThrottleSettings(
                rate_limit=100,
                burst_limit=200
            ),
            quota=apigw.QuotaSettings(
                limit=10000,
                period=apigw.Period.DAY
            )
        )
        
        usage_plan.add_api_key(api_key)
        
        # Outputs
        CfnOutput(
            self, "ApiEndpoint",
            value=self.api.url,
            description="API Gateway endpoint URL"
        )
        
        CfnOutput(
            self, "ApiKeyId",
            value=api_key.key_id,
            description="API Key ID (retrieve value from console)"
        )