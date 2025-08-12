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
    aws_wafv2 as waf,
    aws_kms as kms,
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
                 custom_authorizer_lambda: lambda_.Function = None,
                 kms_key: kms.Key = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # CloudWatch Logs for API Gateway with extended retention for compliance
        api_log_group = logs.LogGroup(
            self, "ApiLogGroup",
            log_group_name="/aws/apigateway/security-audit",
            retention=logs.RetentionDays.THREE_MONTHS,  # Extended for compliance
            removal_policy=RemovalPolicy.RETAIN,  # Retain logs on stack deletion
            encryption_key=kms_key  # Use KMS if provided
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
                allow_origins=[
                    "https://app.example.com",
                    "https://admin.example.com",
                    "http://localhost:3000"  # For development only
                ],
                allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                allow_headers=["Content-Type", "Authorization", "X-Amz-Date", "X-Api-Key", "X-Amz-Security-Token"],
                allow_credentials=True,
                max_age=Duration.hours(1)
            )
        )
        
        # Create custom authorizer if provided
        custom_authorizer = None
        if custom_authorizer_lambda:
            custom_authorizer = apigw.TokenAuthorizer(
                self, "CustomAuthorizer",
                handler=custom_authorizer_lambda,
                identity_source="method.request.header.Authorization",
                validation_regex="^Bearer [-0-9a-zA-z\.]*$",
                results_cache_ttl=Duration.minutes(5)
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
        
        # Create versioned API resources
        # Version 1 - Current stable version
        v1_resource = self.api.root.add_resource("v1")
        v1_scans_resource = v1_resource.add_resource("scans")
        v1_scan_resource = v1_scans_resource.add_resource("{scan_id}")
        
        # Add version header to all responses
        def add_version_headers(method_response):
            """Add API version headers to method responses"""
            if not hasattr(method_response, 'response_parameters'):
                method_response.response_parameters = {}
            method_response.response_parameters.update({
                'method.response.header.X-API-Version': True,
                'method.response.header.X-API-Deprecation': True
            })
            return method_response
        
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
        
        # POST /v1/scans - Start a new scan
        v1_scans_resource.add_method(
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
            authorization_type=apigw.AuthorizationType.CUSTOM if custom_authorizer else apigw.AuthorizationType.IAM,
            authorizer=custom_authorizer
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
        
        # GET /v1/scans/{scan_id} - Get scan status
        v1_scan_resource.add_method(
            "GET",
            get_scan_integration,
            method_responses=[
                apigw.MethodResponse(status_code="200"),
                apigw.MethodResponse(status_code="404")
            ],
            authorization_type=apigw.AuthorizationType.CUSTOM if custom_authorizer else apigw.AuthorizationType.IAM,
            authorizer=custom_authorizer
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
        
        # GET /v1/scans - List scans
        v1_scans_resource.add_method(
            "GET",
            list_scans_integration,
            request_parameters={
                "method.request.querystring.status": False,
                "method.request.querystring.limit": False
            },
            method_responses=[
                apigw.MethodResponse(status_code="200")
            ],
            authorization_type=apigw.AuthorizationType.CUSTOM if custom_authorizer else apigw.AuthorizationType.IAM,
            authorizer=custom_authorizer
        )
        
        # AI Security Analyzer endpoints
        v1_ai_resource = v1_resource.add_resource("ai")
        
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
                        enum=["analyze_sql", "threat_intel", "root_cause", "pure_ai", "sandbox", "test_generator"]
                    ),
                    "payload": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.OBJECT
                    )
                }
            )
        )
            
        # SQL Injection Analysis endpoint
        sql_resource = v1_ai_resource.add_resource("sql-analysis")
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
        threat_resource = v1_ai_resource.add_resource("threat-intelligence")
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
        root_cause_resource = v1_ai_resource.add_resource("root-cause")
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
        pure_ai_resource = v1_ai_resource.add_resource("pure-detection")
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
        sandbox_resource = v1_ai_resource.add_resource("sandbox")
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
        
        # Test Generator endpoint
        test_generator_resource = v1_ai_resource.add_resource("test-generator")
        test_generator_resource.add_method(
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
        
        # Create WAF WebACL for API protection
        web_acl = waf.CfnWebACL(
            self, "ApiWAF",
            scope="REGIONAL",
            default_action=waf.CfnWebACL.DefaultActionProperty(allow={}),
            description="WAF protection for Security Audit API",
            rules=[
                # Rate limiting rule
                waf.CfnWebACL.RuleProperty(
                    name="RateLimitRule",
                    priority=1,
                    statement=waf.CfnWebACL.StatementProperty(
                        rate_based_statement=waf.CfnWebACL.RateBasedStatementProperty(
                            limit=2000,
                            aggregate_key_type="IP",
                            scope_down_statement=waf.CfnWebACL.StatementProperty(
                                not_statement=waf.CfnWebACL.NotStatementProperty(
                                    statement=waf.CfnWebACL.StatementProperty(
                                        byte_match_statement=waf.CfnWebACL.ByteMatchStatementProperty(
                                            search_string="/health",
                                            field_to_match=waf.CfnWebACL.FieldToMatchProperty(uri_path={}),
                                            text_transformations=[
                                                waf.CfnWebACL.TextTransformationProperty(
                                                    priority=0,
                                                    type="NONE"
                                                )
                                            ],
                                            positional_constraint="EXACTLY"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    action=waf.CfnWebACL.RuleActionProperty(
                        block=waf.CfnWebACL.BlockActionProperty(
                            custom_response=waf.CfnWebACL.CustomResponseProperty(
                                response_code=429,
                                custom_response_body_key="rate-limit-exceeded"
                            )
                        )
                    ),
                    visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="RateLimitRule"
                    )
                ),
                # SQL injection protection
                waf.CfnWebACL.RuleProperty(
                    name="SQLiProtection",
                    priority=2,
                    statement=waf.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesSQLiRuleSet"
                        )
                    ),
                    override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
                    visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="SQLiProtection"
                    )
                ),
                # Known bad inputs
                waf.CfnWebACL.RuleProperty(
                    name="KnownBadInputs",
                    priority=3,
                    statement=waf.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesKnownBadInputsRuleSet"
                        )
                    ),
                    override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
                    visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="KnownBadInputs"
                    )
                ),
                # Common rule set
                waf.CfnWebACL.RuleProperty(
                    name="CommonRuleSet",
                    priority=4,
                    statement=waf.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesCommonRuleSet",
                            excluded_rules=[
                                waf.CfnWebACL.ExcludedRuleProperty(name="SizeRestrictions_BODY"),
                                waf.CfnWebACL.ExcludedRuleProperty(name="GenericRFI_BODY")
                            ]
                        )
                    ),
                    override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
                    visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="CommonRuleSet"
                    )
                ),
                # IP reputation list
                waf.CfnWebACL.RuleProperty(
                    name="IPReputationList",
                    priority=5,
                    statement=waf.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                            vendor_name="AWS",
                            name="AWSManagedRulesAmazonIpReputationList"
                        )
                    ),
                    override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
                    visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="IPReputationList"
                    )
                ),
                # Geo-blocking rule (optional - block high-risk countries)
                waf.CfnWebACL.RuleProperty(
                    name="GeoBlockingRule",
                    priority=6,
                    statement=waf.CfnWebACL.StatementProperty(
                        geo_match_statement=waf.CfnWebACL.GeoMatchStatementProperty(
                            country_codes=["CN", "RU", "KP"]  # Example: China, Russia, North Korea
                        )
                    ),
                    action=waf.CfnWebACL.RuleActionProperty(
                        block=waf.CfnWebACL.BlockActionProperty(
                            custom_response=waf.CfnWebACL.CustomResponseProperty(
                                response_code=403,
                                custom_response_body_key="geo-blocked"
                            )
                        )
                    ),
                    visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="GeoBlockingRule"
                    )
                )
            ],
            visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
                sampled_requests_enabled=True,
                cloud_watch_metrics_enabled=True,
                metric_name="SecurityAuditAPIWAF"
            ),
            custom_response_bodies={
                "rate-limit-exceeded": waf.CfnWebACL.CustomResponseBodyProperty(
                    content_type="APPLICATION_JSON",
                    content='{"error": "Rate limit exceeded. Please try again later."}'
                ),
                "geo-blocked": waf.CfnWebACL.CustomResponseBodyProperty(
                    content_type="APPLICATION_JSON",
                    content='{"error": "Access denied from your location."}'
                )
            }
        )
        
        # Associate WAF with API Gateway
        waf_association = waf.CfnWebACLAssociation(
            self, "WAFAssociation",
            resource_arn=f"arn:aws:apigateway:{self.region}::/restapis/{self.api.rest_api_id}/stages/{self.api.deployment_stage.stage_name}",
            web_acl_arn=web_acl.attr_arn
        )
        
        # Add root endpoint that lists available API versions
        versions_model = apigw.Model(
            self, "VersionsModel",
            rest_api=self.api,
            content_type="application/json",
            model_name="APIVersions",
            schema=apigw.JsonSchema(
                type=apigw.JsonSchemaType.OBJECT,
                properties={
                    "versions": apigw.JsonSchema(
                        type=apigw.JsonSchemaType.ARRAY,
                        items=apigw.JsonSchema(
                            type=apigw.JsonSchemaType.OBJECT,
                            properties={
                                "version": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                                "status": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                                "deprecated": apigw.JsonSchema(type=apigw.JsonSchemaType.BOOLEAN),
                                "deprecation_date": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING),
                                "end_of_life": apigw.JsonSchema(type=apigw.JsonSchemaType.STRING)
                            }
                        )
                    )
                }
            )
        )
        
        # Mock integration for root endpoint
        versions_integration = apigw.MockIntegration(
            integration_responses=[
                apigw.IntegrationResponse(
                    status_code="200",
                    response_templates={
                        "application/json": json.dumps({
                            "versions": [
                                {
                                    "version": "v1",
                                    "status": "stable",
                                    "deprecated": False,
                                    "deprecation_date": None,
                                    "end_of_life": None
                                }
                            ],
                            "latest": "v1",
                            "documentation": "https://docs.security-audit-framework.com/api/v1"
                        })
                    }
                )
            ],
            request_templates={
                "application/json": '{"statusCode": 200}'
            }
        )
        
        # GET / - List available API versions
        self.api.root.add_method(
            "GET",
            versions_integration,
            method_responses=[
                apigw.MethodResponse(
                    status_code="200",
                    response_models={
                        "application/json": versions_model
                    },
                    response_parameters={
                        'method.response.header.X-API-Version': True,
                        'method.response.header.Cache-Control': True
                    }
                )
            ]
        )
        
        # Outputs
        CfnOutput(
            self, "ApiEndpoint",
            value=self.api.url,
            description="API Gateway endpoint URL (use /v1/* for versioned endpoints)"
        )
        
        CfnOutput(
            self, "ApiV1Endpoint",
            value=f"{self.api.url}v1/",
            description="API v1 endpoint URL"
        )
        
        CfnOutput(
            self, "ApiKeyId",
            value=api_key.key_id,
            description="API Key ID (retrieve value from console)"
        )
        
        CfnOutput(
            self, "WAFWebACLArn",
            value=web_acl.attr_arn,
            description="WAF WebACL ARN protecting the API"
        )