"""
Certificate Stack - TLS/SSL certificate management for HTTPS endpoints
"""
from aws_cdk import (
    Stack,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_apigateway as apigw,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct
from typing import Optional


class CertificateStack(Stack):
    """Manages TLS/SSL certificates for secure HTTPS endpoints"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 domain_name: str,
                 api: apigw.RestApi,
                 hosted_zone: Optional[route53.IHostedZone] = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create certificate for the domain
        # Note: If no hosted zone is provided, manual DNS validation will be required
        self.certificate = acm.Certificate(
            self, "ApiCertificate",
            domain_name=domain_name,
            subject_alternative_names=[
                f"*.{domain_name}",  # Wildcard for subdomains
                f"api.{domain_name}",  # Specific API subdomain
                f"api-v1.{domain_name}"  # Version-specific subdomain
            ],
            validation=acm.CertificateValidation.from_dns(hosted_zone) if hosted_zone else acm.CertificateValidation.from_dns(),
            certificate_name=f"security-audit-api-{self.region}"
        )
        
        # Create custom domain for API Gateway
        self.api_domain = apigw.DomainName(
            self, "ApiDomainName",
            domain_name=f"api.{domain_name}",
            certificate=self.certificate,
            endpoint_type=apigw.EndpointType.EDGE,  # Use CloudFront distribution
            security_policy=apigw.SecurityPolicy.TLS_1_2
        )
        
        # Map the custom domain to the API
        base_path_mapping = apigw.BasePathMapping(
            self, "ApiBasePathMapping",
            domain_name=self.api_domain,
            rest_api=api,
            base_path=""  # Map to root of custom domain
        )
        
        # Create versioned domain mapping
        self.api_v1_domain = apigw.DomainName(
            self, "ApiV1DomainName",
            domain_name=f"api-v1.{domain_name}",
            certificate=self.certificate,
            endpoint_type=apigw.EndpointType.EDGE,
            security_policy=apigw.SecurityPolicy.TLS_1_2
        )
        
        # Map v1 API directly to versioned domain
        v1_base_path_mapping = apigw.BasePathMapping(
            self, "ApiV1BasePathMapping",
            domain_name=self.api_v1_domain,
            rest_api=api,
            base_path="v1"  # Map v1 path to root of v1 domain
        )
        
        # Create Route 53 records if hosted zone is provided
        if hosted_zone:
            # A record for main API domain
            route53.ARecord(
                self, "ApiARecord",
                zone=hosted_zone,
                record_name=f"api.{domain_name}",
                target=route53.RecordTarget.from_alias(
                    route53.targets.ApiGatewayDomain(self.api_domain)
                )
            )
            
            # A record for v1 API domain
            route53.ARecord(
                self, "ApiV1ARecord",
                zone=hosted_zone,
                record_name=f"api-v1.{domain_name}",
                target=route53.RecordTarget.from_alias(
                    route53.targets.ApiGatewayDomain(self.api_v1_domain)
                )
            )
            
            # CNAME for www variant (optional)
            route53.CnameRecord(
                self, "ApiWwwCname",
                zone=hosted_zone,
                record_name=f"www-api.{domain_name}",
                domain_name=f"api.{domain_name}"
            )
        
        # Certificate monitoring alarm (optional)
        # This would require CloudWatch setup which we already have
        
        # Outputs
        CfnOutput(
            self, "CertificateArn",
            value=self.certificate.certificate_arn,
            description="ARN of the TLS certificate"
        )
        
        CfnOutput(
            self, "ApiCustomDomain",
            value=f"https://api.{domain_name}",
            description="Custom HTTPS domain for the API"
        )
        
        CfnOutput(
            self, "ApiV1CustomDomain",
            value=f"https://api-v1.{domain_name}",
            description="Custom HTTPS domain for API v1"
        )
        
        CfnOutput(
            self, "CloudFrontDistribution",
            value=self.api_domain.domain_name_alias_domain_name,
            description="CloudFront distribution domain for API"
        )
        
        if not hosted_zone:
            CfnOutput(
                self, "DNSValidationRequired",
                value="Manual DNS validation required - check ACM console",
                description="Add CNAME records shown in ACM console to validate certificate"
            )
            
            CfnOutput(
                self, "DNSConfigurationRequired",
                value=f"Create CNAME: api.{domain_name} -> {self.api_domain.domain_name_alias_domain_name}",
                description="Manual DNS configuration required for custom domain"
            )