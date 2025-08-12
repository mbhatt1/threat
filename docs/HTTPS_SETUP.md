# HTTPS Setup Guide for AI Security Audit Framework

This guide explains how to enable HTTPS with custom domains for the API endpoints.

## Prerequisites

1. A registered domain name (e.g., `example.com`)
2. Access to DNS management for your domain
3. AWS account with appropriate permissions

## Quick Start

### 1. Set Domain Name

Set the `DOMAIN_NAME` environment variable before deployment:

```bash
export DOMAIN_NAME="example.com"
```

### 2. Deploy the Stack

Deploy the CDK stack with certificate management enabled:

```bash
cd cdk
cdk deploy SecurityAudit-Certificate
```

### 3. Validate Certificate

If you're not using Route53, you'll need to manually validate the certificate:

1. Go to AWS Certificate Manager (ACM) console
2. Find your certificate (named `security-audit-api-{region}`)
3. Click on the certificate
4. Copy the CNAME records shown for validation
5. Add these CNAME records to your DNS provider
6. Wait for validation (usually 5-30 minutes)

### 4. Configure DNS

After certificate validation, configure your DNS:

1. Get the CloudFront distribution domain from the stack outputs
2. Create the following DNS records:

```
Type: CNAME
Name: api.example.com
Value: <CloudFront distribution domain from outputs>

Type: CNAME
Name: api-v1.example.com
Value: <CloudFront distribution domain from outputs>
```

## Available Endpoints

Once configured, your API will be available at:

- **Main API**: `https://api.example.com/`
  - Version discovery: `GET https://api.example.com/`
  - V1 endpoints: `https://api.example.com/v1/*`
  
- **Version-specific**: `https://api-v1.example.com/`
  - Direct access to v1 endpoints without `/v1` prefix

## Using Route53 (Recommended)

If your domain is hosted in Route53:

1. Modify `app.py` to pass your hosted zone:

```python
# Import Route53
import aws_route53 as route53

# Look up your hosted zone
hosted_zone = route53.HostedZone.from_lookup(
    self, "HostedZone",
    domain_name=domain_name
)

# Pass to certificate stack
certificate_stack = CertificateStack(
    app, f"{stack_prefix}-Certificate",
    domain_name=domain_name,
    api=api_stack.api,
    hosted_zone=hosted_zone,  # Now automated!
    env=env
)
```

2. Redeploy - DNS validation and configuration will be automatic

## Security Features

The HTTPS setup includes:

- **TLS 1.2 minimum**: Enforces modern encryption standards
- **Certificate auto-renewal**: ACM handles certificate renewal
- **CloudFront distribution**: Provides global edge caching and DDoS protection
- **Multiple domains**: Supports wildcard and specific subdomains
- **API versioning**: Separate domains for different API versions

## Troubleshooting

### Certificate Not Validating

- Ensure CNAME records are correctly added to DNS
- Check for typos in the CNAME values
- Allow up to 30 minutes for DNS propagation
- Verify domain ownership

### Custom Domain Not Working

- Ensure certificate is validated (shows "Issued" in ACM)
- Check CloudFront distribution is deployed (can take 15-30 minutes)
- Verify DNS records point to correct CloudFront domain
- Clear local DNS cache if testing immediately

### API Gateway Errors

- Check API Gateway custom domain configuration
- Ensure base path mappings are correct
- Verify certificate covers the domain being accessed

## Cost Considerations

- **ACM certificates**: Free for use with AWS services
- **CloudFront**: Pay for data transfer and requests
- **Route53**: $0.50/month per hosted zone + query charges
- **API Gateway custom domains**: No additional charge

## Next Steps

1. Enable CloudFront caching for better performance
2. Configure WAF rules on CloudFront distribution
3. Set up monitoring for certificate expiration
4. Implement domain-based rate limiting
5. Add additional domains for different environments (staging, dev)

## References

- [AWS Certificate Manager Documentation](https://docs.aws.amazon.com/acm/)
- [API Gateway Custom Domains](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html)
- [CloudFront with API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-regional-api-custom-domain-create.html)