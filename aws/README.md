# PSIRT Agent - AWS ECS Deployment

Deploy the PSIRT Security Agent to AWS ECS Fargate with Amazon Bedrock for Claude Sonnet 4.5.

## Architecture

```
                    Internet
                       │
                       ▼
              ┌────────────────┐
              │  Application   │
              │ Load Balancer  │
              └───────┬────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
         ▼            ▼            ▼
    ┌─────────┐  ┌─────────┐  ┌─────────┐
    │   ECS   │  │   ECS   │  │   ECS   │
    │  Task   │  │  Task   │  │  Task   │
    │(Fargate)│  │(Fargate)│  │(Fargate)│
    └────┬────┘  └────┬────┘  └────┬────┘
         │            │            │
         └────────────┼────────────┘
                      │
                      ▼
              ┌────────────────┐
              │ Amazon Bedrock │
              │ (Claude 4.5)   │
              └────────────────┘
```

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **Docker** installed for building images
3. **AWS Account** with permissions for:
   - CloudFormation
   - ECS/ECR
   - IAM
   - EC2/VPC
   - Elastic Load Balancing
   - CloudWatch Logs
   - Amazon Bedrock

## Enable Bedrock Model Access

Before deploying, you must enable Claude models in Amazon Bedrock:

1. Go to AWS Console → Amazon Bedrock
2. Navigate to "Model access" in the left sidebar
3. Click "Manage model access"
4. Enable the following models:
   - Anthropic Claude Sonnet 4.5
   - Anthropic Claude 3.5 Sonnet (optional)
   - Anthropic Claude 3 Haiku (optional, for faster responses)
5. Submit and wait for access approval

## Quick Start

### 1. Create the Infrastructure

```bash
# Set your AWS region
export AWS_REGION=us-east-1
export BEDROCK_REGION=us-east-1

# Create the CloudFormation stack
./deploy.sh create
```

This creates:
- VPC with public subnets
- ECS Cluster (Fargate)
- ECR Repository
- Application Load Balancer
- IAM Roles with Bedrock permissions
- CloudWatch Log Group

### 2. Build and Deploy

```bash
# Build Docker image and push to ECR, then deploy
./deploy.sh deploy
```

Or step by step:
```bash
# Just build and push image
./deploy.sh build

# Force new deployment with latest image
./deploy.sh force
```

### 3. Access the Application

After deployment, get the URLs:

```bash
./deploy.sh outputs
```

You'll see:
- **ApplicationURL**: Main dashboard
- **AdminURL**: Configure settings (`/admin`)
- **UserURL**: Ask security questions (`/user`)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| AWS_REGION | us-east-1 | AWS region for deployment |
| BEDROCK_REGION | us-east-1 | Region for Bedrock API |

### CloudFormation Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| EnvironmentName | psirt | Prefix for all resources |
| VpcCIDR | 10.0.0.0/16 | VPC CIDR block |
| ContainerPort | 8080 | Application port |
| DesiredCount | 1 | Number of ECS tasks |
| BedrockRegion | us-east-1 | Bedrock API region |

## Commands Reference

```bash
./deploy.sh create    # Create CloudFormation stack
./deploy.sh update    # Update CloudFormation stack
./deploy.sh delete    # Delete CloudFormation stack
./deploy.sh build     # Build and push Docker image
./deploy.sh deploy    # Build, push, and deploy
./deploy.sh force     # Force new deployment
./deploy.sh status    # Show ECS service status
./deploy.sh outputs   # Show stack outputs
./deploy.sh logs      # View recent logs (streaming)
```

## IAM Permissions

The ECS task role includes permissions for:

```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream"
  ],
  "Resource": [
    "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-*",
    "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-*"
  ]
}
```

## Costs

Estimated monthly costs (varies by usage):
- ECS Fargate (0.5 vCPU, 1GB): ~$15-25/month
- Application Load Balancer: ~$20/month
- Bedrock Claude 4.5: Pay per token usage
  - Input: $3 per 1M tokens
  - Output: $15 per 1M tokens
- CloudWatch Logs: Minimal
- Data Transfer: Varies

## Troubleshooting

### Check ECS Service Status
```bash
./deploy.sh status
```

### View Logs
```bash
./deploy.sh logs
```

### Common Issues

1. **Bedrock Access Denied**
   - Ensure model access is enabled in Bedrock console
   - Check IAM role has correct permissions
   - Verify the region supports the model

2. **Task Keeps Restarting**
   - Check CloudWatch logs for errors
   - Verify health check endpoint works
   - Ensure Qdrant container starts properly

3. **Cannot Reach Application**
   - Check security group allows traffic
   - Verify ALB target group health
   - Check ECS service has running tasks

## Cleanup

To remove all resources:

```bash
./deploy.sh delete
```

Note: This will delete:
- ECS Service and Cluster
- ECR Repository (including images)
- Load Balancer
- VPC and networking
- IAM Roles
- CloudWatch Log Group
