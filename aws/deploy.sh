#!/bin/bash
set -e

# PSIRT Agent ECS Deployment Script
# Usage: ./deploy.sh [create|update|delete]

STACK_NAME="psirt-agent"
REGION="${AWS_REGION:-us-east-1}"
BEDROCK_REGION="${BEDROCK_REGION:-us-east-1}"
ENVIRONMENT="psirt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get AWS Account ID
get_account_id() {
    aws sts get-caller-identity --query Account --output text
}

# Build and push Docker image to ECR
build_and_push() {
    log_info "Building and pushing Docker image to ECR..."

    ACCOUNT_ID=$(get_account_id)
    ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ENVIRONMENT}-agent"

    # Login to ECR
    log_info "Logging into ECR..."
    aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

    # Build image
    log_info "Building Docker image..."
    cd "$(dirname "$0")/.."
    docker build -t ${ENVIRONMENT}-agent:latest .

    # Tag and push
    log_info "Tagging and pushing image..."
    docker tag ${ENVIRONMENT}-agent:latest ${ECR_URI}:latest
    docker tag ${ENVIRONMENT}-agent:latest ${ECR_URI}:$(date +%Y%m%d-%H%M%S)

    docker push ${ECR_URI}:latest
    docker push ${ECR_URI}:$(date +%Y%m%d-%H%M%S)

    log_info "Image pushed successfully: ${ECR_URI}:latest"
}

# Create CloudFormation stack
create_stack() {
    log_info "Creating CloudFormation stack: ${STACK_NAME}"

    aws cloudformation create-stack \
        --stack-name ${STACK_NAME} \
        --template-body file://$(dirname "$0")/cloudformation.yaml \
        --parameters \
            ParameterKey=EnvironmentName,ParameterValue=${ENVIRONMENT} \
            ParameterKey=BedrockRegion,ParameterValue=${BEDROCK_REGION} \
        --capabilities CAPABILITY_NAMED_IAM \
        --region ${REGION}

    log_info "Waiting for stack creation..."
    aws cloudformation wait stack-create-complete \
        --stack-name ${STACK_NAME} \
        --region ${REGION}

    log_info "Stack created successfully!"
    show_outputs
}

# Update CloudFormation stack
update_stack() {
    log_info "Updating CloudFormation stack: ${STACK_NAME}"

    aws cloudformation update-stack \
        --stack-name ${STACK_NAME} \
        --template-body file://$(dirname "$0")/cloudformation.yaml \
        --parameters \
            ParameterKey=EnvironmentName,ParameterValue=${ENVIRONMENT} \
            ParameterKey=BedrockRegion,ParameterValue=${BEDROCK_REGION} \
        --capabilities CAPABILITY_NAMED_IAM \
        --region ${REGION} || {
            if [[ $? -eq 255 ]]; then
                log_warn "No updates to perform"
                return 0
            fi
            return 1
        }

    log_info "Waiting for stack update..."
    aws cloudformation wait stack-update-complete \
        --stack-name ${STACK_NAME} \
        --region ${REGION}

    log_info "Stack updated successfully!"
    show_outputs
}

# Delete CloudFormation stack
delete_stack() {
    log_warn "Deleting CloudFormation stack: ${STACK_NAME}"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cancelled"
        return
    fi

    aws cloudformation delete-stack \
        --stack-name ${STACK_NAME} \
        --region ${REGION}

    log_info "Waiting for stack deletion..."
    aws cloudformation wait stack-delete-complete \
        --stack-name ${STACK_NAME} \
        --region ${REGION}

    log_info "Stack deleted successfully!"
}

# Force new deployment (pull latest image)
force_deploy() {
    log_info "Forcing new deployment..."

    CLUSTER_NAME="${ENVIRONMENT}-cluster"
    SERVICE_NAME="${ENVIRONMENT}-service"

    aws ecs update-service \
        --cluster ${CLUSTER_NAME} \
        --service ${SERVICE_NAME} \
        --force-new-deployment \
        --region ${REGION}

    log_info "Deployment triggered. Waiting for service stability..."
    aws ecs wait services-stable \
        --cluster ${CLUSTER_NAME} \
        --services ${SERVICE_NAME} \
        --region ${REGION}

    log_info "Service is stable!"
    show_outputs
}

# Show stack outputs
show_outputs() {
    log_info "Stack Outputs:"
    echo ""
    aws cloudformation describe-stacks \
        --stack-name ${STACK_NAME} \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
        --output table \
        --region ${REGION}
}

# Show ECS service status
show_status() {
    log_info "ECS Service Status:"

    CLUSTER_NAME="${ENVIRONMENT}-cluster"
    SERVICE_NAME="${ENVIRONMENT}-service"

    aws ecs describe-services \
        --cluster ${CLUSTER_NAME} \
        --services ${SERVICE_NAME} \
        --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount,Pending:pendingCount}' \
        --output table \
        --region ${REGION}

    log_info "Recent Events:"
    aws ecs describe-services \
        --cluster ${CLUSTER_NAME} \
        --services ${SERVICE_NAME} \
        --query 'services[0].events[:5].[createdAt,message]' \
        --output table \
        --region ${REGION}
}

# View logs
view_logs() {
    log_info "Viewing recent logs..."

    LOG_GROUP="/ecs/${ENVIRONMENT}"

    aws logs tail ${LOG_GROUP} \
        --since 30m \
        --follow \
        --region ${REGION}
}

# Print usage
usage() {
    echo "PSIRT Agent ECS Deployment Script"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  create      Create the CloudFormation stack"
    echo "  update      Update the CloudFormation stack"
    echo "  delete      Delete the CloudFormation stack"
    echo "  build       Build and push Docker image to ECR"
    echo "  deploy      Build, push, and force new deployment"
    echo "  force       Force new deployment (use existing image)"
    echo "  status      Show ECS service status"
    echo "  outputs     Show stack outputs"
    echo "  logs        View recent logs"
    echo ""
    echo "Environment Variables:"
    echo "  AWS_REGION      AWS region (default: us-east-1)"
    echo "  BEDROCK_REGION  Region for Bedrock API (default: us-east-1)"
}

# Main
case "${1}" in
    create)
        create_stack
        ;;
    update)
        update_stack
        ;;
    delete)
        delete_stack
        ;;
    build)
        build_and_push
        ;;
    deploy)
        build_and_push
        force_deploy
        ;;
    force)
        force_deploy
        ;;
    status)
        show_status
        ;;
    outputs)
        show_outputs
        ;;
    logs)
        view_logs
        ;;
    *)
        usage
        exit 1
        ;;
esac
