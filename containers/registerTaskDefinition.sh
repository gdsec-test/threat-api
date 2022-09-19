# this script creates Task definition to be used for running Tasks inside ECS Cluster `api-ecstask-cluster` for long module requests
# need to have proper permissions to be able to register task, admin

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
AWS_REGION=us-west-2
TASK_IMAGE=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/api-ecstask:tanium

aws ecs register-task-definition --family api-ecstask-task \
  --execution-role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/threattools-custom-api-ecstask-role \
  --task-role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/threattools-custom-api-ecstask-role \
  --cpu 256 --memory 512 --network-mode awsvpc \
  --container-definitions "[ { \"name\": \"api-ecstask-task\", \"image\": \"${TASK_IMAGE}\", \"logConfiguration\": { \"logDriver\": \"awslogs\", \"options\": { \"awslogs-group\": \"/ecs/api-ecstask-task\", \"awslogs-region\": \"${AWS_REGION}\", \"awslogs-create-group\": \"true\", \"awslogs-stream-prefix\": \"ecs\" } } } ]"
