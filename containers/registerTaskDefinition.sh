# this script creates Task definition to be used for running Tasks inside ECS Cluster `api-ecstask-cluster` for long module requests
# need to have proper permissions to be able to register task, admin

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
aws ecs register-task-definition --family api-ecstask-task \
  --execution-role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/threattools-custom-api-ecstask-role \
  --task-role-arn arn:aws:iam::$AWS_ACCOUNT_ID:role/threattools-custom-api-ecstask-role \
  --cpu 256 --memory 512 --network-mode awsvpc --container-definitions '[ { "name": "container", "image": "TBD" }]'
