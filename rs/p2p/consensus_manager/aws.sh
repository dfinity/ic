#!/bin/env bash


# Variables
S3_BUCKET="conesnsus-binary"
US_REGION="us-west-1"
EU_REGION="eu-central-1"
AMI_ID="ami-0faab6bdbac9486fb" # ubuntu 22.04
INSTANCE_TYPE="t2.micro"
KEY_NAME="test-key-pair" # Replace with your key pair name
STARTUP_SCRIPT="path/to/your/startup-script.sh"
BINARY_FILE="consensus_manager_runner"
BINARY_ARGS="your_cli_args"
EXPERIMENT_TAG="ConsExp"


if [ "$1" == "-d" ]; then
    echo "Terminating instances"
    aws ec2 --region $EU_REGION terminate-instances --instance-ids $(aws ec2 --region $EU_REGION describe-instances --query 'Reservations[].Instances[].InstanceId' --filters "Name=tag:tagkey,Values=$EXPERIMENT_TAG" --output text)
    aws s3 rm s3://$S3_BUCKET/$BINARY_FILE
    aws s3api --region $EU_REGION delete-bucket --bucket $S3_BUCKET 
    exit 0
fi

# Create bucket
aws s3api create-bucket \
    --bucket $S3_BUCKET \
    --region $EU_REGION \
    --create-bucket-configuration LocationConstraint=$EU_REGION

aws s3 cp $RUNNER_BIN s3://$S3_BUCKET/$BINARY_FILE

PRESIGNED=$(aws s3 presign --region $EU_REGION s3://$S3_BUCKET/$BINARY_FILE)

echo $PRESIGNED

aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specification ResourceType=vpc,Tags=[{Key=Name,Value=$EXPERIMENT_TAG}]

exit 1
# aws ec2 create-subnet \
#     --vpc-id vpc-081ec835f3EXAMPLE \
#     --cidr-block 10.0.0.0/24 \
#     --tag-specifications ResourceType=subnet,Tags=[{Key=Name,Value=$EXPERIMENT_TAG}]

create_instance() {
    local REGION=$1
    local PRESIGNED_URL=$2
    local ID=$3
    local PEERS_ADDR=$4

    aws ec2 run-instances \
        --image-id $AMI_ID \
        --count 1 \
        --instance-type $INSTANCE_TYPE \
        --key-name $KEY_NAME \
        --region $REGION \
        --private-ip-address 172.31.16.$ID \
        --user-data file://<(cat <<EOF
#!/bin/bash

# Download the binary from the pre-signed S3 URL
curl -o /tmp/binary "$PRESIGNED_URL"

# Make binary executable
chmod +x /tmp/binary

# Run the binary with arguments
/tmp/binary --id $ID --message-size 1000 --message-rate 10 --port 4100 --peers-addrs $PEERS_ADDR
EOF
)

}

# ssh -i "test-key-pair.pem" ubuntu@ec2-3-67-194-73.eu-central-1.compute.amazonaws.com

# Deploy in EU region
create_instance $EU_REGION $PRESIGNED 10 172.31.16.11:4100 > /dev/null 2>&1
echo "started instance"
create_instance $EU_REGION $PRESIGNED 11 172.32.16.10:4100 > /dev/null 2>&1
echo "started instance"



