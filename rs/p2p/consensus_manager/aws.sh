#!/bin/env bash


# Variables
S3_BUCKET="conesnsus-binary"
EU_REGION="eu-central-1"
BINARY_FILE="consensus_manager_runner"
EXPERIMENT_TAG="ConsExp"


# Create bucket
aws s3api create-bucket \
    --bucket $S3_BUCKET \
    --region $EU_REGION \
    --create-bucket-configuration LocationConstraint=$EU_REGION

aws s3 cp $RUNNER_BIN s3://$S3_BUCKET/$BINARY_FILE

PRESIGNED=$(aws s3 presign --region $EU_REGION s3://$S3_BUCKET/$BINARY_FILE)

echo $PRESIGNED


