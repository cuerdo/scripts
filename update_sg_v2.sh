#!/bin/bash
set -x

# Variables
PORT=22
AWS_REGION=us-east-1
DESCRIPTION="forti ip"

# Parse arguments
REMOVE_MODE=false
while [[ "$1" =~ ^- ]]; do
  case $1 in
    --remove)
      REMOVE_MODE=true
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

OLD_CIDR_BLOCK=$1

if [ -z "$OLD_CIDR_BLOCK" ]; then
  echo "Missing IP to be processed"
  exit 1
fi

if [ "$REMOVE_MODE" = false ]; then
  NEW_CIDR_BLOCK="`curl -s ipv4.icanhazip.com`/32"
  echo "Replacing ${OLD_CIDR_BLOCK} with ${NEW_CIDR_BLOCK}"
else
  echo "Removing rules with IP ${OLD_CIDR_BLOCK}"
fi

export AWS_REGION=$AWS_REGION
instances=$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' --output text)

for instance in $instances; do
    echo "Processing instance: $instance"
    security_groups=$(aws ec2 describe-instances --instance-ids $instance --query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' --output text)

    for sg in $security_groups; do
        echo "Checking security group: $sg"

        ingress_rule=$(aws ec2 describe-security-groups --group-ids $sg --query "SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp=='${OLD_CIDR_BLOCK}']].[FromPort, IpProtocol, ToPort, IpRanges[?CidrIp=='${OLD_CIDR_BLOCK}']]" --output text)

        if [ ! -z "$ingress_rule" ]; then
            echo "Found rule in security group $sg"

            aws ec2 revoke-security-group-ingress --group-id $sg --protocol tcp --port $PORT --cidr $OLD_CIDR_BLOCK --no-cli-pager
            echo "Removed old rule from $sg"

            if [ "$REMOVE_MODE" = false ]; then
                aws ec2 authorize-security-group-ingress --group-id $sg --protocol tcp --port $PORT --cidr $NEW_CIDR_BLOCK --description "$DESCRIPTION" --no-cli-pager
                echo "Added new rule to $sg with description '$DESCRIPTION'"
            fi
        else
            echo "No matching rule found in security group $sg."
        fi
    done
done

echo "Script execution completed."

