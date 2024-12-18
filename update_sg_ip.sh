#!/bin/bash
set -x
# Define the variables
NEW_CIDR_BLOCK="`curl ipv4.icanhazip.com`/32"  
OLD_CIDR_BLOCK=$1  # The existing CIDR block you want to replace
PORT=22  
AWS_REGION=us-east-1

if [ -z $1 ]; then
  echo "Missing IP to be replaced"
fi

echo "The rules with the IP ${OLD_CIDR_BLOCK} with ${NEW_CIDR_BLOCK}"

# Fetch all EC2 instances

export $AWS_REGION
instances=$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].InstanceId' --output text)

# Iterate through each instance to find associated security groups
for instance in $instances; do
    echo "Processing instance: $instance"
    security_groups=$(aws ec2 describe-instances --instance-ids $instance --query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' --output text)
    
    for sg in $security_groups; do
        echo "Checking security group: $sg"

        # Check if the security group has the old CIDR block on the specified port
        ingress_rule=$(aws ec2 describe-security-groups --group-ids $sg --query "SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp=='${OLD_CIDR_BLOCK}']].[FromPort, IpProtocol, ToPort, IpRanges[?CidrIp=='${OLD_CIDR_BLOCK}']]" --output text)
        
        if [ ! -z "$ingress_rule" ]; then
            echo "Found rule in security group $sg, updating CIDR block from $OLD_CIDR_BLOCK to $NEW_CIDR_BLOCK"

            # Revoke the old rule
            aws ec2 revoke-security-group-ingress --group-id $sg --protocol tcp --port $PORT --cidr $OLD_CIDR_BLOCK --no-cli-pager
            
            # Add the new rule
            aws ec2 authorize-security-group-ingress --group-id $sg --protocol tcp --port $PORT --cidr $NEW_CIDR_BLOCK --no-cli-pager
            
            echo "Security group $sg updated successfully."
        else
            echo "No matching rule found in security group $sg."
        fi
    done
done

echo "Script execution completed."
