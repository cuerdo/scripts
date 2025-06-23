#!/usr/bin/env python3
import boto3
import csv
import argparse
from datetime import datetime, timezone

# ——— CONFIG ———

region_name = 'us-east-1'  # region where your CloudTrail event history is visible
output_csv = 'sso_last_activity.csv'

# ——— CLIENTS ———
idstore = boto3.client('identitystore', region_name='us-east-1')
trail = boto3.client('cloudtrail', region_name=region_name)

# ——— GET IDENTITY STORE ID AUTOMATICALLY ———
def get_identity_store_id():
    sso = boto3.client('sso-admin', region_name='us-east-1')
    instances = sso.list_instances()
    if not instances['Instances']:
        raise Exception("No IAM Identity Center instances found.")
    return instances['Instances'][0]['IdentityStoreId']

identity_store_id = get_identity_store_id()
print(f"Identity store id: {identity_store_id}")

# ——— STEP 1: List all users ———
def list_users():
    paginator = idstore.get_paginator('list_users')
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        for user in page['Users']:
            yield {
                'UserName': user.get('UserName'),
                'DisplayName': user.get('DisplayName'),
                'UserId': user.get('UserId')
            }

# ——— STEP 2: Get last activity from CloudTrail ———
def get_last_activity(username):
    latest = None
    paginator = trail.get_paginator('lookup_events')
    for page in paginator.paginate(
        LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': username}],
        MaxResults=50
    ):
        for event in page.get('Events', []):
            name = event['EventName']
            source = event['EventSource']
            if source in ('signin.amazonaws.com', 'sso.amazonaws.com', 'sts.amazonaws.com'):
                ts = event['EventTime']
                if not latest or ts > latest:
                    latest = ts
    return latest

# ——— MAIN ———
def main():
    parser = argparse.ArgumentParser(description='Check last activity of IAM Identity Center users.')
    parser.add_argument('--user', type=str, help='Username to check (case sensitive)')
    args = parser.parse_args()

    target_users = []

    if args.user:
        print(f"🔎 Checking user: {args.user}")
        for user in list_users():
            if user['UserName'] == args.user:
                target_users.append(user)
                break
        if not target_users:
            print(f"❌ User {args.user} not found in Identity Center.")
            return
    else:
        print("📋 Checking all users...")
        target_users = list(list_users())

    rows = []
    for user in target_users:
        usern = user['UserName']
        last_seen = get_last_activity(usern)
        rows.append({
            'UserName': usern,
            'DisplayName': user['DisplayName'],
            'LastSeen': last_seen.isoformat() if last_seen else 'Never'
        })
        print(f"✔ User {usern}: {'Never seen' if not last_seen else last_seen.isoformat()}")

    # ——— OUTPUT CSV ———
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['UserName', 'DisplayName', 'LastSeen'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n✅ Done! CSV saved to {output_csv}")

if __name__ == '__main__':
    main()

