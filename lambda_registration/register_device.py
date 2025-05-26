# lambda/register_device.py
import os
import json
import boto3

# DynamoDB table for Users
dynamodb = boto3.resource('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-2'))
users_table = dynamodb.Table(os.getenv('USERS_TABLE', 'Users'))

# SNS client
sns = boto3.client('sns')
# Your SNS Platform Application ARN for FCM
PLATFORM_ARN = os.getenv('SNS_FCM_PLATFORM_ARN')


def register_device(user_id, device_token):
    """
    Helper that creates or retrieves an SNS endpoint for a given FCM device token,
    then stores the resulting endpoint ARN in DynamoDB under the user record.
    """
    # Create (or get) the platform endpoint
    resp = sns.create_platform_endpoint(
        PlatformApplicationArn=PLATFORM_ARN,
        Token=device_token,
        CustomUserData=user_id
    )
    endpoint_arn = resp['EndpointArn']

    # Save endpoint ARN in the Users table
    users_table.update_item(
        Key={'user_id': user_id},
        UpdateExpression="SET push_endpoint = :e",
        ExpressionAttributeValues={':e': endpoint_arn}
    )
    return endpoint_arn


def lambda_handler(event, context):
    # Parse the incoming POST body
    body = json.loads(event.get('body', '{}'))
    user_id = body.get('user_id')
    device_token = body.get('device_token')
    if not user_id or not device_token:
        return {"statusCode":400, "body":"Missing user_id or device_token"}

    # Call the helper to register and store the endpoint
    try:
        endpoint = register_device(user_id, device_token)
        return {"statusCode":200, "body": json.dumps({"endpoint_arn": endpoint})}
    except Exception as e:
        return {"statusCode":500, "body": str(e)}