# AWS Lambda Trading Bot

This project contains the AWS Lambda functions and supporting code for running your leveraged trading bot on a serverless schedule.

## Directory Structure

- lambda_bot/
  - `lambda_function.py`: Main Lambda handler implementing the trading cycle.
  - `common_scripts.py`: Logger setup and EmailManager for sending alerts.
  - `requirements.txt`: Python dependencies.

## Setup

1. **Create DynamoDB Table**  
   ```bash
   aws dynamodb create-table \
     --table-name Users \
     --attribute-definitions AttributeName=user_id,AttributeType=S \
     --key-schema AttributeName=user_id,KeyType=HASH \
     --billing-mode PAY_PER_REQUEST
   ```

2. **Configure AWS Lambda**  
   - In the AWS Console, create a new Lambda function using Python 3.11.  
   - Upload the contents of `lambda_bot/` as a ZIP file or via the AWS CLI:  
     ```bash
     zip -r deploy.zip lambda_function.py common_scripts.py requirements.txt
     aws lambda update-function-code --function-name MyTradingBot --zip-file fileb://deploy.zip
     ```
   - Set environment variable `USERS_TABLE=Users` in the Lambda configuration.

3. **Set Permissions**  
   Ensure the Lambda execution role has permissions:
   - `dynamodb:Scan`, `dynamodb:UpdateItem` on the `Users` table.  
   - `lambda:InvokeFunction` if using EventBridge Scheduler.  

4. **Schedule the Lambda**  
   Create an EventBridge Scheduler rule to run every minute or at market open:
   ```bash
   aws events put-rule \
     --name cron-every-minute \
     --schedule-expression "rate(1 minute)"
   aws events put-targets \
     --rule cron-every-minute \
     --targets "Id"="1","Arn"="arn:aws:lambda:REGION:ACCOUNT_ID:function:MyTradingBot"
   ```
   Grant permission:
   ```bash
   aws lambda add-permission \
     --function-name MyTradingBot \
     --statement-id "AllowEventBridgeInvoke" \
     --action "lambda:InvokeFunction" \
     --principal events.amazonaws.com \
     --source-arn "arn:aws:events:REGION:ACCOUNT_ID:rule/cron-every-minute"
   ```

5. **Environment Variables**  
   - `USERS_TABLE`: DynamoDB table name (default "Users").
   - (Optional) Use a `.env` file with `AWS_PROFILE` etc if using the AWS CLI locally.

## Local Testing

You can test the handler locally with a simple Python script:

```python
from lambda_bot.lambda_function import lambda_handler

print(lambda_handler({}, None))
```

## Dependencies

- boto3
- alpaca-trade-api
- python-dotenv
- pandas-market-calendars

Install locally via:

```bash
pip install -r lambda_bot/requirements.txt
```

## Notes

- The Lambda only runs when the market is open (uses NYSE calendar).
- State (trading_config) is stored per user in DynamoDB.
- Email notifications require valid SMTP credentials via `EmailManager`.
