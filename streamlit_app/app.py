import streamlit as st
import boto3
import json
from botocore.exceptions import ClientError

# ---------------------- Configuration ----------------------
# Ensure the following environment variables are set, or configure AWS credentials
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION

# DynamoDB table name
TABLE_NAME = "Users"

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TABLE_NAME)

# ---------------------- Helpers ----------------------

def create_trading_config():
    # Default initial trading_config structure
    return {
        "FNGA": {
            "buy_triggers": [300, 250, 200],
            "sell_triggers": [650, 700, 750],
            "last_buy_price": None,
            "last_sell_price": None,
            "triggered_buy_levels": [],
            "triggered_sell_levels": []
        },
        "TQQQ": {
            "buy_triggers": [45, 40, 35],
            "sell_triggers": [85, 90, 95],
            "last_buy_price": None,
            "last_sell_price": None,
            "triggered_buy_levels": [],
            "triggered_sell_levels": []
        }
    }

# ---------------------- Streamlit App ----------------------

st.title("Trading Bot User Registration")
st.markdown("Register to use the trading bot by providing your credentials below.")

# Input form
with st.form(key="registration_form"):
    user_id = st.text_input("User ID", help="Unique identifier for your account")
    alpaca_api_key = st.text_input("Alpaca API Key")
    alpaca_api_secret = st.text_input("Alpaca API Secret", type="password")
    sender_email = st.text_input("Sender Email")
    receiver_email = st.text_input("Receiver Email")
    sender_email_password = st.text_input("Sender Email Password", type="password")
    submit = st.form_submit_button("Register")

if submit:
    if not all([user_id, alpaca_api_key, alpaca_api_secret, sender_email, receiver_email, sender_email_password]):
        st.error("All fields are required. Please fill in every field.")
    else:
        # Prepare item
        item = {
            'user_id': user_id,
            'alpaca_api_key': alpaca_api_key,
            'alpaca_api_secret': alpaca_api_secret,
            'sender_email': sender_email,
            'receiver_email': receiver_email,
            'sender_email_password': sender_email_password,
            'trading_config': create_trading_config()
        }
        try:
            table.put_item(Item=item)
            st.success(f"User '{user_id}' registered successfully!")
        except ClientError as e:
            st.error(f"Registration failed: {e.response['Error']['Message']}")
