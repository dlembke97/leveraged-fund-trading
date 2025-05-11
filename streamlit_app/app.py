import streamlit as st
import boto3
import os
from botocore.exceptions import ClientError

# ---------- Configuration ----------
# DynamoDB table name and AWS region via environment vars
TABLE_NAME = os.getenv('TABLE_NAME', 'Users')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')

# Initialize DynamoDB resource
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    table = dynamodb.Table(TABLE_NAME)
except Exception as e:
    st.error(f"Error initializing DynamoDB: {e}")
    st.stop()

# ---------- Authentication ----------
# Simple in-app authentication; replace or integrate with a secrets store for production
VALID_USERS = {
    "david": "Testing2020$!@#",
}

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Login form
if not st.session_state.logged_in:
    st.title("🔒 Trading Bot Registration — Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Log in"):
        if VALID_USERS.get(username) == password:
            st.session_state.logged_in = True
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid credentials")
    st.stop()

# ---------- Helper Functions ----------

def create_trading_config():
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

# ---------- Registration Form ----------
st.title("Trading Bot User Registration")
st.markdown("Complete the form below to register your account for the trading bot.")

with st.form(key="registration_form"):
    user_id = st.text_input("User ID", help="A unique identifier for your account")
    alpaca_api_key = st.text_input("Alpaca API Key")
    alpaca_api_secret = st.text_input("Alpaca API Secret", type="password")
    sender_email = st.text_input("Sender Email")
    receiver_email = st.text_input("Receiver Email")
    sender_email_password = st.text_input("Sender Email Password", type="password")
    submit = st.form_submit_button("Register")

if submit:
    # Validate inputs
    if not all([user_id, alpaca_api_key, alpaca_api_secret, sender_email, receiver_email, sender_email_password]):
        st.error("All fields are required. Please fill in every field.")
    else:
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
