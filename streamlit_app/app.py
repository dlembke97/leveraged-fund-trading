import streamlit as st
import boto3
import os
import json
from botocore.exceptions import ClientError

# ---------- Configuration ----------
TABLE_NAME = os.getenv('TABLE_NAME', 'Users')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)

# ---------- Authentication ----------
VALID_USERS = {
    "david": "Testing",
}

# Initialize login state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Show login form if not authenticated
if not st.session_state.logged_in:
    st.title("🔒 Trading Bot Registration — Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    login_clicked = st.button("Log in")
    if login_clicked:
        if VALID_USERS.get(username) == password:
            st.session_state.logged_in = True
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid credentials")
    # If still not logged in, stop and do not show registration
    if not st.session_state.logged_in:
        st.stop()

# ---------- Helpers ----------

def parse_trigger_list(text):
    try:
        return [int(x.strip()) for x in text.split(',') if x.strip()]
    except ValueError:
        return []

# ---------- Registration Form ----------
st.title("Trading Bot User Registration")
st.markdown("Complete the form below to register your account and custom trading configuration.")

with st.form(key="registration_form"):
    user_id = st.text_input("User ID", help="Unique identifier for your account")
    alpaca_api_key = st.text_input("Alpaca API Key")
    alpaca_api_secret = st.text_input("Alpaca API Secret", type="password")
    sender_email = st.text_input("Sender Email")
    receiver_email = st.text_input("Receiver Email")
    sender_email_password = st.text_input("Sender Email Password", type="password")
    st.markdown("---")
    st.subheader("Trading Configuration")
    st.markdown("Enter your desired tickers and triggers.")
    tickers_str = st.text_input("Tickers (comma-separated)", value="FNGA,TQQQ")
    tickers = [t.strip().upper() for t in tickers_str.split(',') if t.strip()]
    trading_config = {}
    for ticker in tickers:
        st.markdown(f"**{ticker}** configuration")
        buy_str = st.text_input(f"{ticker} Buy Triggers (comma-separated)", key=f"buy_{ticker}")
        sell_str = st.text_input(f"{ticker} Sell Triggers (comma-separated)", key=f"sell_{ticker}")
        trading_config[ticker] = {
            "buy_triggers": parse_trigger_list(buy_str),
            "sell_triggers": parse_trigger_list(sell_str),
            "last_buy_price": None,
            "last_sell_price": None,
            "triggered_buy_levels": [],
            "triggered_sell_levels": []
        }
    submit = st.form_submit_button("Register")

if submit:
    if not all([user_id, alpaca_api_key, alpaca_api_secret, sender_email, receiver_email, sender_email_password]):
        st.error("All primary fields are required. Please fill in every field.")
    else:
        item = {
            'user_id': user_id,
            'alpaca_api_key': alpaca_api_key,
            'alpaca_api_secret': alpaca_api_secret,
            'sender_email': sender_email,
            'receiver_email': receiver_email,
            'sender_email_password': sender_email_password,
            'trading_config': trading_config
        }
        try:
            table.put_item(Item=item)
            st.success(f"User '{user_id}' registered successfully!")
            st.balloons()
        except ClientError as e:
            st.error(f"Registration failed: {e.response['Error']['Message']}")
