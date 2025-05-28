import streamlit as st
import boto3
import os
import json
from botocore.exceptions import ClientError
from streamlit_javascript import st_javascript

# ---------- Configuration ----------
TABLE_NAME = os.getenv('TABLE_NAME', 'Users')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-2')

dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)

# Load push-related secrets
REGISTER_ENDPOINT = st.secrets["REGISTER_ENDPOINT"]
PUBLIC_VAPID_KEY   = st.secrets["PUBLIC_VAPID_KEY"]
FIREBASE_CONFIG    = st.secrets["FIREBASE_CONFIG"]

# ---------- Authentication ----------
VALID_USERS = {
    "david": "Testing",
}

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

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

# ---------- Helpers ----------
def parse_trigger_list(text):
    try:
        return [int(x.strip()) for x in text.split(',') if x.strip()]
    except ValueError:
        return []

# ---------- Registration Form ----------
st.title("Trading Bot User Registration")
st.markdown("Complete the form below to register your account and custom trading configuration.")

with st.form("registration_form"):
    user_id                  = st.text_input("User ID", help="Unique identifier for your account")
    alpaca_api_key           = st.text_input("Alpaca API Key")
    alpaca_api_secret        = st.text_input("Alpaca API Secret", type="password")
    enable_notifs            = st.checkbox("Enable push notifications")
    sender_email             = st.text_input("Sender Email")
    receiver_email           = st.text_input("Receiver Email")
    sender_email_password    = st.text_input("Sender Email Password", type="password")
    st.markdown("---")
    st.subheader("Trading Configuration")
    tickers_str = st.text_input("Tickers (comma-separated)", value="FNGA,TQQQ")
    tickers     = [t.strip().upper() for t in tickers_str.split(',') if t.strip()]
    trading_config = {}
    for ticker in tickers:
        st.markdown(f"**{ticker}** configuration")
        buy_str  = st.text_input(f"{ticker} Buy Triggers (comma-separated)", key=f"buy_{ticker}")
        sell_str = st.text_input(f"{ticker} Sell Triggers (comma-separated)", key=f"sell_{ticker}")
        trading_config[ticker] = {
            "buy_triggers":         parse_trigger_list(buy_str),
            "sell_triggers":        parse_trigger_list(sell_str),
            "last_buy_price":       None,
            "last_sell_price":      None,
            "triggered_buy_levels": [],
            "triggered_sell_levels":[]
        }

    submitted = st.form_submit_button("Register")

if submitted:
    # Validate
    if not all([user_id, alpaca_api_key, alpaca_api_secret, sender_email, receiver_email, sender_email_password]):
        st.error("All primary fields are required. Please fill in every field.")
    else:
        # Persist to DynamoDB
        item = {
            'user_id':               user_id,
            'alpaca_api_key':        alpaca_api_key,
            'alpaca_api_secret':     alpaca_api_secret,
            'sender_email':          sender_email,
            'receiver_email':        receiver_email,
            'sender_email_password': sender_email_password,
            'trading_config':        trading_config
        }
        try:
            table.put_item(Item=item)
            st.success(f"User '{user_id}' registered successfully!")
            st.balloons()
        except ClientError as e:
            st.error(f"Registration failed: {e.response['Error']['Message']}")
            st.stop()

        # If they opted in, inject JS to register push token
        if enable_notifs:
            # JSON-stringify the Firebase config for injection
            firebase_json = json.dumps(FIREBASE_CONFIG)
            js = f"""
            (async () => {{
              // Load Firebase app & messaging
              firebase.initializeApp({firebase_json});
              const messaging = firebase.messaging();

              // Register service worker
              await navigator.serviceWorker.register('/firebase-messaging-sw.js');

              // Ask permission
              const perm = await Notification.requestPermission();
              if (perm === 'granted') {{
                // Get FCM token
                const token = await messaging.getToken({{ vapidKey: '{PUBLIC_VAPID_KEY}' }});
                // Send to your registration endpoint
                await fetch('{REGISTER_ENDPOINT}', {{
                  method: 'POST',
                  headers: {{ 'Content-Type': 'application/json' }},
                  body: JSON.stringify({{ user_id: '{user_id}', device_token: token }})
                }});
              }}
            }})();
            """
            st_javascript(js)
