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

# ---------- Push Notification Secrets ----------
REGISTER_ENDPOINT   = st.secrets["REGISTER_ENDPOINT"]
PUBLIC_VAPID_KEY    = st.secrets["PUBLIC_VAPID_KEY"]
FIREBASE_API_KEY    = st.secrets["apiKey"]
FIREBASE_AUTH_DOMAIN= st.secrets["authDomain"]
FIREBASE_PROJECT_ID = st.secrets["projectId"]
FIREBASE_SENDER_ID  = st.secrets["messagingSenderId"]
FIREBASE_APP_ID     = st.secrets["appId"]

# ---------- Authentication ----------
VALID_USERS = {"david": "Testing"}

# Initialize login state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Login form
if not st.session_state.logged_in:
    st.title("🔒 Trading Bot Registration — Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted_login = st.form_submit_button("Log in")
    if submitted_login:
        if VALID_USERS.get(username) == password:
            st.session_state.logged_in = True
            st.success(f"Welcome, {username}!")
        else:
            st.error("Invalid credentials")
    # Only stop if still not logged in after attempt
    if not st.session_state.logged_in:
        st.stop()

# ---------- Helpers ---------- ---------- ----------
def parse_trigger_list(text):
    try:
        return [int(x.strip()) for x in text.split(',') if x.strip()]
    except ValueError:
        return []

# ---------- Registration Form ----------
st.title("Trading Bot User Registration")
st.markdown("Complete the form below to register your account and custom trading configuration.")

with st.form("registration_form"):
    user_id               = st.text_input("User ID", help="Unique identifier for your account")
    alpaca_api_key        = st.text_input("Alpaca API Key")
    alpaca_api_secret     = st.text_input("Alpaca API Secret", type="password")
    enable_notifs         = st.checkbox("Enable push notifications")
    sender_email          = st.text_input("Sender Email")
    receiver_email        = st.text_input("Receiver Email")
    sender_email_password = st.text_input("Sender Email Password", type="password")
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
            "buy_triggers": parse_trigger_list(buy_str),
            "sell_triggers": parse_trigger_list(sell_str),
            "last_buy_price": None,
            "last_sell_price": None,
            "triggered_buy_levels": [],
            "triggered_sell_levels": []
        }
    submitted = st.form_submit_button("Register")

if submitted:
    if not all([user_id, alpaca_api_key, alpaca_api_secret, sender_email, receiver_email, sender_email_password]):
        st.error("All primary fields are required. Please fill in every field.")
    else:
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

                        if enable_notifs:
            # Build Firebase config from individual secrets
            firebase_config = json.dumps({
                "apiKey": FIREBASE_API_KEY,
                "authDomain": FIREBASE_AUTH_DOMAIN,
                "projectId": FIREBASE_PROJECT_ID,
                "messagingSenderId": FIREBASE_SENDER_ID,
                "appId": FIREBASE_APP_ID
            })

            # Debugging-enhanced JS for push registration
            js = f"""
            (async () => {{
              console.log('🔔 Starting push registration flow');
              try {{
                // Load Firebase modules dynamically
                const fbAppModule = await import('https://www.gstatic.com/firebasejs/9.22.1/firebase-app.js');
                const fbMsgModule = await import('https://www.gstatic.com/firebasejs/9.22.1/firebase-messaging.js');
                const appInit = fbAppModule.initializeApp;
                const getMessaging = fbMsgModule.getMessaging;
                const getToken = fbMsgModule.getToken;

                // Initialize Firebase
                const app = appInit({{firebase_config}});
                console.log('✅ Firebase initialized');
                const messaging = getMessaging(app);
                console.log('✅ Firebase Messaging loaded');

                // Register Service Worker
                const sw = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
                console.log('✅ Service worker registered:', sw);

                // Request permission
                const permission = await Notification.requestPermission();
                console.log('🔔 Notification permission:', permission);
                if (permission === 'granted') {{
                  // Get token
                  const token = await getToken(messaging, {{ vapidKey: '{PUBLIC_VAPID_KEY}' }});
                  console.log('🔑 FCM token:', token);

                  // POST to registration endpoint
                  const response = await fetch('{REGISTER_ENDPOINT}', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ user_id: '{user_id}', device_token: token }})
                  }});
                  const text = await response.text();
                  console.log('📨 Registration response:', response.status, text);
                }}
              }} catch (err) {{
                console.error('❌ Push registration error:', err);
              }}
            }})();
            """
            st_javascript(js)
