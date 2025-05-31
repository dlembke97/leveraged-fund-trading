import streamlit as st
import boto3
import os
from botocore.exceptions import ClientError

# ---------- Configuration & DynamoDB setup ----------
TABLE_NAME = st.secrets["DYNAMODB_TABLE_NAME"]
AWS_REGION = st.secrets["AWS_REGION"]

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)

# ---------- Helper Functions ----------
def get_user_item(user_id: str):
    """Fetch a user item from DynamoDB by user_id. Returns None if not found."""
    try:
        response = table.get_item(Key={"user_id": user_id})
    except ClientError as e:
        st.error(f"Error looking up user: {e.response['Error']['Message']}")
        return None

    return response.get("Item")


def update_user_password(user_id: str, new_password: str):
    """Update the trading_app_password attribute for a given user_id."""
    try:
        table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET trading_app_password = :p",
            ExpressionAttributeValues={":p": new_password},
        )
        return True
    except ClientError as e:
        st.error(f"Failed to update password: {e.response['Error']['Message']}")
        return False


# ---------- Streamlit App ----------
st.set_page_config(page_title="Trading Bot App", layout="centered")

tabs = st.tabs(["🔒 Login", "📝 Registration"])

# ─── Tab 1: Login (with Change Password) ─────────────────────────────────────
with tabs[0]:
    st.title("🔒 Trading Bot — Login / Change Password")

    mode = st.radio(
        label="Select an action:",
        options=["Log In", "Change Password"],
        horizontal=True,
    )

    if mode == "Log In":
        with st.form("login_form"):
            login_user_id = st.text_input("Username", key="login_user_id")
            login_password = st.text_input("Password", type="password", key="login_password")
            submitted_login = st.form_submit_button("Log in")

        if submitted_login:
            if not login_user_id or not login_password:
                st.error("Please enter both username and password.")
            else:
                item = get_user_item(login_user_id)
                if not item:
                    st.error(
                        "User not found, please email dlembke9797@gmail.com "
                        "with your preferred username to register!"
                    )
                else:
                    stored_pwd = item.get("trading_app_password", "")
                    if stored_pwd == login_password:
                        st.success(f"Welcome, {login_user_id}! 🎉")
                        # Mark user as “logged in” in session state if you need it for downstream tabs
                        st.session_state["logged_in_user"] = login_user_id
                    else:
                        st.error(f"Password for '{login_user_id}' incorrect.")

    else:  # mode == "Change Password"
        st.markdown(
            "To update your password, please fill in all fields below and click **Update Password**."
        )
        with st.form("change_password_form"):
            cp_user_id = st.text_input("Username", key="cp_user_id")
            cp_current_pwd = st.text_input("Current Password", type="password", key="cp_current_pwd")
            cp_new_pwd = st.text_input("New Password", type="password", key="cp_new_pwd")
            cp_confirm_new = st.text_input(
                "Confirm New Password", type="password", key="cp_confirm_new"
            )
            submitted_cp = st.form_submit_button("Update Password")

        if submitted_cp:
            # Basic validation
            if not (cp_user_id and cp_current_pwd and cp_new_pwd and cp_confirm_new):
                st.error("All fields are required to change your password.")
            else:
                item = get_user_item(cp_user_id)
                if not item:
                    st.error(
                        "User not found, please email dlembke97@gmail.com "
                        "with your preferred username to register!"
                    )
                else:
                    stored_pwd = item.get("trading_app_password", "")
                    if cp_current_pwd != stored_pwd:
                        st.error("Current password is incorrect.")
                    elif cp_new_pwd != cp_confirm_new:
                        st.error("New password entries do not match.")
                    else:
                        success = update_user_password(cp_user_id, cp_new_pwd)
                        if success:
                            st.success("Password updated successfully!")
                            # Optionally clear fields or set session state
                            st.session_state["cp_current_pwd"] = ""
                            st.session_state["cp_new_pwd"] = ""
                            st.session_state["cp_confirm_new"] = ""


# ─── Tab 2: Registration ──────────────────────────────────────────────────────
with tabs[1]:
    st.title("📝 Trading Bot User Registration")
    st.markdown("Complete the form below to register your account and custom trading configuration.")

    def parse_trigger_list(text):
        try:
            return [int(x.strip()) for x in text.split(",") if x.strip()]
        except ValueError:
            return []

    with st.form(key="registration_form"):
        user_id = st.text_input("Set Username", help="Unique identifier for your account")
        receiver_email = st.text_input("Email")
        trading_app_password = st.text_input("Set Your Password", type="password")
        alpaca_api_key = st.text_input("Alpaca API Key")
        alpaca_api_secret = st.text_input("Alpaca API Secret", type="password")

        st.markdown("---")
        st.subheader("Trading Configuration")
        st.markdown("Enter your desired tickers and triggers.")
        tickers_str = st.text_input("Tickers (comma-separated)", value="TQQQ")
        tickers = [t.strip().upper() for t in tickers_str.split(",") if t.strip()]

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
                "triggered_sell_levels": [],
            }

        submit = st.form_submit_button("Register")

    if submit:
        # Basic required‐fields check
        if not all([user_id, alpaca_api_key, alpaca_api_secret, receiver_email, trading_app_password]):
            st.error("All primary fields are required. Please fill in every field.")
        else:
            # Before writing, check if user already exists
            existing = get_user_item(user_id)
            if existing:
                st.error(f"User '{user_id}' already exists. Please pick a different username.")
            else:
                item = {
                    "user_id": user_id,
                    "alpaca_api_key": alpaca_api_key,
                    "alpaca_api_secret": alpaca_api_secret,
                    "receiver_email": receiver_email,
                    "trading_app_password": trading_app_password,
                    "trading_config": trading_config,
                }
                try:
                    table.put_item(Item=item)
                    st.success(f"User '{user_id}' registered successfully!")
                    st.balloons()
                except ClientError as e:
                    st.error(f"Registration failed: {e.response['Error']['Message']}")
