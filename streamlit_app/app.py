import streamlit as st
import boto3
import bcrypt
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError

# ─── Configuration & DynamoDB Setup ────────────────────────────────────────────
TABLE_NAME = st.secrets["DYNAMODB_TABLE_NAME"]
AWS_REGION = st.secrets["AWS_REGION"]
SENDER_EMAIL = st.secrets["SENDER_EMAIL"]

# Get your Fernet key from secrets (Base64‐encoded)
FERNET_KEY = st.secrets["FERNET_KEY"].encode("utf-8")
fernet = Fernet(FERNET_KEY)

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)

# Admin credentials
VALID_USERS = {
    "david": st.secrets["DAVID_USER_PASSWORD"]
}


# ─── Helper Functions ──────────────────────────────────────────────────────────

def fernet_encrypt(plaintext: str) -> str:
    token: bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def fernet_decrypt(token_b64: str) -> str:
    plaintext: bytes = fernet.decrypt(token_b64.encode("utf-8"))
    return plaintext.decode("utf-8")


def get_user_item(user_id: str):
    """Fetch a user record from DynamoDB by user_id. Return None if not found."""
    try:
        response = table.get_item(Key={"user_id": user_id})
    except ClientError as e:
        st.error(f"Error looking up user: {e.response['Error']['Message']}")
        return None
    return response.get("Item")


def update_user_password(user_id: str, new_password: str) -> bool:
    """Overwrite the user’s hashed password in DynamoDB. Return True on success."""
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    try:
        table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET password_hash = :p",
            ExpressionAttributeValues={":p": hashed},
        )
        return True
    except ClientError as e:
        st.error(f"Failed to update password: {e.response['Error']['Message']}")
        return False


def update_user_credentials(user_id: str, email: str, alpaca_key: str, alpaca_secret: str):
    """
    Update receiver_email, encrypted_alpaca_key, and encrypted_alpaca_secret in DynamoDB.
    """
    encrypted_key = fernet_encrypt(alpaca_key)
    encrypted_secret = fernet_encrypt(alpaca_secret)
    try:
        table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET receiver_email = :e, encrypted_alpaca_key = :k, encrypted_alpaca_secret = :s",
            ExpressionAttributeValues={
                ":e": email,
                ":k": encrypted_key,
                ":s": encrypted_secret
            },
        )
        return True
    except ClientError as e:
        st.error(f"Failed to update credentials: {e.response['Error']['Message']}")
        return False


def update_trading_config(user_id: str, config: dict):
    """
    Overwrite the trading_config attribute for the given user_id.
    """
    try:
        table.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET trading_config = :c",
            ExpressionAttributeValues={":c": config},
        )
        return True
    except ClientError as e:
        st.error(f"Failed to update trading config: {e.response['Error']['Message']}")
        return False


# ─── Streamlit App Layout ─────────────────────────────────────────────────────
st.set_page_config(page_title="Trading Bot App", layout="centered")

tabs = st.tabs(["🔒 User Login", "📝 Registration (Admin Only)"])

# ─── Tab 1: User Login (with Change Password & Post-Login) ─────────────────────
with tabs[0]:
    st.title("🔒 User Login")

    # Initialize session state
    if "user_logged_in" not in st.session_state:
        st.session_state["user_logged_in"] = False
    if "show_change_pw" not in st.session_state:
        st.session_state["show_change_pw"] = False
    if "logged_in_user" not in st.session_state:
        st.session_state["logged_in_user"] = ""

    # ---------- If the user is not logged in, show login or change-password ----------
    if not st.session_state["user_logged_in"]:
        if not st.session_state["show_change_pw"]:
            with st.form("login_form"):
                user_id = st.text_input("Username", key="login_user_id")
                password = st.text_input("Password", type="password", key="login_password")
                submitted = st.form_submit_button("Log In")
            if submitted:
                if not user_id:
                    st.error("Please enter your username.")
                else:
                    item = get_user_item(user_id)
                    if not item:
                        st.error(
                            f"User not found. Please email {SENDER_EMAIL} "
                            "with your preferred username to register!"
                        )
                    else:
                        stored_hash = item.get("password_hash", "")
                        if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                            # Decrypt credentials if they exist (we'll check later)
                            st.session_state["user_logged_in"] = True
                            st.session_state["logged_in_user"] = user_id
                            st.success(f"Welcome, {user_id}! 🎉")
                            st.rerun()
                        else:
                            st.error(f"Password for '{user_id}' incorrect.")

            # Button to switch to change-password mode
            if st.button("Change Password"):
                st.session_state["show_change_pw"] = True
                st.rerun()

        else:
            st.info("🔑 Change Your Password")
            with st.form("change_password_form"):
                user_id_cp = st.text_input("Username", key="cp_user_id")
                current_pwd = st.text_input("Current Password", type="password", key="cp_current_password")
                new_pwd = st.text_input("New Password", type="password", key="cp_new_password")
                confirm_new = st.text_input("Confirm New Password", type="password", key="cp_confirm_new_password")
                submitted_cp = st.form_submit_button("Update Password")
            if submitted_cp:
                if not (user_id_cp and current_pwd and new_pwd and confirm_new):
                    st.error("All fields are required to change your password.")
                else:
                    item_cp = get_user_item(user_id_cp)
                    if not item_cp:
                        st.error(
                            f"User not found. Please email {SENDER_EMAIL} "
                            "with your preferred username to register!"
                        )
                    else:
                        stored_hash_cp = item_cp.get("password_hash", "")
                        if not bcrypt.checkpw(current_pwd.encode("utf-8"), stored_hash_cp.encode("utf-8")):
                            st.error("Current password is incorrect.")
                        elif new_pwd != confirm_new:
                            st.error("New password entries do not match.")
                        else:
                            success_cp = update_user_password(user_id_cp, new_pwd)
                            if success_cp:
                                st.success("Password updated successfully!")
                                st.session_state["show_change_pw"] = False
                                st.rerun()

            # Button to go back to login
            if st.button("Back to Login"):
                st.session_state["show_change_pw"] = False
                st.rerun()

    # ---------- If the user is logged in, show post-login account & config UI ----------
    else:
        user_id = st.session_state["logged_in_user"]
        item = get_user_item(user_id)
        if not item:
            st.error("Error fetching your account details.")
            st.stop()

        # Decrypt stored Alpaca keys (if present)
        encrypted_key = item.get("encrypted_alpaca_key", "")
        encrypted_secret = item.get("encrypted_alpaca_secret", "")
        receiver_email = item.get("receiver_email", "")

        # If any of the fields are missing, prompt user to fill them
        if not (receiver_email and encrypted_key and encrypted_secret):
            st.warning("⚠️ Please provide your Recipient Email and Alpaca API credentials to continue.")

            with st.form("fill_credentials_form"):
                email_input = st.text_input("Recipient Email", value=receiver_email or "", key="new_receiver_email")
                key_input = st.text_input("Alpaca API Key", value="", key="new_alpaca_key")
                secret_input = st.text_input("Alpaca API Secret", type="password", value="", key="new_alpaca_secret")
                save_creds = st.form_submit_button("Save Credentials")

            if save_creds:
                if not (email_input and key_input and secret_input):
                    st.error("All fields are required to save credentials.")
                else:
                    saved = update_user_credentials(user_id, email_input, key_input, secret_input)
                    if saved:
                        st.success("Credentials saved successfully!")
                        st.rerun()

            st.stop()

        # At this point, we know email and Alpaca keys exist; decrypt them if needed
        try:
            alpaca_api_key = fernet_decrypt(encrypted_key)
            alpaca_api_secret = fernet_decrypt(encrypted_secret)
        except Exception as e:
            st.error(f"Failed to decrypt Alpaca credentials: {e}")
            st.stop()

        st.success(f"Logged in as **{user_id}**")
        st.write(f"Recipient email: **{receiver_email}**")
        # We do not display Alpaca keys in UI for security, but they are available in memory

        # ─── Trading Configuration Section ────────────────────────────────────
        st.markdown("---")
        st.subheader("Trading Configuration")

        # Fetch existing trading_config (or default to empty dict)
        existing_config = item.get("trading_config", {})

        # Build a form to edit trading configuration
        with st.form("trading_config_form"):
            # Users enter tickers as comma-separated. If existing_config has keys, prefill.
            existing_tickers = list(existing_config.keys())
            ticker_values = ", ".join(existing_tickers) if existing_tickers else ""
            tickers_str = st.text_input(
                "Tickers (comma-separated)",
                value=ticker_values,
                help="Enter tickers you wish to configure, e.g. TQQQ, SPY",
                key="tc_tickers_str"
            )
            tickers = [t.strip().upper() for t in tickers_str.split(",") if t.strip()]

            # For each ticker, show buy/sell trigger fields, prefilled if exist
            new_trading_config = {}
            for ticker in tickers:
                st.markdown(f"**{ticker}** configuration")
                prev = existing_config.get(ticker, {})
                prev_buy = prev.get("buy_triggers", [])
                prev_sell = prev.get("sell_triggers", [])
                buy_str = st.text_input(
                    f"{ticker} Buy Triggers (comma-separated)",
                    value=", ".join(str(x) for x in prev_buy),
                    key=f"tc_buy_{ticker}"
                )
                sell_str = st.text_input(
                    f"{ticker} Sell Triggers (comma-separated)",
                    value=", ".join(str(x) for x in prev_sell),
                    key=f"tc_sell_{ticker}"
                )

                def parse_trigger_list(text):
                    try:
                        return [int(x.strip()) for x in text.split(",") if x.strip()]
                    except ValueError:
                        return []

                new_trading_config[ticker] = {
                    "buy_triggers": parse_trigger_list(buy_str),
                    "sell_triggers": parse_trigger_list(sell_str),
                    # Preserve last known prices/triggered levels if they exist
                    "last_buy_price": prev.get("last_buy_price"),
                    "last_sell_price": prev.get("last_sell_price"),
                    "triggered_buy_levels": prev.get("triggered_buy_levels", []),
                    "triggered_sell_levels": prev.get("triggered_sell_levels", []),
                }

            save_config = st.form_submit_button("Save Trading Configuration")

        if save_config:
            # Validate at least one ticker
            if not tickers:
                st.error("Please specify at least one ticker.")
            else:
                updated = update_trading_config(user_id, new_trading_config)
                if updated:
                    st.success("Trading configuration updated!")
                    st.rerun()


# ─── Tab 2: Registration (Admin Only) ─────────────────────────────────────────
with tabs[1]:
    st.title("📝 Registration (Admin Only)")

    if "admin_logged_in" not in st.session_state:
        st.session_state["admin_logged_in"] = False

    if not st.session_state["admin_logged_in"]:
        st.info("Please log in as admin to register new users.")
        with st.form("admin_login_form"):
            admin_user = st.text_input("Admin Username", key="admin_user_input")
            admin_pwd = st.text_input("Admin Password", type="password", key="admin_password_input")
            login_admin = st.form_submit_button("Log in as Admin")
        if login_admin:
            if VALID_USERS.get(admin_user) == admin_pwd:
                st.session_state["admin_logged_in"] = True
                st.success(f"Welcome, {admin_user}! You may now register new users.")
            else:
                st.error("Invalid admin credentials.")
        if not st.session_state["admin_logged_in"]:
            st.stop()

    st.markdown("---")
    st.markdown("**Create a new user account with custom trading configuration.**")

    def parse_trigger_list(text):
        try:
            return [int(x.strip()) for x in text.split(",") if x.strip()]
        except ValueError:
            return []

    with st.form(key="registration_form"):
        new_user_id = st.text_input("Set Username", help="Unique identifier for this account")
        receiver_email = st.text_input("Email")
        raw_trading_password = st.text_input("Set Your Password", type="password")
        raw_alpaca_api_key = st.text_input("Alpaca API Key")
        raw_alpaca_api_secret = st.text_input("Alpaca API Secret", type="password")

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
        if not all([new_user_id, receiver_email, raw_trading_password, raw_alpaca_api_key, raw_alpaca_api_secret]):
            st.error("All primary fields are required. Please fill in every field.")
        else:
            existing = get_user_item(new_user_id)
            if existing:
                st.error(f"User '{new_user_id}' already exists. Please choose a different username.")
            else:
                # Encrypt credentials and hash password
                encrypted_key = fernet_encrypt(raw_alpaca_api_key)
                encrypted_secret = fernet_encrypt(raw_alpaca_api_secret)
                password_hash = bcrypt.hashpw(raw_trading_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

                item = {
                    "user_id": new_user_id,
                    "password_hash": password_hash,
                    "encrypted_alpaca_key": encrypted_key,
                    "encrypted_alpaca_secret": encrypted_secret,
                    "receiver_email": receiver_email,
                    "trading_config": trading_config,
                }
                try:
                    table.put_item(Item=item)
                    st.success(f"User '{new_user_id}' registered successfully!")
                    st.balloons()
                    # Clear form state
                    st.session_state["new_user_id"] = ""
                    st.session_state["receiver_email"] = ""
                    st.session_state["raw_trading_password"] = ""
                    st.session_state["raw_alpaca_api_key"] = ""
                    st.session_state["raw_alpaca_api_secret"] = ""
                except ClientError as e:
                    st.error(f"Registration failed: {e.response['Error']['Message']}") 
