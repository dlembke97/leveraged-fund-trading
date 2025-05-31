import streamlit as st
import boto3
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
    """
    Encrypt a UTF-8 string with Fernet, return a Base64‐encoded result.
    """
    token: bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def fernet_decrypt(token_b64: str) -> str:
    """
    Decrypt a Base64‐encoded Fernet token, return the plaintext string.
    """
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


# ─── Streamlit App Layout ─────────────────────────────────────────────────────
st.set_page_config(page_title="Trading Bot App", layout="centered")

tabs = st.tabs(["🔒 User Login", "📝 Registration (Admin Only)"])

# ─── Tab 1: User Login (with Change Password) ─────────────────────────────────
with tabs[0]:
    st.title("🔒 User Login")

    if "user_logged_in" not in st.session_state:
        st.session_state["user_logged_in"] = False

    with st.form("user_login_form"):
        user_id = st.text_input("Username", key="login_user_id")
        password = st.text_input("Password", type="password", key="login_password")

        change_pw = st.checkbox("Change Password?", key="change_pw_checkbox")
        if change_pw:
            current_pwd = st.text_input(
                "Current Password", type="password", key="current_password"
            )
            new_pwd = st.text_input("New Password", type="password", key="new_password")
            confirm_new = st.text_input(
                "Confirm New Password", type="password", key="confirm_new_password"
            )
            submit_button = st.form_submit_button("Update Password")
        else:
            submit_button = st.form_submit_button("Log In")

    if submit_button:
        if not user_id:
            st.error("Please enter your username.")
        else:
            item = get_user_item(user_id)

            if change_pw:
                # ─── Change Password Logic ─────────────────────────────────────
                if not (current_pwd and new_pwd and confirm_new):
                    st.error("All password fields are required to change your password.")
                else:
                    if not item:
                        st.error(
                            f"User not found. Please email {SENDER_EMAIL} "
                            "with your preferred username to register!"
                        )
                    else:
                        stored_hash = item.get("password_hash", "")
                        if not bcrypt.checkpw(current_pwd.encode("utf-8"), stored_hash.encode("utf-8")):
                            st.error("Current password is incorrect.")
                        elif new_pwd != confirm_new:
                            st.error("New password entries do not match.")
                        else:
                            success = update_user_password(user_id, new_pwd)
                            if success:
                                st.success("Password updated successfully!")
                                st.session_state["login_password"] = ""
                                st.session_state["current_password"] = ""
                                st.session_state["new_password"] = ""
                                st.session_state["confirm_new_password"] = ""
            else:
                # ─── Normal Login Logic ────────────────────────────────────────
                if not item:
                    st.error(
                        f"User not found. Please email {SENDER_EMAIL} "
                        "with your preferred username to register!"
                    )
                else:
                    stored_hash = item.get("password_hash", "")
                    if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                        # ─── FERNET‐DECRYPT ───────────────────────────────────
                        encrypted_key = item.get("encrypted_alpaca_key", "")
                        encrypted_secret = item.get("encrypted_alpaca_secret", "")
                        try:
                            alpaca_api_key = fernet_decrypt(encrypted_key)
                            alpaca_api_secret = fernet_decrypt(encrypted_secret)
                        except Exception as e:
                            st.error(f"Failed to decrypt Alpaca credentials: {e}")
                            st.stop()

                        st.session_state["user_logged_in"] = True
                        st.success(f"Welcome, {user_id}! 🎉")
                        # Now you can create an Alpaca REST client:
                        # from alpaca_trade_api.rest import REST, TimeFrame
                        # api = REST(alpaca_api_key, alpaca_api_secret, base_url="https://paper-api.alpaca.markets")
                    else:
                        st.error(f"Password for '{user_id}' incorrect.")


# ─── Tab 2: Registration (Admin Only) ─────────────────────────────────────────
with tabs[1]:
    st.title("📝 Registration (Admin Only)")

    if "admin_logged_in" not in st.session_state:
        st.session_state["admin_logged_in"] = False

    if not st.session_state["admin_logged_in"]:
        st.info("Please log in as admin to register new users.")

        with st.form("admin_login_form"):
            admin_user = st.text_input("Admin Username", key="admin_user_input")
            admin_pwd = st.text_input(
                "Admin Password", type="password", key="admin_password_input"
            )
            login_admin = st.form_submit_button("Log in as Admin")

        if login_admin:
            if VALID_USERS.get(admin_user) == admin_pwd:
                st.session_state["admin_logged_in"] = True
                st.success(f"Welcome, {admin_user}! You may now register new users.")
            else:
                st.error("Invalid admin credentials.")
        if not st.session_state["admin_logged_in"]:
            st.stop()

    # ─── Actual Registration Form ───────────────────────────────────────────
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
        # Basic required‐fields check
        if not all([new_user_id, receiver_email, raw_trading_password, raw_alpaca_api_key, raw_alpaca_api_secret]):
            st.error("All primary fields are required. Please fill in every field.")
        else:
            existing = get_user_item(new_user_id)
            if existing:
                st.error(f"User '{new_user_id}' already exists. Please choose a different username.")
            else:
                # ─── FERNET‐ENCRYPT ───────────────────────────────────────
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
                    st.session_state["trading_app_password"] = ""
                    st.session_state["alpaca_api_key"] = ""
                    st.session_state["alpaca_api_secret"] = ""
                except ClientError as e:
                    st.error(f"Registration failed: {e.response['Error']['Message']}")
