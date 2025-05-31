import streamlit as st
import boto3
from botocore.exceptions import ClientError

# ─── Configuration & DynamoDB Setup ────────────────────────────────────────────
TABLE_NAME = st.secrets["DYNAMODB_TABLE_NAME"]
AWS_REGION = st.secrets["AWS_REGION"]
SENDER_EMAIL = st.secrets["SENDER_EMAIL"]

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)

# Admin credentials (only you can register new users)
VALID_USERS = {
    "david": st.secrets["DAVID_USER_PASSWORD"]
}


# ─── Helper Functions ──────────────────────────────────────────────────────────
def get_user_item(user_id: str):
    """Fetch a user record from DynamoDB by user_id. Return None if not found."""
    try:
        response = table.get_item(Key={"user_id": user_id})
    except ClientError as e:
        st.error(f"Error looking up user: {e.response['Error']['Message']}")
        return None
    return response.get("Item")


def update_user_password(user_id: str, new_password: str) -> bool:
    """Overwrite the user’s trading_app_password in DynamoDB. Returns True on success."""
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


# ─── Streamlit App Layout ─────────────────────────────────────────────────────
st.set_page_config(page_title="Trading Bot App", layout="centered")

tabs = st.tabs(["🔒 User Login", "📝 Registration (Admin Only)"])

# ─── Tab 1: User Login (with Change Password) ─────────────────────────────────
with tabs[0]:
    st.title("🔒 User Login")

    # Initialize session state for normal user login
    if "user_logged_in" not in st.session_state:
        st.session_state["user_logged_in"] = False

    # Build a single form that handles both “Log In” and “Change Password”
    with st.form("user_login_form"):
        user_id = st.text_input("Username", key="login_user_id")
        password = st.text_input("Password", type="password", key="login_password")

        change_pw = st.checkbox("Change Password?", key="change_pw_checkbox")
        if change_pw:
            # Only show these fields if the user wants to change password
            current_pwd = st.text_input(
                "Current Password", type="password", key="current_password"
            )
            new_pwd = st.text_input(
                "New Password", type="password", key="new_password"
            )
            confirm_new = st.text_input(
                "Confirm New Password", type="password", key="confirm_new_password"
            )
            submit_button = st.form_submit_button("Update Password")
        else:
            submit_button = st.form_submit_button("Log In")

    # Handle form submission
    if submit_button:
        if not user_id:
            st.error("Please enter your username.")
        else:
            # Attempt to fetch from DynamoDB
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
                        stored_pwd = item.get("trading_app_password", "")
                        if current_pwd != stored_pwd:
                            st.error("Current password is incorrect.")
                        elif new_pwd != confirm_new:
                            st.error("New password entries do not match.")
                        else:
                            success = update_user_password(user_id, new_pwd)
                            if success:
                                st.success("Password updated successfully!")
                                # Clear out the password fields
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
                    stored_pwd = item.get("trading_app_password", "")
                    if password == stored_pwd:
                        st.session_state["user_logged_in"] = True
                        st.success(f"Welcome, {user_id}! 🎉")
                    else:
                        st.error(f"Password for '{user_id}' incorrect.")


# ─── Tab 2: Registration (Admin Only) ─────────────────────────────────────────
with tabs[1]:
    st.title("📝 Registration (Admin Only)")

    # Admin-login session state
    if "admin_logged_in" not in st.session_state:
        st.session_state["admin_logged_in"] = False

    # If not logged in as admin, show admin-login form
    if not st.session_state["admin_logged_in"]:
        st.info("Please log in as admin to register new users.")

        with st.form("admin_login_form"):
            # Using distinct keys so we don’t collide with any other widget
            admin_user = st.text_input("Admin Username", key="admin_user_input")
            admin_pwd = st.text_input(
                "Admin Password", type="password", key="admin_password_input"
            )
            login_admin = st.form_submit_button("Log in as Admin")

        if login_admin:
            if VALID_USERS.get(admin_user) == admin_pwd:
                st.session_state["admin_logged_in"] = True
                st.success(f"Welcome, {admin_user}! You may now register new users.")
                # Removed the lines that tried to clear admin_user_input / admin_password_input
            else:
                st.error("Invalid admin credentials.")

        # Prevent rendering the registration form until admin is logged in
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
        if not all([new_user_id, receiver_email, trading_app_password, alpaca_api_key, alpaca_api_secret]):
            st.error("All primary fields are required. Please fill in every field.")
        else:
            # Ensure username is not already in use
            existing = get_user_item(new_user_id)
            if existing:
                st.error(f"User '{new_user_id}' already exists. Please choose a different username.")
            else:
                item = {
                    "user_id": new_user_id,
                    "alpaca_api_key": alpaca_api_key,
                    "alpaca_api_secret": alpaca_api_secret,
                    "receiver_email": receiver_email,
                    "trading_app_password": trading_app_password,
                    "trading_config": trading_config,
                }
                try:
                    table.put_item(Item=item)
                    st.success(f"User '{new_user_id}' registered successfully!")
                    st.balloons()
                    # Optionally clear form state
                    st.session_state["new_user_id"] = ""
                    st.session_state["receiver_email"] = ""
                    st.session_state["trading_app_password"] = ""
                    st.session_state["alpaca_api_key"] = ""
                    st.session_state["alpaca_api_secret"] = ""
                except ClientError as e:
                    st.error(f"Registration failed: {e.response['Error']['Message']}")
