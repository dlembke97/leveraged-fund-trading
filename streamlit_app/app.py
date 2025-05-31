import streamlit as st
import boto3
import bcrypt
import pandas as pd
from decimal import Decimal
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError

# ─── Configuration & DynamoDB Setup ────────────────────────────────────────────
TABLE_NAME = st.secrets["DYNAMODB_TABLE_NAME"]
AWS_REGION = st.secrets["AWS_REGION"]
SENDER_EMAIL = st.secrets["SENDER_EMAIL"]

FERNET_KEY = st.secrets["FERNET_KEY"].encode("utf-8")
fernet = Fernet(FERNET_KEY)

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(TABLE_NAME)

VALID_USERS = {
    "david": st.secrets["DAVID_USER_PASSWORD"]
}


# ─── HELPER FUNCTIONS ──────────────────────────────────────────────────────────

def fernet_encrypt(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def fernet_decrypt(token_b64: str) -> str:
    return fernet.decrypt(token_b64.encode("utf-8")).decode("utf-8")


def get_user_item(user_id: str):
    try:
        resp = table.get_item(Key={"user_id": user_id})
    except ClientError as e:
        st.error(f"Error looking up user: {e.response['Error']['Message']}")
        return None
    return resp.get("Item")


def update_user_password(user_id: str, new_password: str) -> bool:
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


def update_user_credentials_partial(user_id: str, email: str, alpaca_key: str, alpaca_secret: str) -> bool:
    expressions = []
    values = {}
    if email:
        expressions.append("receiver_email = :e")
        values[":e"] = email
    if alpaca_key:
        expressions.append("encrypted_alpaca_key = :k")
        values[":k"] = fernet_encrypt(alpaca_key)
    if alpaca_secret:
        expressions.append("encrypted_alpaca_secret = :s")
        values[":s"] = fernet_encrypt(alpaca_secret)

    if not expressions:
        return True

    update_expr = "SET " + ", ".join(expressions)
    try:
        table.update_item(
            Key={"user_id": user_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=values,
        )
        return True
    except ClientError as e:
        st.error(f"Failed to update credentials: {e.response['Error']['Message']}")
        return False


def update_trading_config(user_id: str, config: dict) -> bool:
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


def edit_trigger_quantity_table(key_prefix: str, prev_triggers: list, prev_quantities: list, table_title: str = None):
    """
    Renders a two‐column data_editor labelled "Trigger" and "Quantity (USD)".
    Returns (List[int], List[Decimal]) based on the edited DataFrame.
    """
    df = pd.DataFrame({
        "Trigger": prev_triggers,
        "Quantity (USD)": [float(q) for q in prev_quantities]
    }).reset_index(drop=True)

    if table_title:
        st.write(table_title)

    edited = st.data_editor(
        df,
        num_rows="dynamic",
        hide_index=True,
        key=f"{key_prefix}_table"
    )

    triggers, quantities = [], []
    if "Trigger" in edited.columns and "Quantity (USD)" in edited.columns:
        for _, row in edited.iterrows():
            t, q = row["Trigger"], row["Quantity (USD)"]
            if pd.notna(t) and pd.notna(q):
                try:
                    triggers.append(int(t))
                    quantities.append(Decimal(str(float(q))))
                except Exception:
                    pass

    return triggers, quantities


def render_buy_funding_block(key_prefix: str, prev_block: dict):
    """
    Renders the "Buy‐Funding Source" radio + conditional ticker/proportion table.
    Returns:
      { "type": "cash" }
      OR
      { "type": "sell", "sources": [ {"ticker": str, "proportion": Decimal}, … ] }
    """
    prev_type = prev_block.get("type", "cash")
    st.write("**Buy‐Funding Source**")
    choice = st.radio(
        f"{key_prefix} → When a BUY triggers, use:",
        options=["Cash Balance", "Sell Other Ticker(s)"],
        index=0 if prev_type == "cash" else 1,
        key=f"buy_fund_type_{key_prefix}",
    )

    result = {}
    if choice == "Cash Balance":
        result["type"] = "cash"
    else:
        result["type"] = "sell"
        st.write("Specify ticker(s) to sell and proportions (must sum to 1.0):")
        prev_sources = prev_block.get("sources", [])
        df = pd.DataFrame({
            "Ticker": pd.Series([row.get("ticker", "") for row in prev_sources], dtype="string"),
            "Proportion": pd.Series([float(row.get("proportion", 0)) for row in prev_sources], dtype="float")
        }).reset_index(drop=True)

        edited = st.data_editor(
            df,
            num_rows="dynamic",
            hide_index=True,
            key=f"buy_src_table_{key_prefix}"
        )

        sources = []
        for _, row in edited.iterrows():
            tkr, prop = row["Ticker"], row["Proportion"]
            if pd.notna(tkr) and tkr.strip() and pd.notna(prop):
                try:
                    sources.append({"ticker": tkr.strip().upper(), "proportion": Decimal(str(float(prop)))})
                except Exception:
                    pass
        result["sources"] = sources

    return result


def render_sell_realloc_block(key_prefix: str, prev_block: dict):
    """
    Renders the "Sell‐Proceeds Re‐Allocation" radio + conditional ticker/proportion table.
    Returns:
      { "enabled": False }
      OR
      { "enabled": True, "targets": [ {"ticker": str, "proportion": Decimal}, … ] }
    """
    enabled = prev_block.get("enabled", False)
    st.write("**Sell‐Proceeds Re‐Allocation**")
    choice = st.radio(
        f"{key_prefix} → After a SELL triggers, should proceeds be re‐invested?",
        options=["No (keep in cash)", "Yes (allocate to other tickers)"],
        index=0 if not enabled else 1,
        key=f"sell_realloc_type_{key_prefix}",
    )

    result = {"enabled": False}
    if choice == "No (keep in cash)":
        result["enabled"] = False
    else:
        result["enabled"] = True
        st.write("Specify ticker(s) and proportions (must sum to 1.0):")
        prev_targets = prev_block.get("targets", [])
        df = pd.DataFrame({
            "Ticker": pd.Series([row.get("ticker", "") for row in prev_targets], dtype="string"),
            "Proportion": pd.Series([float(row.get("proportion", 0)) for row in prev_targets], dtype="float")
        }).reset_index(drop=True)

        edited = st.data_editor(
            df,
            num_rows="dynamic",
            hide_index=True,
            key=f"sell_tgt_table_{key_prefix}"
        )

        targets = []
        for _, row in edited.iterrows():
            tkr, prop = row["Ticker"], row["Proportion"]
            if pd.notna(tkr) and tkr.strip() and pd.notna(prop):
                try:
                    targets.append({"ticker": tkr.strip().upper(), "proportion": Decimal(str(float(prop)))})
                except Exception:
                    pass
        result["targets"] = targets

    return result


# ─── STREAMLIT APP LAYOUT ─────────────────────────────────────────────────────
st.set_page_config(page_title="Trading Bot App", layout="centered")
tabs = st.tabs(["Trading Selections", "📝 Registration (Admin Only)"])


# ─── TAB 1: USER LOGIN & TRADING CONFIG ────────────────────────────────────────
with tabs[0]:
    st.header("Trading Logic Login")

    # Session State Initialization
    if "user_logged_in" not in st.session_state:
        st.session_state["user_logged_in"] = False
    if "show_change_pw" not in st.session_state:
        st.session_state["show_change_pw"] = False
    if "logged_in_user" not in st.session_state:
        st.session_state["logged_in_user"] = ""
    if "show_update_credentials" not in st.session_state:
        st.session_state["show_update_credentials"] = False

    # ── LOGIN OR CHANGE PASSWORD ───────────────────────────────────────────────
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
                            st.session_state["user_logged_in"] = True
                            st.session_state["logged_in_user"] = user_id
                            st.success(f"Welcome, {user_id}! 🎉")
                            st.rerun()
                        else:
                            st.error(f"Password for '{user_id}' incorrect.")

            if st.button("Change Password"):
                st.session_state["show_change_pw"] = True
                st.rerun()

        else:
            st.info("🔑 Change Your Password")
            with st.form("change_password_form"):
                cp_user = st.text_input("Username", key="cp_user_id")
                cp_current = st.text_input("Current Password", type="password", key="cp_current_password")
                cp_new = st.text_input("New Password", type="password", key="cp_new_password")
                cp_confirm = st.text_input("Confirm New Password", type="password", key="cp_confirm_new_password")
                submitted_cp = st.form_submit_button("Update Password")

            if submitted_cp:
                if not (cp_user and cp_current and cp_new and cp_confirm):
                    st.error("All fields are required to change your password.")
                else:
                    item_cp = get_user_item(cp_user)
                    if not item_cp:
                        st.error(
                            f"User not found. Please email {SENDER_EMAIL} "
                            "with your preferred username to register!"
                        )
                    else:
                        stored_hash_cp = item_cp.get("password_hash", "")
                        if not bcrypt.checkpw(cp_current.encode("utf-8"), stored_hash_cp.encode("utf-8")):
                            st.error("Current password is incorrect.")
                        elif cp_new != cp_confirm:
                            st.error("New password entries do not match.")
                        else:
                            if update_user_password(cp_user, cp_new):
                                st.success("Password updated successfully!")
                                st.session_state["show_change_pw"] = False
                                st.rerun()

            if st.button("Back to Login"):
                st.session_state["show_change_pw"] = False
                st.rerun()

    # ── LOGGED‐IN USER DASHBOARD & CONFIG ───────────────────────────────────────
    else:
        user_id = st.session_state["logged_in_user"]
        item = get_user_item(user_id)
        if not item:
            st.error("Error fetching your account details.")
            st.stop()

        encrypted_key = item.get("encrypted_alpaca_key", "")
        encrypted_secret = item.get("encrypted_alpaca_secret", "")
        receiver_email = item.get("receiver_email", "")

        # If credentials missing, prompt to fill
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
                    if update_user_credentials_partial(user_id, email_input, key_input, secret_input):
                        st.success("Credentials saved successfully!")
                        st.rerun()

            st.stop()

        # Decrypt to verify
        try:
            alpaca_api_key = fernet_decrypt(encrypted_key)
            alpaca_api_secret = fernet_decrypt(encrypted_secret)
        except Exception as e:
            st.error(f"Failed to decrypt Alpaca credentials: {e}")
            st.stop()

        st.success(f"Logged in as **{user_id}**")
        st.write(f"Recipient email: **{receiver_email}**")

        # Toggle “Update Credentials”
        if not st.session_state["show_update_credentials"]:
            if st.button("Update Email or Alpaca Keys"):
                st.session_state["show_update_credentials"] = True
                st.rerun()
        else:
            st.info("✏️ Update Your Credentials")
            with st.form("update_credentials_form"):
                email_input = st.text_input("Recipient Email", value=receiver_email, key="upd_receiver_email")
                key_input = st.text_input("Alpaca API Key", value="", key="upd_alpaca_key")
                secret_input = st.text_input("Alpaca API Secret", type="password", value="", key="upd_alpaca_secret")
                save_updates = st.form_submit_button("Save Updates")

            if save_updates:
                if update_user_credentials_partial(
                    user_id,
                    email_input if email_input != receiver_email else "",
                    key_input,
                    secret_input
                ):
                    st.success("Credentials updated successfully!")
                    st.session_state["show_update_credentials"] = False
                    st.rerun()

            if st.button("Cancel"):
                st.session_state["show_update_credentials"] = False
                st.rerun()

        # ── TRADING CONFIGURATION SECTION ──────────────────────────────────────
        st.markdown("---")
        st.header("Threshold Based Trading Configuration")

        existing_config = item.get("trading_config", {})

        # Let user add/remove tickers in one line
        existing_tickers = list(existing_config.keys())
        ticker_values = ", ".join(existing_tickers) if existing_tickers else ""
        tickers_str = st.text_input(
            "Tickers (comma-separated)",
            value=ticker_values,
            help="Enter tickers you wish to configure, e.g. TQQQ, SPY",
            key="tc_tickers_str"
        )

        tickers = [t.strip().upper() for t in tickers_str.split(",") if t.strip()]

        new_trading_config = {}

        for ticker in tickers:
            st.markdown(f"### {ticker} configuration")
            prev = existing_config.get(ticker, {})

            # 1) Buy Levels & Quantities
            buy_trigs, buy_qs = edit_trigger_quantity_table(
                key_prefix=f"buy_{ticker}",
                prev_triggers=prev.get("buy_triggers", []),
                prev_quantities=prev.get("buy_quantities", []),
                table_title=f"{ticker} Buy Thresholds/Dollar Amounts"
            )

            # 2) Buy‐Funding Source
            buy_fund = render_buy_funding_block(
                key_prefix=f"buyfund_{ticker}",
                prev_block=prev.get("buy_funding", {"type": "cash"})
            )

            # 3) Sell Levels & Quantities
            sell_trigs, sell_qs = edit_trigger_quantity_table(
                key_prefix=f"sell_{ticker}",
                prev_triggers=prev.get("sell_triggers", []),
                prev_quantities=prev.get("sell_quantities", []),
                table_title=f"{ticker} Sell Thresholds/Dollar Amounts"
            )

            # 4) Sell‐Proceeds Re‐Allocation
            sell_realloc = render_sell_realloc_block(
                key_prefix=f"sellrealloc_{ticker}",
                prev_block=prev.get("sell_reallocate", {"enabled": False})
            )

            # 5) Build per‐ticker dictionary
            new_trading_config[ticker] = {
                "buy_triggers": buy_trigs,
                "buy_quantities": buy_qs,
                "buy_funding": buy_fund,

                "sell_triggers": sell_trigs,
                "sell_quantities": sell_qs,
                "sell_reallocate": sell_realloc,

                "last_buy_price": prev.get("last_buy_price"),
                "last_sell_price": prev.get("last_sell_price"),
                "triggered_buy_levels": prev.get("triggered_buy_levels", []),
                "triggered_sell_levels": prev.get("triggered_sell_levels", []),
            }

            st.markdown("---")

        if st.button("Save Trading Configuration"):
            if not tickers:
                st.error("Please specify at least one ticker.")
            else:
                if update_trading_config(user_id, new_trading_config):
                    st.success("Trading configuration updated!")


# ─── TAB 2: REGISTRATION (ADMIN ONLY) ───────────────────────────────────────────
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
    st.markdown("**Create a new user account.**")

    with st.form("registration_form"):
        new_user_id = st.text_input("Set Username", help="Unique identifier for this account")
        raw_trading_password = st.text_input("Set Your Password", type="password")
        submit = st.form_submit_button("Register")

    if submit:
        if not (new_user_id and raw_trading_password):
            st.error("Both Username and Password are required.")
        else:
            existing = get_user_item(new_user_id)
            if existing:
                st.error(f"User '{new_user_id}' already exists. Please choose a different username.")
            else:
                password_hash = bcrypt.hashpw(raw_trading_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
                item = {
                    "user_id": new_user_id,
                    "password_hash": password_hash,
                    "encrypted_alpaca_key": "",
                    "encrypted_alpaca_secret": "",
                    "receiver_email": "",
                    "trading_config": {},
                }
                try:
                    table.put_item(Item=item)
                    st.success(f"User '{new_user_id}' registered successfully!")
                    st.balloons()
                except ClientError as e:
                    st.error(f"Registration failed: {e.response['Error']['Message']}")
