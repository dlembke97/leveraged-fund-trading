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


def update_user_credentials_partial(user_id: str, email: str, alpaca_key: str, alpaca_secret: str) -> bool:
    """
    Update only the provided (non-empty) fields among receiver_email, encrypted_alpaca_key,
    or encrypted_alpaca_secret in DynamoDB.
    """
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
        return True  # nothing to update

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
    if "show_update_credentials" not in st.session_state:
        st.session_state["show_update_credentials"] = False

    # ─── If the user is not logged in, show login or change-password ───────────
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

            if st.button("Back to Login"):
                st.session_state["show_change_pw"] = False
                st.rerun()

    # ─── If the user is logged in, show post-login account & config UI ────────────
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

        # ─── If credentials are missing, prompt user to fill them ──────────────────
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
                    saved = update_user_credentials_partial(user_id, email_input, key_input, secret_input)
                    if saved:
                        st.success("Credentials saved successfully!")
                        st.rerun()

            st.stop()

        # ─── At this point, credentials exist ───────────────────────────────────────
        try:
            alpaca_api_key = fernet_decrypt(encrypted_key)
            alpaca_api_secret = fernet_decrypt(encrypted_secret)
        except Exception as e:
            st.error(f"Failed to decrypt Alpaca credentials: {e}")
            st.stop()

        st.success(f"Logged in as **{user_id}**")
        st.write(f"Recipient email: **{receiver_email}**")

        # Button to allow updating credentials
        if not st.session_state["show_update_credentials"]:
            if st.button("Update Email or Alpaca Keys"):
                st.session_state["show_update_credentials"] = True
                st.rerun()
        else:
            st.info("✏️ Update Your Credentials")
            with st.form("update_credentials_form"):
                # Email prefilled, keys empty
                email_input = st.text_input("Recipient Email", value=receiver_email, key="upd_receiver_email")
                key_input = st.text_input("Alpaca API Key", value="", key="upd_alpaca_key")
                secret_input = st.text_input("Alpaca API Secret", type="password", value="", key="upd_alpaca_secret")
                save_updates = st.form_submit_button("Save Updates")

            if save_updates:
                # Perform partial update: only non-empty fields get updated
                saved = update_user_credentials_partial(
                    user_id,
                    email_input if email_input != receiver_email else "",
                    key_input,
                    secret_input
                )
                if saved:
                    st.success("Credentials updated successfully!")
                    st.session_state["show_update_credentials"] = False
                    st.rerun()

            if st.button("Cancel"):
                st.session_state["show_update_credentials"] = False
                st.rerun()

        # ─── Trading Configuration Section (with editable tables) ───────────────────
        st.markdown("---")
        st.subheader("Trading Configuration")

        existing_config = item.get("trading_config", {})

        with st.form("trading_config_form"):
            # Let user add/remove tickers
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

                # ── 1) Buy Levels & Quantities via data_editor ─────────────────────
                prev_buy = prev.get("buy_triggers", [])
                prev_buy_qty = prev.get("buy_quantities", [])
                buy_df = pd.DataFrame({
                    "Trigger": prev_buy,
                    "Quantity (USD)": [float(q) for q in prev_buy_qty]
                }).reset_index(drop=True)

                st.write("Buy Levels and Quantities")
                edited_buy = st.data_editor(
                    buy_df,
                    num_rows="dynamic",
                    hide_index=True,
                    key=f"buy_table_{ticker}"
                )

                # Parse edited_buy back into lists
                buy_triggers = []
                buy_quantities = []
                if all(col in edited_buy.columns for col in ["Trigger", "Quantity (USD)"]):
                    for _, row in edited_buy.iterrows():
                        t = row["Trigger"]
                        q = row["Quantity (USD)"]
                        if pd.notna(t) and pd.notna(q):
                            try:
                                buy_triggers.append(int(t))
                                buy_quantities.append(Decimal(str(float(q))))
                            except Exception:
                                pass

                # ── 2) “Where do Buy funds come from?” ───────────────────────────
                prev_buy_funding = prev.get("buy_funding", {"type": "cash"})
                funding_type = prev_buy_funding.get("type", "cash")

                st.write("**Buy‐Funding Source**")
                bt = st.radio(
                    f"{ticker} → When a BUY triggers, use:",
                    options=["Cash Balance", "Sell Other Asset(s)"],
                    index=0 if funding_type == "cash" else 1,
                    key=f"buy_fund_type_{ticker}"
                )

                buy_funding_block = {}
                if bt == "Cash Balance":
                    buy_funding_block["type"] = "cash"
                else:
                    buy_funding_block["type"] = "sell"
                    st.write("Specify asset(s) to sell and proportions (must sum to 1.0):")
                    prev_sources = prev.get("buy_funding", {}).get("sources", [])
                    buy_src_df = pd.DataFrame({
                        "Asset": [row.get("asset", "") for row in prev_sources],
                        "Proportion": [float(row.get("proportion", 0)) for row in prev_sources]
                    }).reset_index(drop=True)

                    edited_buy_src = st.data_editor(
                        buy_src_df,
                        num_rows="dynamic",
                        hide_index=True,
                        key=f"buy_src_table_{ticker}"
                    )

                    new_buy_sources = []
                    for _, row in edited_buy_src.iterrows():
                        a = row.get("Asset")
                        p = row.get("Proportion")
                        if pd.notna(a) and a.strip() and pd.notna(p):
                            try:
                                dec_p = Decimal(str(float(p)))
                                new_buy_sources.append({"asset": a.strip().upper(), "proportion": dec_p})
                            except Exception:
                                pass
                    buy_funding_block["sources"] = new_buy_sources

                # ── 3) Sell Levels & Quantities via data_editor ─────────────────────
                prev_sell = prev.get("sell_triggers", [])
                prev_sell_qty = prev.get("sell_quantities", [])
                sell_df = pd.DataFrame({
                    "Trigger": prev_sell,
                    "Quantity (USD)": [float(q) for q in prev_sell_qty]
                }).reset_index(drop=True)

                st.write("Sell Levels and Quantities")
                edited_sell = st.data_editor(
                    sell_df,
                    num_rows="dynamic",
                    hide_index=True,
                    key=f"sell_table_{ticker}"
                )

                sell_triggers = []
                sell_quantities = []
                if all(col in edited_sell.columns for col in ["Trigger", "Quantity (USD)"]):
                    for _, row in edited_sell.iterrows():
                        t = row["Trigger"]
                        q = row["Quantity (USD)"]
                        if pd.notna(t) and pd.notna(q):
                            try:
                                sell_triggers.append(int(t))
                                sell_quantities.append(Decimal(str(float(q))))
                            except Exception:
                                pass

                # ── 4) “Re‐allocate Sell Proceeds?” ────────────────────────────────
                prev_sell_realloc = prev.get("sell_reallocate", {"enabled": False})
                sell_realloc_enabled = prev_sell_realloc.get("enabled", False)

                st.write("**Sell‐Proceeds Re‐Allocation**")
                sr = st.radio(
                    f"{ticker} → After a SELL triggers, should proceeds be re‐invested?",
                    options=["No (keep in cash)", "Yes (allocate to other assets)"],
                    index=0 if not sell_realloc_enabled else 1,
                    key=f"sell_realloc_type_{ticker}"
                )

                sell_realloc_block = {"enabled": False}
                if sr == "No (keep in cash)":
                    sell_realloc_block["enabled"] = False
                else:
                    sell_realloc_block["enabled"] = True
                    st.write("Specify asset(s) and proportions (must sum to 1.0):")
                    prev_targets = prev.get("sell_reallocate", {}).get("targets", [])
                    sell_tgt_df = pd.DataFrame({
                        "Asset": [row.get("asset", "") for row in prev_targets],
                        "Proportion": [float(row.get("proportion", 0)) for row in prev_targets]
                    }).reset_index(drop=True)

                    edited_sell_tgt = st.data_editor(
                        sell_tgt_df,
                        num_rows="dynamic",
                        hide_index=True,
                        key=f"sell_tgt_table_{ticker}"
                    )

                    new_sell_targets = []
                    for _, row in edited_sell_tgt.iterrows():
                        a = row.get("Asset")
                        p = row.get("Proportion")
                        if pd.notna(a) and a.strip() and pd.notna(p):
                            try:
                                dec_p = Decimal(str(float(p)))
                                new_sell_targets.append({"asset": a.strip().upper(), "proportion": dec_p})
                            except Exception:
                                pass
                    sell_realloc_block["targets"] = new_sell_targets

                # ── 5) Build per‐ticker config dict ─────────────────────────────────
                new_trading_config[ticker] = {
                    "buy_triggers": buy_triggers,
                    "buy_quantities": buy_quantities,
                    "buy_funding": buy_funding_block,

                    "sell_triggers": sell_triggers,
                    "sell_quantities": sell_quantities,
                    "sell_reallocate": sell_realloc_block,

                    "last_buy_price": prev.get("last_buy_price"),
                    "last_sell_price": prev.get("last_sell_price"),
                    "triggered_buy_levels": prev.get("triggered_buy_levels", []),
                    "triggered_sell_levels": prev.get("triggered_sell_levels", []),
                }

                st.markdown("---")

            save_config = st.form_submit_button("Save Trading Configuration")

        if save_config:
            if not tickers:
                st.error("Please specify at least one ticker.")
            else:
                updated = update_trading_config(user_id, new_trading_config)
                if updated:
                    st.success("Trading configuration updated!")


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
    st.markdown("**Create a new user account.**")

    with st.form(key="registration_form"):
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

                # Initially leave email, Alpaca credentials, and trading_config empty
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
