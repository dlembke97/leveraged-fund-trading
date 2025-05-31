import os
import json
import time
import datetime
from zoneinfo import ZoneInfo

import boto3
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError
from alpaca_trade_api.rest import REST, TimeFrame, APIError
import pandas_market_calendars as mcal
from lambda_bot.common_scripts import EmailManager, setup_logger

#─── Setup ───────────────────────────────────────────────
logger = setup_logger("lambda_bot")

dynamodb = boto3.resource("dynamodb")
USERS_TABLE = os.getenv("USERS_TABLE", "Users")
table = dynamodb.Table(USERS_TABLE)

FERNET_KEY = os.environ["FERNET_KEY"].encode("utf-8")
fernet = Fernet(FERNET_KEY)

SENDER_EMAIL = os.environ["SENDER_EMAIL"]
SENDER_EMAIL_PASSWORD = os.environ["SENDER_EMAIL_PASSWORD"]

# NYSE calendar for market hours/holidays:
NYSE = mcal.get_calendar("NYSE")

# ─── Helper: Fetch & Decrypt Alpaca Credentials ─────────────────────────────────
def get_decrypted_alpaca_creds(user_id: str):
    """
    Given a user_id, fetch that item from DynamoDB, then decrypt
    the stored 'encrypted_alpaca_key' and 'encrypted_alpaca_secret' via Fernet.
    Returns (alpaca_api_key, alpaca_api_secret) as plain strings.
    """
    try:
        resp = table.get_item(Key={"user_id": user_id})
    except ClientError as e:
        raise RuntimeError(f"DynamoDB get_item error: {e.response['Error']['Message']}")

    item = resp.get("Item")
    if not item:
        raise RuntimeError(f"No user record for user_id = '{user_id}'")

    enc_key = item.get("encrypted_alpaca_key")
    enc_secret = item.get("encrypted_alpaca_secret")
    if not enc_key or not enc_secret:
        raise RuntimeError("Missing encrypted Alpaca credentials in DynamoDB item.")

    try:
        # Decrypt the Base64‐encoded token strings
        alpaca_api_key = fernet.decrypt(enc_key.encode("utf-8")).decode("utf-8")
        alpaca_api_secret = fernet.decrypt(enc_secret.encode("utf-8")).decode("utf-8")
    except Exception as e:
        raise RuntimeError(f"Fernet decryption failed: {str(e)}")

    return alpaca_api_key, alpaca_api_secret

def is_market_open():
    now = datetime.datetime.now(ZoneInfo("America/New_York"))
    schedule = NYSE.schedule(start_date=now.date(), end_date=now.date())
    if schedule.empty:
        return False

    # Use iloc[0] to grab the only row in today's schedule
    row = schedule.iloc[0]
    open_dt  = row["market_open"].to_pydatetime()
    close_dt = row["market_close"].to_pydatetime()
    return open_dt <= now <= close_dt

def wait_for_fill(api, order_id, interval=0.5):
    while True:
        o = api.get_order(order_id)
        if o.status == "filled":
            return
        time.sleep(interval)

def get_current_price(api, symbol):
    try:
        bars = list(api.get_bars(symbol, TimeFrame.Minute, limit=1))
        if bars and bars[0]:
            return bars[0].c
    except Exception:
        logger.warning(f"Minute data not available for {symbol}, falling back to daily.")
    today = datetime.date.today()
    bars = list(api.get_bars(symbol, TimeFrame.Day, start=today.isoformat(), limit=1))
    if bars:
        return bars[0].c
    return None

def one_cycle(api, config, email_mgr):
    for symbol, cfg in config.items():
        price = get_current_price(api, symbol)
        if price is None:
            continue

        # SELL logic
        for trigger in sorted(cfg["sell_triggers"]):
            if price >= trigger and trigger not in cfg["triggered_sell_levels"]:
                try:
                    order = api.submit_order(
                        symbol=symbol,
                        notional="200",
                        side="sell",
                        type="market",
                        time_in_force="day"
                    )
                except APIError:
                    logger.warning(f"Wash trade block on sell {symbol}; retrying in 1s")
                    time.sleep(1)
                    order = api.submit_order(
                        symbol=symbol,
                        notional="200",
                        side="sell",
                        type="market",
                        time_in_force="day"
                    )
                wait_for_fill(api, order.id)
                cfg["triggered_sell_levels"].add(trigger)
                email_mgr.send_trigger_alert(f"{symbol} sold at {trigger}")
                break

        # BUY logic
        for trigger in sorted(cfg["buy_triggers"]):
            if price <= trigger and trigger not in cfg["triggered_buy_levels"]:
                try:
                    order = api.submit_order(
                        symbol=symbol,
                        notional="200",
                        side="buy",
                        type="market",
                        time_in_force="day"
                    )
                except APIError:
                    logger.warning(f"Wash trade block on buy {symbol}; retrying in 1s")
                    time.sleep(1)
                    order = api.submit_order(
                        symbol=symbol,
                        notional="200",
                        side="buy",
                        type="market",
                        time_in_force="day"
                    )
                wait_for_fill(api, order.id)
                cfg["triggered_buy_levels"].add(trigger)
                email_mgr.send_trigger_alert(f"{symbol} bought at {trigger}")
                break

    return config

def lambda_handler(event, context):
    if not is_market_open():
        logger.info("Market closed, exiting.")
        return {"statusCode": 200, "body": "Market closed"}

    resp = table.scan()
    users = resp.get("Items", [])
    for u in users:
        user_id = u.get("user_id")
        logger.info(f"Processing user {user_id}")
        alpaca_api_key, alpaca_api_secret = get_decrypted_alpaca_creds(user_id)
        api = REST(
            alpaca_api_key,
            alpaca_api_secret,
            base_url="https://paper-api.alpaca.markets"
        )

        email_mgr = EmailManager(
            sender_email=SENDER_EMAIL,
            receiver_email=u.get("receiver_email"),
            sender_password=SENDER_EMAIL_PASSWORD
        )
        try:
            updated = one_cycle(api, u.get("trading_config", {}), email_mgr)
            table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET trading_config = :cfg",
                ExpressionAttributeValues={":cfg": updated}
            )
        except Exception as e:
            logger.error(f"Error for user {user_id}: {e}", exc_info=True)

    return {"statusCode": 200, "body": "Processed users"}
