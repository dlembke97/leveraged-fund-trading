import os
import json
import time
import datetime
from zoneinfo import ZoneInfo

import boto3
from alpaca_trade_api.rest import REST, TimeFrame, APIError
import pandas_market_calendars as mcal
from lambda_bot.common_scripts import EmailManager, setup_logger

#─── Setup ───────────────────────────────────────────────
logger = setup_logger("lambda_bot")
dynamodb = boto3.resource("dynamodb")
USERS_TABLE = os.getenv("USERS_TABLE", "Users")
table = dynamodb.Table(USERS_TABLE)

# NYSE calendar for market hours/holidays:
NYSE = mcal.get_calendar("NYSE")

def is_market_open():
    now = datetime.datetime.now(ZoneInfo("America/New_York"))
    schedule = NYSE.schedule(start_date=now.date(), end_date=now.date())
    if schedule.empty:
        return False
    open_dt = schedule.at[now.date(), "market_open"].to_pydatetime()
    close_dt = schedule.at[now.date(), "market_close"].to_pydatetime()
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
        # SELL logic for example
        for trigger in sorted(cfg["sell_triggers"]):
            if price >= trigger and trigger not in cfg["triggered_sell_levels"]:
                try:
                    order = api.submit_order(symbol=symbol, notional="200", side="sell", type="market", time_in_force="day")
                except APIError:
                    logger.warning(f"Wash trade block on sell {symbol}; retrying in 1s")
                    time.sleep(1)
                    order = api.submit_order(symbol=symbol, notional="200", side="sell", type="market", time_in_force="day")
                wait_for_fill(api, order.id)
                cfg["triggered_sell_levels"].add(trigger)
                email_mgr.send_trigger_alert(f"{symbol} sold at {trigger}")
                break
        # BUY logic would go here...
    return config

def lambda_handler(event, context):
    if not is_market_open():
        logger.info("Market closed, exiting.")
        return {"statusCode": 200, "body": "Market closed"}

    resp = table.scan()
    users = resp.get("Items", [])
    for u in users:
        user_id = u["user_id"]
        logger.info(f"Processing user {user_id}")
        api = REST(u["alpaca_api_key"], u["alpaca_api_secret"], base_url="https://paper-api.alpaca.markets")
        email_mgr = EmailManager(sender_email=u["sender_email"], receiver_email=u["receiver_email"], sender_password=u["sender_email_password"])
        try:
            updated = one_cycle(api, u.get("trading_config", {}), email_mgr)
            table.update_item(Key={"user_id": user_id},
                              UpdateExpression="SET trading_config = :cfg",
                              ExpressionAttributeValues={":cfg": updated})
        except Exception as e:
            logger.error(f"Error for user {user_id}: {e}", exc_info=True)

    return {"statusCode": 200, "body": "Processed users"}
