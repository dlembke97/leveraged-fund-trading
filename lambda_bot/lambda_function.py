import os
import time
import datetime
from zoneinfo import ZoneInfo

import boto3
from decimal import Decimal
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError

# Replace alpaca-trade-api imports with alpaca-py imports:
from alpaca.trading.client import TradingClient
from alpaca.trading.enums import OrderSide, OrderType, TimeInForce
from alpaca.trading.requests import MarketOrderRequest
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame as DataTimeFrame

from lambda_bot.common_scripts import EmailManager, setup_logger

# ─── Setup ───────────────────────────────────────────────
logger = setup_logger("lambda_bot")

dynamodb = boto3.resource("dynamodb")
USERS_TABLE = os.getenv("USERS_TABLE", "Users")
table = dynamodb.Table(USERS_TABLE)

FERNET_KEY = os.environ["FERNET_KEY"].encode("utf-8")
fernet = Fernet(FERNET_KEY)

SENDER_EMAIL = os.environ["SENDER_EMAIL"]
SENDER_EMAIL_PASSWORD = os.environ["SENDER_EMAIL_PASSWORD"]

# NYSE calendar for market hours/holidays:
import pandas_market_calendars as mcal  # unchanged

NYSE = mcal.get_calendar("NYSE")


# ─── Helper: Fetch & Decrypt Alpaca Credentials ─────────────────────────────────
def get_decrypted_alpaca_creds(user_id: str):
    """
    Given a user_id, fetch that item from DynamoDB, then decrypt
    'encrypted_alpaca_key' and 'encrypted_alpaca_secret' via Fernet.
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

    row = schedule.iloc[0]
    open_dt = row["market_open"].to_pydatetime()
    close_dt = row["market_close"].to_pydatetime()
    return open_dt <= now <= close_dt


def wait_for_fill(trading_client: TradingClient, order_id: str, interval: float = 0.5):
    """
    Polls Alpaca until the given order_id is filled.
    """
    while True:
        order = trading_client.get_order_by_id(order_id)
        if order.status == "filled":
            return
        time.sleep(interval)


def get_current_price(
    data_client: StockHistoricalDataClient, symbol: str
) -> float | None:
    """
    Attempts to fetch the latest minute bar; if unavailable, falls back to daily bar.
    Returns the close price as a float, or None if not found.
    """
    # 1) Try fetching the most recent minute bar (limit=1, no start/end means "latest")
    bars_req = StockBarsRequest(
        symbol_or_symbols=[symbol], timeframe=DataTimeFrame.MINUTE, limit=1
    )
    try:
        bars = data_client.get_stock_bars(bars_req)
        if bars and bars[symbol]:
            # bars[symbol] is a list of Bar objects; use the first one's close price
            return bars[symbol][0].close
    except Exception:
        logger.warning(
            f"Minute data not available for {symbol}, falling back to daily."
        )

    # 2) Fall back to today's daily bar
    today = datetime.date.today().isoformat()
    bars_req = StockBarsRequest(
        symbol_or_symbols=[symbol],
        timeframe=DataTimeFrame.DAY,
        start=today,
        end=today,
        limit=1,
    )
    bars = data_client.get_stock_bars(bars_req)
    if bars and bars[symbol]:
        return bars[symbol][0].close

    return None


def one_cycle(
    trading_client: TradingClient,
    data_client: StockHistoricalDataClient,
    config: dict,
    email_mgr: EmailManager,
) -> dict:
    """
    Executes one iteration of buy/sell logic for every symbol in `config`.
    Integrates two new blocks per‐ticker:
      - cfg["sell_reallocate"]: if enabled, reinvest sale proceeds
      - cfg["buy_funding"]: if type="sell", first sell other tickers to fund the buy
    Quantities are all dollar‐notional (Decimal).
    Returns the possibly‐updated config dictionary.
    """
    for symbol, cfg in config.items():
        price = get_current_price(data_client, symbol)
        if price is None:
            continue

        # ─── SELL logic ─────────────────────────────────────
        sell_pairs = sorted(
            zip(cfg.get("sell_triggers", []), cfg.get("sell_quantities", [])),
            key=lambda pair: pair[0],
        )
        for trigger, qty_decimal in sell_pairs:
            if price >= trigger and trigger not in cfg.get(
                "triggered_sell_levels", set()
            ):
                # 1) Place the triggered sell for this ticker
                order_request = MarketOrderRequest(
                    symbol=symbol,
                    notional=str(qty_decimal),  # dollar amount
                    side=OrderSide.SELL,
                    time_in_force=TimeInForce.DAY,
                )
                try:
                    order = trading_client.submit_order(order_request)
                except Exception as e:
                    # Mirror the old APIError retry logic for wash sale blocks
                    logger.warning(
                        f"Wash trade block on sell {symbol}@{trigger}; retrying in 1s"
                    )
                    time.sleep(1)
                    order = trading_client.submit_order(order_request)

                wait_for_fill(trading_client, order.id)

                # Mark this trigger as fired
                cfg.setdefault("triggered_sell_levels", set()).add(trigger)
                email_mgr.send_trigger_alert(
                    f"{symbol} sold at {trigger} (notional=${qty_decimal})"
                )

                # 2) Re‐allocate proceeds if requested
                sell_realloc = cfg.get("sell_reallocate", {"enabled": False})
                if sell_realloc.get("enabled", False):
                    total_sell_usd = qty_decimal  # entire proceed in USD

                    for tgt in sell_realloc.get("targets", []):
                        tgt_ticker = tgt["ticker"]
                        proportion = tgt["proportion"]  # Decimal
                        dollars_to_invest = (total_sell_usd * proportion).quantize(
                            Decimal("0.01")
                        )
                        if dollars_to_invest > 0:
                            try:
                                buy_req = MarketOrderRequest(
                                    symbol=tgt_ticker,
                                    notional=str(dollars_to_invest),
                                    side=OrderSide.BUY,
                                    time_in_force=TimeInForce.DAY,
                                )
                                buy_order = trading_client.submit_order(buy_req)
                                wait_for_fill(trading_client, buy_order.id)
                                email_mgr.send_trigger_alert(
                                    f"{tgt_ticker} re‐invested ${dollars_to_invest} "
                                    f"from sale of {symbol}@{trigger}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to re‐invest into {tgt_ticker}: {e}"
                                )
                break  # only one triggered sell per cycle

        # ─── BUY logic ──────────────────────────────────────
        buy_pairs = sorted(
            zip(cfg.get("buy_triggers", []), cfg.get("buy_quantities", [])),
            key=lambda pair: pair[0],
        )
        for trigger, qty_decimal in buy_pairs:
            if price <= trigger and trigger not in cfg.get(
                "triggered_buy_levels", set()
            ):
                buy_fund = cfg.get("buy_funding", {"type": "cash"})

                if buy_fund.get("type") == "cash":
                    # 1A) Straight cash‐balance buy
                    order_request = MarketOrderRequest(
                        symbol=symbol,
                        notional=str(qty_decimal),
                        side=OrderSide.BUY,
                        time_in_force=TimeInForce.DAY,
                    )
                    try:
                        order = trading_client.submit_order(order_request)
                    except Exception:
                        logger.warning(
                            f"Wash trade block on buy {symbol}@{trigger}; retrying in 1s"
                        )
                        time.sleep(1)
                        order = trading_client.submit_order(order_request)

                    wait_for_fill(trading_client, order.id)
                    cfg.setdefault("triggered_buy_levels", set()).add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} bought at {trigger} (notional=${qty_decimal})"
                    )

                else:
                    # 1B) Sell other ticker(s) first to raise funds
                    total_needed = qty_decimal
                    for source in buy_fund.get("sources", []):
                        src_ticker = source["ticker"]
                        proportion = source["proportion"]  # Decimal
                        usd_from_src = (total_needed * proportion).quantize(
                            Decimal("0.01")
                        )
                        if usd_from_src > 0:
                            try:
                                sell_req = MarketOrderRequest(
                                    symbol=src_ticker,
                                    notional=str(usd_from_src),
                                    side=OrderSide.SELL,
                                    time_in_force=TimeInForce.DAY,
                                )
                                sell_order = trading_client.submit_order(sell_req)
                                wait_for_fill(trading_client, sell_order.id)
                                email_mgr.send_trigger_alert(
                                    f"{src_ticker} sold for ${usd_from_src} "
                                    f"to fund buy of {symbol}@{trigger}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to sell {src_ticker} for funding: {e}"
                                )

                    # 2) Now place the intended buy
                    order_request = MarketOrderRequest(
                        symbol=symbol,
                        notional=str(qty_decimal),
                        side=OrderSide.BUY,
                        time_in_force=TimeInForce.DAY,
                    )
                    try:
                        order = trading_client.submit_order(order_request)
                    except Exception:
                        logger.warning(
                            f"Wash trade block on buy {symbol}@{trigger}; retrying in 1s"
                        )
                        time.sleep(1)
                        order = trading_client.submit_order(order_request)

                    wait_for_fill(trading_client, order.id)
                    cfg.setdefault("triggered_buy_levels", set()).add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} bought at {trigger} (notional=${qty_decimal})"
                    )

                break  # only one triggered buy per cycle

    return config


def lambda_handler(event, context):
    # Exit early if market closed
    if not is_market_open():
        logger.info("Market closed, exiting.")
        return {"statusCode": 200, "body": "Market closed"}

    resp = table.scan()
    users = resp.get("Items", [])

    for u in users:
        user_id = u.get("user_id")
        logger.info(f"Processing user {user_id}")

        try:
            alpaca_api_key, alpaca_api_secret = get_decrypted_alpaca_creds(user_id)
        except RuntimeError as err:
            logger.error(f"Skipping {user_id}: {err}")
            continue

        # Instantiate alpaca-py clients:
        trading_client = TradingClient(
            alpaca_api_key, alpaca_api_secret, paper=True  # use paper trading endpoint
        )
        data_client = StockHistoricalDataClient(alpaca_api_key, alpaca_api_secret)

        email_mgr = EmailManager(
            sender_email=SENDER_EMAIL,
            receiver_email=u.get("receiver_email"),
            sender_password=SENDER_EMAIL_PASSWORD,
        )

        # Ensure "triggered_*_levels" are sets
        trading_cfg = u.get("trading_config", {})
        trading_cfg.setdefault(
            "triggered_buy_levels", set(trading_cfg.get("triggered_buy_levels", []))
        )
        trading_cfg.setdefault(
            "triggered_sell_levels", set(trading_cfg.get("triggered_sell_levels", []))
        )

        try:
            updated_cfg = one_cycle(trading_client, data_client, trading_cfg, email_mgr)

            # Convert sets back to lists before saving to DynamoDB
            updated_cfg["triggered_buy_levels"] = list(
                updated_cfg.get("triggered_buy_levels", [])
            )
            updated_cfg["triggered_sell_levels"] = list(
                updated_cfg.get("triggered_sell_levels", [])
            )

            table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET trading_config = :cfg",
                ExpressionAttributeValues={":cfg": updated_cfg},
            )
        except Exception as e:
            logger.error(f"Error for user {user_id}: {e}", exc_info=True)

    return {"statusCode": 200, "body": "Processed users"}
