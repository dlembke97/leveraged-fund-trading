import os
import time
import datetime
from zoneinfo import ZoneInfo
import re

import boto3
from decimal import Decimal
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError

# alpaca-py imports
from alpaca.trading.client import TradingClient
from alpaca.trading.enums import OrderSide, OrderType, TimeInForce
from alpaca.trading.requests import MarketOrderRequest
from alpaca.data.historical import StockHistoricalDataClient
from alpaca.data.requests import StockBarsRequest
from alpaca.data.timeframe import TimeFrame as DataTimeFrame

import pandas_market_calendars as mcal

from lambda_bot.common_scripts import EmailManager, setup_logger

# ─── Setup ───────────────────────────────────────────────
logger = setup_logger("lambda_bot")

dynamodb = boto3.resource("dynamodb")
USERS_TABLE = os.getenv("USERS_TABLE", "Users")
STATE_TABLE = os.getenv("STATE_TABLE", "TweetState")
SIGNALS_TABLE = os.getenv("SIGNALS_TABLE", "TweetSignals")
table = dynamodb.Table(USERS_TABLE)
state_tbl = dynamodb.Table(STATE_TABLE)
signals_tbl = dynamodb.Table(SIGNALS_TABLE)

FERNET_KEY = os.environ["FERNET_KEY"].encode("utf-8")
fernet = Fernet(FERNET_KEY)
SENDER_EMAIL = os.environ["SENDER_EMAIL"]
SENDER_PASSWORD = os.environ["SENDER_EMAIL_PASSWORD"]

# NYSE calendar for market hours/holidays:
NYSE = mcal.get_calendar("NYSE")

# ─── Capital Gains Constants ─────────────────────────────────────────────
LONG_TERM_DAYS = 365
LTCG_BUFFER_DAYS = 30
DEFAULT_NOTIONAL = Decimal("1000")

# ─── Twitter Constants ────────────────────────────────────────────────────
# Dollar amount to trade per Twitter “buy” or “sell” signal:
TWITTER_NOTIONAL = Decimal("500")


# ─── Helper: Fetch & Decrypt Alpaca Credentials ─────────────────────────────
def get_decrypted_alpaca_creds(user_id: str):
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
    1) Try to fetch the latest minute bar; if that fails (403 or no data),
       fall back to today’s daily bar.
    2) If there is still no bar for `symbol`, return None.
    """
    # ─── Try minute bars ─────────────────────────────────────────
    try:
        bars_req = StockBarsRequest(
            symbol_or_symbols=[symbol], timeframe=DataTimeFrame.Minute, limit=1
        )
        minute_bars = data_client.get_stock_bars(bars_req)
        if (
            hasattr(minute_bars, "data")
            and symbol in minute_bars.data
            and minute_bars.data[symbol]
        ):
            return minute_bars.data[symbol][0].close
    except Exception:
        logger.warning(
            f"Could not fetch minute bars for {symbol} (403 or no data); falling back to daily."
        )

    # ─── Fall back to a daily bar for “today” ───────────────────
    today_iso = datetime.date.today().isoformat()
    try:
        bars_req = StockBarsRequest(
            symbol_or_symbols=[symbol],
            timeframe=DataTimeFrame.Day,
            start=today_iso,
            end=today_iso,
            limit=1,
        )
        daily_bars = data_client.get_stock_bars(bars_req)
        if (
            hasattr(daily_bars, "data")
            and symbol in daily_bars.data
            and daily_bars.data[symbol]
        ):
            return daily_bars.data[symbol][0].close
    except Exception:
        logger.warning(f"Could not fetch daily bar for {symbol} (no data).")

    return None


# ─── RegEx patterns ────────────────────────────────────────────────────────
TICKER_RE = re.compile(r"\$([A-Za-z]{1,5})")
BUY_WORDS = re.compile(r"\b(buy|long|accumulate|moon|bullish)\b", re.IGNORECASE)
SELL_WORDS = re.compile(r"\b(sell|short|profit|bearish)\b", re.IGNORECASE)


def extract_tickers(text: str) -> list[str]:
    """Return uppercase tickers found via $TICKER syntax."""
    return [m.group(1).upper() for m in TICKER_RE.finditer(text)]


def classify_tweet(text: str) -> str:
    """
    Keyword-based classification:
      • If bullish keywords → "buy"
      • If bearish keywords → "sell"
      • Otherwise → "hold"
    """
    if BUY_WORDS.search(text):
        return "buy"
    if SELL_WORDS.search(text):
        return "sell"
    return "hold"


# ─── FIFO Lot Reconstruction ─────────────────────────────────────────────
def sync_positions(
    trading_client: TradingClient, symbol: str, initial_lots: list[dict]
) -> list[dict]:
    """
    Build a FIFO list of {"quantity": float, "timestamp": ISO-string} for this symbol,
    merging:
      1) “Closed BUY” orders from Alpaca
      2) Any user-supplied initial lots (shares transferred in) in chronological order
    """
    now = datetime.datetime.now(ZoneInfo("America/New_York"))
    try:
        pos = trading_client.get_position(symbol)
        total_qty = float(pos.qty)
    except Exception:
        return []

    orders = trading_client.get_orders(
        status="closed",
        side="buy",
        symbol=symbol,
        limit=500,
        after="2000-01-01",
        until=now.isoformat(),
    )
    filled = [o for o in orders if float(o.filled_qty) > 0]
    filled.sort(key=lambda o: o.filled_at)

    lots = []
    accumulated = 0.0
    for o in filled:
        if accumulated >= total_qty:
            break
        qty = min(total_qty - accumulated, float(o.filled_qty))
        lots.append({"quantity": qty, "timestamp": o.filled_at})
        accumulated += qty

    initial_lots = initial_lots or []
    sorted_initial = sorted(initial_lots, key=lambda lot: lot["timestamp"])
    for init_lot in sorted_initial:
        if accumulated >= total_qty:
            break
        qty_avail = float(init_lot.get("quantity", 0.0))
        if qty_avail <= 0:
            continue
        take_qty = min(qty_avail, total_qty - accumulated)
        lots.append({"quantity": take_qty, "timestamp": init_lot["timestamp"]})
        accumulated += take_qty

    if accumulated < total_qty:
        leftover = total_qty - accumulated
        lots.append({"quantity": leftover, "timestamp": now.isoformat()})
        accumulated += leftover

    return lots


# ─── Sell Allocation Honoring LTCG & STCG Buffer ─────────────────────────────
def allocate_and_execute_sells(
    trading_client: TradingClient,
    symbol: str,
    cfg: dict,
    email_mgr: EmailManager,
    price: float,
):
    """
    (same as your original code; omitted for brevity)
    """
    now = datetime.datetime.now(ZoneInfo("America/New_York"))

    notional = Decimal(str(cfg.get("sell_notional", DEFAULT_NOTIONAL)))
    shares_to_sell = float(notional / price) if price > 0 else 0.0
    if shares_to_sell <= 0:
        return

    positions = cfg.setdefault("positions", [])
    if not positions:
        positions[:] = sync_positions(
            trading_client, symbol, cfg.get("initial_lots", [])
        )

    fifo_list = sorted(
        [(idx, lot["quantity"], lot["timestamp"]) for idx, lot in enumerate(positions)],
        key=lambda entry: datetime.datetime.fromisoformat(entry[2]),
    )

    total_sold_shares = 0.0
    total_LTCG_proceeds = Decimal("0.0")
    total_STCG_proceeds = Decimal("0.0")

    for idx, avail_qty, ts_iso in fifo_list:
        if total_sold_shares >= shares_to_sell:
            break

        buy_ts = datetime.datetime.fromisoformat(ts_iso)
        age_days = (now - buy_ts).days

        if (age_days >= (LONG_TERM_DAYS - LTCG_BUFFER_DAYS)) and (
            age_days < LONG_TERM_DAYS
        ):
            logger.info(
                f"{symbol}: encountered ST_near lot (age {age_days} days). "
                "Stopping further sells to avoid STCG."
            )
            break

        if (age_days >= LONG_TERM_DAYS) or (
            age_days < (LONG_TERM_DAYS - LTCG_BUFFER_DAYS)
        ):
            qty_left_to_sell = shares_to_sell - total_sold_shares
            qty_from_this_lot = min(avail_qty, qty_left_to_sell)

            if qty_from_this_lot <= 0:
                continue

            sell_req = MarketOrderRequest(
                symbol=symbol,
                qty=str(qty_from_this_lot),
                side=OrderSide.SELL,
                type=OrderType.MARKET,
                time_in_force=TimeInForce.DAY,
            )
            try:
                order = trading_client.submit_order(sell_req)
            except Exception:
                logger.warning(f"Wash trade block on sell {symbol}; retrying in 1s")
                time.sleep(1)
                order = trading_client.submit_order(sell_req)
            wait_for_fill(trading_client, order.id)

            positions[idx]["quantity"] -= qty_from_this_lot
            total_sold_shares += qty_from_this_lot

            proceeds = Decimal(str(qty_from_this_lot * price))
            if age_days >= LONG_TERM_DAYS:
                total_LTCG_proceeds += proceeds
            else:
                total_STCG_proceeds += proceeds

    cfg["positions"] = [lot for lot in positions if lot.get("quantity", 0) > 0]

    if total_sold_shares == 0:
        email_mgr.send_trigger_alert(
            f"{symbol} reached the sell threshold at price ${price:.2f}, "
            "but no shares were sold because all lots are within the short-term buffer window."
        )
        return

    total_proceeds = (Decimal(str(total_sold_shares * price))).quantize(Decimal("0.01"))
    sell_realloc = cfg.get("sell_reallocate", {"enabled": False})
    if sell_realloc.get("enabled", False):
        for tgt in sell_realloc.get("targets", []):
            tgt_ticker = tgt["ticker"]
            proportion = tgt["proportion"]
            dollars_to_reinvest = (total_proceeds * proportion).quantize(
                Decimal("0.01")
            )
            if dollars_to_reinvest > 0:
                buy_req = MarketOrderRequest(
                    symbol=tgt_ticker,
                    notional=str(dollars_to_reinvest),
                    side=OrderSide.BUY,
                    type=OrderType.MARKET,
                    time_in_force=TimeInForce.DAY,
                )
                try:
                    buy_order = trading_client.submit_order(buy_req)
                    wait_for_fill(trading_client, buy_order.id)
                    email_mgr.send_trigger_alert(
                        f"{tgt_ticker} re-invested ${dollars_to_reinvest} from sale of {symbol}"
                    )
                except Exception as e:
                    logger.error(f"Failed to re-invest into {tgt_ticker}: {e}")

    skipped_shares = shares_to_sell - total_sold_shares
    skipped_proceeds = Decimal(str(skipped_shares * price)).quantize(Decimal("0.01"))
    cfg["last_sell_price"] = price

    email_mgr.send_trigger_alert(
        f"{symbol} sold ${total_proceeds:.2f} "
        f"(LTCG=${total_LTCG_proceeds:.2f}, STCG=${total_STCG_proceeds:.2f}); "
        f"skipped ${skipped_proceeds:.2f} due to ST_near lots"
    )


# ─── Core Trading Logic (one_cycle) ─────────────────────────────────────────
def one_cycle(
    trading_client: TradingClient,
    data_client: StockHistoricalDataClient,
    config: dict,
    email_mgr: EmailManager,
) -> dict:
    for symbol, cfg in config.items():
        cfg.setdefault("triggered_buy_levels", set(cfg.get("triggered_buy_levels", [])))
        cfg.setdefault(
            "triggered_sell_levels", set(cfg.get("triggered_sell_levels", []))
        )
        cfg.setdefault("consider_long_vs_short_term_gains", False)
        cfg.setdefault("initial_lots", cfg.get("initial_lots", []))
        cfg.setdefault("positions", cfg.get("positions", []))
        cfg.setdefault("sell_notional", cfg.get("sell_notional", DEFAULT_NOTIONAL))

        price = get_current_price(data_client, symbol)
        if price is None:
            continue

        # SELL logic (same as before)
        sell_pairs = sorted(
            zip(cfg.get("sell_triggers", []), cfg.get("sell_quantities", [])),
            key=lambda pair: pair[0],
        )
        for trigger, qty_decimal in sell_pairs:
            if price >= trigger and trigger not in cfg["triggered_sell_levels"]:
                if cfg["consider_long_vs_short_term_gains"]:
                    cfg["sell_notional"] = qty_decimal
                    allocate_and_execute_sells(
                        trading_client, symbol, cfg, email_mgr, price
                    )
                    cfg["triggered_sell_levels"].add(trigger)
                else:
                    order_request = MarketOrderRequest(
                        symbol=symbol,
                        notional=str(qty_decimal),
                        side=OrderSide.SELL,
                        type=OrderType.MARKET,
                        time_in_force=TimeInForce.DAY,
                    )
                    try:
                        order = trading_client.submit_order(order_request)
                    except Exception:
                        logger.warning(
                            f"Wash trade block on sell {symbol}@{trigger}; retrying in 1s"
                        )
                        time.sleep(1)
                        order = trading_client.submit_order(order_request)

                    wait_for_fill(trading_client, order.id)
                    cfg["triggered_sell_levels"].add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} sold at {trigger} (notional=${qty_decimal})"
                    )

                    sell_realloc = cfg.get("sell_reallocate", {"enabled": False})
                    if sell_realloc.get("enabled", False):
                        total_sell_usd = qty_decimal
                        for tgt in sell_realloc.get("targets", []):
                            tgt_ticker = tgt["ticker"]
                            proportion = tgt["proportion"]
                            dollars_to_invest = (
                                Decimal(str(total_sell_usd)) * proportion
                            ).quantize(Decimal("0.01"))
                            if dollars_to_invest > 0:
                                buy_req = MarketOrderRequest(
                                    symbol=tgt_ticker,
                                    notional=str(dollars_to_invest),
                                    side=OrderSide.BUY,
                                    type=OrderType.MARKET,
                                    time_in_force=TimeInForce.DAY,
                                )
                                try:
                                    buy_order = trading_client.submit_order(buy_req)
                                    wait_for_fill(trading_client, buy_order.id)
                                    email_mgr.send_trigger_alert(
                                        f"{tgt_ticker} re-invested ${dollars_to_invest} "
                                        f"from sale of {symbol}@{trigger}"
                                    )
                                except Exception as e:
                                    logger.error(
                                        f"Failed to re-invest into {tgt_ticker}: {e}"
                                    )
                break

        # BUY logic (same as before)
        buy_pairs = sorted(
            zip(cfg.get("buy_triggers", []), cfg.get("buy_quantities", [])),
            key=lambda pair: pair[0],
        )
        for trigger, qty_decimal in buy_pairs:
            if price <= trigger and trigger not in cfg["triggered_buy_levels"]:
                buy_fund = cfg.get("buy_funding", {"type": "cash"})

                if buy_fund.get("type") == "cash":
                    order_request = MarketOrderRequest(
                        symbol=symbol,
                        notional=str(qty_decimal),
                        side=OrderSide.BUY,
                        type=OrderType.MARKET,
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
                    cfg["triggered_buy_levels"].add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} bought at {trigger} (notional=${qty_decimal})"
                    )

                else:
                    total_needed = qty_decimal
                    for source in buy_fund.get("sources", []):
                        src_ticker = source["ticker"]
                        proportion = source["proportion"]
                        usd_from_src = (total_needed * proportion).quantize(
                            Decimal("0.01")
                        )
                        if usd_from_src > 0:
                            sell_req = MarketOrderRequest(
                                symbol=src_ticker,
                                notional=str(usd_from_src),
                                side=OrderSide.SELL,
                                type=OrderType.MARKET,
                                time_in_force=TimeInForce.DAY,
                            )
                            try:
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

                    order_request = MarketOrderRequest(
                        symbol=symbol,
                        notional=str(qty_decimal),
                        side=OrderSide.BUY,
                        type=OrderType.MARKET,
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
                    cfg["triggered_buy_levels"].add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} bought at {trigger} (notional=${qty_decimal})"
                    )

                break

    return config


# ─── New: Process Twitter Signals ───────────────────────────────────────────
def process_twitter_signals(
    user_id: str,
    trading_client: TradingClient,
    data_client: StockHistoricalDataClient,
    email_mgr: EmailManager,
):
    """
    1) Query TweetSignals table for this user.
    2) For each signal (tweet_id, category, tickers):
         • If 'buy', place a Market BUY for TWITTER_NOTIONAL on each ticker.
         • If 'sell', place a Market SELL for TWITTER_NOTIONAL on each ticker.
         • Send an email notification for each completed order.
    3) Delete the signal from TweetSignals so it does not re-run.
    """
    try:
        sig_resp = signals_tbl.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("user_id").eq(user_id)
        )
    except ClientError as e:
        logger.error(f"[ERROR] Querying TweetSignals for {user_id}: {e}")
        return

    signals = sig_resp.get("Items", [])
    if not signals:
        return

    logger.info(f"Found {len(signals)} Twitter signals for {user_id}")

    for sig in signals:
        tid = sig["tweet_id"]
        category = sig["category"]  # "buy" or "sell"
        tickers = sig.get("tickers", [])

        for ticker in tickers:
            # Confirm market data
            price = get_current_price(data_client, ticker)
            if price is None:
                logger.warning(f"No price data for {ticker}; skipping Twitter signal.")
                continue

            if category == "buy":
                notional = TWITTER_NOTIONAL
                order_request = MarketOrderRequest(
                    symbol=ticker,
                    notional=str(notional),
                    side=OrderSide.BUY,
                    type=OrderType.MARKET,
                    time_in_force=TimeInForce.DAY,
                )
                try:
                    order = trading_client.submit_order(order_request)
                    wait_for_fill(trading_client, order.id)
                    email_mgr.send_trigger_alert(
                        f"Twitter signal: BUY {ticker} @{tid} — bought ${notional}"
                    )
                except Exception as e:
                    logger.error(f"Failed to execute Twitter buy for {ticker}: {e}")

            elif category == "sell":
                notional = TWITTER_NOTIONAL
                order_request = MarketOrderRequest(
                    symbol=ticker,
                    notional=str(notional),
                    side=OrderSide.SELL,
                    type=OrderType.MARKET,
                    time_in_force=TimeInForce.DAY,
                )
                try:
                    order = trading_client.submit_order(order_request)
                    wait_for_fill(trading_client, order.id)
                    email_mgr.send_trigger_alert(
                        f"Twitter signal: SELL {ticker} @{tid} — sold ${notional}"
                    )
                except Exception as e:
                    logger.error(f"Failed to execute Twitter sell for {ticker}: {e}")

            else:
                # "hold" signals get filtered out upstream, but handle defensively
                continue

        # After processing this signal, delete it
        try:
            signals_tbl.delete_item(Key={"user_id": user_id, "tweet_id": tid})
        except ClientError as e:
            logger.error(f"Failed to delete TweetSignal {tid} for {user_id}: {e}")


def lambda_handler(event, context):
    # 1) If market closed → exit early
    if not is_market_open():
        logger.info("Market closed, exiting.")
        return {"statusCode": 200, "body": "Market closed"}

    # 2) Scan all users
    resp = table.scan()
    users = resp.get("Items", [])

    for u in users:
        user_id = u.get("user_id")
        # (Optional) Filter to a specific user during testing:
        if u.get("user_id") != "David_L":
            continue

        logger.info(f"Processing user {user_id}")
        try:
            # ─── Decrypt Alpaca credentials ─────────────────────────────
            alpaca_api_key, alpaca_api_secret = get_decrypted_alpaca_creds(user_id)

            # ─── Instantiate Alpaca clients ─────────────────────────────
            trading_client = TradingClient(
                alpaca_api_key, alpaca_api_secret, paper=True
            )
            data_client = StockHistoricalDataClient(alpaca_api_key, alpaca_api_secret)

            email_mgr = EmailManager(
                sender_email=SENDER_EMAIL,
                receiver_email=u.get("receiver_email"),
                sender_password=SENDER_PASSWORD,
            )

            # ─── Fetch per-user threshold trading config ────────────────
            trading_cfg = u.get("trading_config", {})

            # ─── Run one cycle of threshold-based trading logic ─────────
            updated_cfg = one_cycle(trading_client, data_client, trading_cfg, email_mgr)

            # ─── Convert per-ticker sets back to lists, then persist ────
            for symbol, cfg in updated_cfg.items():
                if isinstance(cfg.get("triggered_buy_levels"), set):
                    cfg["triggered_buy_levels"] = list(cfg["triggered_buy_levels"])
                if isinstance(cfg.get("triggered_sell_levels"), set):
                    cfg["triggered_sell_levels"] = list(cfg["triggered_sell_levels"])

            table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET trading_config = :cfg",
                ExpressionAttributeValues={":cfg": updated_cfg},
            )

            # ─── Now process any new Twitter signals for this user ──────
            process_twitter_signals(user_id, trading_client, data_client, email_mgr)

        except Exception as e:
            logger.error(f"Error for user {user_id}: {e}", exc_info=True)
            continue

    return {"statusCode": 200, "body": "Processed users and Twitter signals"}
