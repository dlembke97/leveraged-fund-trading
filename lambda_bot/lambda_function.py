import os
import time
import datetime
from zoneinfo import ZoneInfo

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
table = dynamodb.Table(USERS_TABLE)

FERNET_KEY = os.environ["FERNET_KEY"].encode("utf-8")
fernet = Fernet(FERNET_KEY)

SENDER_EMAIL = os.environ["SENDER_EMAIL"]
SENDER_EMAIL_PASSWORD = os.environ["SENDER_EMAIL_PASSWORD"]

# NYSE calendar for market hours/holidays:
NYSE = mcal.get_calendar("NYSE")

# ─── Capital Gains Constants ─────────────────────────────────────────────
LONG_TERM_DAYS = 365
LTCG_BUFFER_DAYS = 30
DEFAULT_NOTIONAL = Decimal("1000")


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
        # minute_bars.data is the actual dict mapping symbol → list[Bar]
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


# ─── FIFO Lot Reconstruction ─────────────────────────────────────────────
def sync_positions(
    trading_client: TradingClient, symbol: str, initial_lots: list[dict]
) -> list[dict]:
    """
    Build a FIFO list of {"quantity": float, "timestamp": ISO-string} for this symbol,
    merging:
      1) “Closed BUY” orders from Alpaca
      2) Any user‐supplied initial lots (shares transferred in) in chronological order

    - `initial_lots`: list of {"quantity": float, "timestamp": ISO-string}
    """
    now = datetime.datetime.now(ZoneInfo("America/New_York"))
    # 1) How many shares do we truly hold?
    try:
        pos = trading_client.get_position(symbol)
        total_qty = float(pos.qty)
    except Exception:
        return []

    # 2) Get all closed BUY orders, sorted by filled_at
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

    # 3) Walk through Alpaca‐buy orders, building lots until we match total_qty
    lots: list[dict] = []
    accumulated = 0.0
    for o in filled:
        if accumulated >= total_qty:
            break
        qty = min(total_qty - accumulated, float(o.filled_qty))
        lots.append({"quantity": qty, "timestamp": o.filled_at})
        accumulated += qty

    # 4) If still below total_qty, drain from initial_lots
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

    # 5) If still below, assume leftover was bought “now”
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
    1) Build a true FIFO list of all open lots (each with quantity & timestamp).
    2) Walk down the FIFO list (oldest → newest). For each lot:
         • If LTCG (age ≥ LONG_TERM_DAYS), sell as much as needed from that lot.
         • Else if ST_far (age < LONG_TERM_DAYS - LTCG_BUFFER_DAYS), sell as much as needed.
         • Else if (LONG_TERM_DAYS - LTCG_BUFFER_DAYS) ≤ age < LONG_TERM_DAYS → ST_near:
             STOP processing further lots (cannot skip over ST_near).
    3) Issue one MARKET‐sell order per eligible lot chunk (so Alpaca’s FIFO will drain exactly that lot).
    4) If total_sold_shares == 0 (i.e. threshold was triggered but every lot was ST_near),
       send an email explaining “no eligible shares to sell.”
    5) Otherwise (some shares sold), perform any “sell_reallocate” logic and send the usual summary.
    """
    now = datetime.datetime.now(ZoneInfo("America/New_York"))

    # 1) Determine how many shares we want to sell (based on notional)
    notional = Decimal(str(cfg.get("sell_notional", DEFAULT_NOTIONAL)))
    shares_to_sell = float(notional / price) if price > 0 else 0.0
    if shares_to_sell <= 0:
        return  # nothing to sell

    # 2) Reconstruct current FIFO list of lots
    positions = cfg.setdefault("positions", [])
    if not positions:
        positions[:] = sync_positions(
            trading_client, symbol, cfg.get("initial_lots", [])
        )

    # Build a sorted list of (idx, quantity_remaining, timestamp) by timestamp ascending
    fifo_list = sorted(
        [(idx, lot["quantity"], lot["timestamp"]) for idx, lot in enumerate(positions)],
        key=lambda entry: datetime.datetime.fromisoformat(entry[2]),
    )

    total_sold_shares = 0.0
    total_LTCG_proceeds = Decimal("0.0")
    total_STCG_proceeds = Decimal("0.0")

    # 3) Walk through each lot in true FIFO order
    for idx, avail_qty, ts_iso in fifo_list:
        if total_sold_shares >= shares_to_sell:
            break  # we've sold enough shares

        buy_ts = datetime.datetime.fromisoformat(ts_iso)
        age_days = (now - buy_ts).days

        # If this lot is ST_near (inside buffer window), stop entirely
        if (age_days >= (LONG_TERM_DAYS - LTCG_BUFFER_DAYS)) and (
            age_days < LONG_TERM_DAYS
        ):
            logger.info(
                f"{symbol}: encountered ST_near lot (age {age_days} days). "
                "Stopping further sells to avoid STCG."
            )
            break

        # If this lot is LTCG (age ≥ LONG_TERM_DAYS) or ST_far (age < LONG_TERM_DAYS - LTCG_BUFFER_DAYS)
        if (age_days >= LONG_TERM_DAYS) or (
            age_days < (LONG_TERM_DAYS - LTCG_BUFFER_DAYS)
        ):
            qty_left_to_sell = shares_to_sell - total_sold_shares
            qty_from_this_lot = min(avail_qty, qty_left_to_sell)

            if qty_from_this_lot <= 0:
                continue

            # Place one MARKET sell order for exactly qty_from_this_lot
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

            # Deduct those shares from this FIFO lot in our local `positions` array
            positions[idx]["quantity"] -= qty_from_this_lot
            total_sold_shares += qty_from_this_lot

            # Classify proceeds as LTCG or STCG
            proceeds = Decimal(str(qty_from_this_lot * price))
            if age_days >= LONG_TERM_DAYS:
                total_LTCG_proceeds += proceeds
            else:
                total_STCG_proceeds += proceeds

    # 4) Clean up any fully-sold lots
    cfg["positions"] = [lot for lot in positions if lot.get("quantity", 0) > 0]

    # 5) If nothing sold but trigger fired, send a “nothing sold” email
    if total_sold_shares == 0:
        email_mgr.send_trigger_alert(
            f"{symbol} reached the sell threshold at price ${price:.2f}, "
            "but no shares were sold because all lots are within the short-term buffer window."
        )
        return

    # 6) If we did sell some shares, perform the “sell_reallocate” logic
    total_proceeds = (Decimal(str(total_sold_shares * price))).quantize(Decimal("0.01"))
    sell_realloc = cfg.get("sell_reallocate", {"enabled": False})
    if sell_realloc.get("enabled", False):
        for tgt in sell_realloc.get("targets", []):
            tgt_ticker = tgt["ticker"]
            proportion = tgt["proportion"]  # Decimal
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

    # 7) Finally, send the usual “sold X shares” summary
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
    """
    Executes one iteration of buy/sell logic for every symbol in `config`.
    Now each `cfg` is the per‐symbol dict, so we set defaults inside this loop.
    """
    for symbol, cfg in config.items():
        # ─── ENSURE per‐ticker defaults ─────────────────────────────────
        cfg.setdefault("triggered_buy_levels", set(cfg.get("triggered_buy_levels", [])))
        cfg.setdefault(
            "triggered_sell_levels", set(cfg.get("triggered_sell_levels", []))
        )
        cfg.setdefault("consider_long_vs_short_term_gains", False)
        cfg.setdefault("initial_lots", cfg.get("initial_lots", []))
        cfg.setdefault("positions", cfg.get("positions", []))
        cfg.setdefault("sell_notional", cfg.get("sell_notional", DEFAULT_NOTIONAL))

        # ─── Fetch current price ────────────────────────────────────────
        price = get_current_price(data_client, symbol)
        if price is None:
            continue

        # ─── SELL logic ────────────────────────────────────────────────
        sell_pairs = sorted(
            zip(cfg.get("sell_triggers", []), cfg.get("sell_quantities", [])),
            key=lambda pair: pair[0],
        )
        for trigger, qty_decimal in sell_pairs:
            if price >= trigger and trigger not in cfg["triggered_sell_levels"]:
                if cfg["consider_long_vs_short_term_gains"]:
                    # Lot‐aware sell
                    cfg["sell_notional"] = qty_decimal
                    allocate_and_execute_sells(
                        trading_client, symbol, cfg, email_mgr, price
                    )
                    cfg["triggered_sell_levels"].add(trigger)
                else:
                    # Original notional‐based sell
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
                break  # only one triggered sell per cycle

        # ─── BUY logic ─────────────────────────────────────────────────
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
            # ─── DECRYPT CREDENTIALS ─────────────────────────────────
            alpaca_api_key, alpaca_api_secret = get_decrypted_alpaca_creds(user_id)

            # ─── INSTANTIATE alpaca-py CLIENTS ───────────────────────
            trading_client = TradingClient(
                alpaca_api_key, alpaca_api_secret, paper=True
            )
            data_client = StockHistoricalDataClient(alpaca_api_key, alpaca_api_secret)

            email_mgr = EmailManager(
                sender_email=SENDER_EMAIL,
                receiver_email=u.get("receiver_email"),
                sender_password=SENDER_EMAIL_PASSWORD,
            )

            # ─── FETCH & PREPARE PER‐USER TRADING CONFIG ─────────────
            trading_cfg = u.get("trading_config", {})

            # ─── RUN ONE CYCLE OF TRADING LOGIC ─────────────────────
            updated_cfg = one_cycle(trading_client, data_client, trading_cfg, email_mgr)

            # ─── CONVERT per‐ticker sets back to lists ───────────────
            for symbol, cfg in updated_cfg.items():
                if isinstance(cfg.get("triggered_buy_levels"), set):
                    cfg["triggered_buy_levels"] = list(cfg["triggered_buy_levels"])
                if isinstance(cfg.get("triggered_sell_levels"), set):
                    cfg["triggered_sell_levels"] = list(cfg["triggered_sell_levels"])

            # ─── PERSIST CHANGES TO DYNAMODB ────────────────────────
            table.update_item(
                Key={"user_id": user_id},
                UpdateExpression="SET trading_config = :cfg",
                ExpressionAttributeValues={":cfg": updated_cfg},
            )

        except Exception as e:
            # Log and continue to next user
            logger.error(f"Error for user {user_id}: {e}", exc_info=True)
            continue

    return {"statusCode": 200, "body": "Processed users"}
