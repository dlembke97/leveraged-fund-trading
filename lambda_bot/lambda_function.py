import os
import time
import datetime
from zoneinfo import ZoneInfo

import boto3
from decimal import Decimal
from cryptography.fernet import Fernet
from botocore.exceptions import ClientError
from alpaca_trade_api.rest import REST, TimeFrame, APIError
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
# You can adjust these as needed or even override them from cfg if you like.
LONG_TERM_DAYS = 365
LTCG_BUFFER_DAYS = 30  # e.g. any lot within 30 days of turning LTCG is “near buffer”

DEFAULT_NOTIONAL = Decimal("1000")  # fallback notional if cfg lacks sell_notional


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
        logger.warning(
            f"Minute data not available for {symbol}, falling back to daily."
        )
    today = datetime.date.today()
    bars = list(api.get_bars(symbol, TimeFrame.Day, start=today.isoformat(), limit=1))
    if bars:
        return bars[0].c
    return None


# ─── FIFO Lot Reconstruction ─────────────────────────────────────────────
def sync_positions(api, symbol):
    """
    Build a FIFO list of {"quantity": float, "timestamp": ISO-string} for this symbol
    by looking at your current Alpaca position + history of filled buy orders.
    """
    now = datetime.datetime.now(ZoneInfo("America/New_York"))
    try:
        pos = api.get_position(symbol)
        total_qty = float(pos.qty)
    except Exception:
        return []  # no current position

    # 1) Pull all closed BUY orders
    orders = api.get_orders(
        status="closed",
        side="buy",
        symbol=symbol,
        limit=500,  # tweak if >500 buys historically
        after="2000-01-01",  # arbitrary old date
        until=now.isoformat(),
    )
    # Keep only those with filled_qty > 0, sorted by fill time
    filled = [o for o in orders if float(o.filled_qty) > 0]
    filled.sort(key=lambda o: o.filled_at)

    # 2) Walk through buys, building up FIFO lots until we match total_qty
    lots = []
    accumulated = 0.0
    for o in filled:
        if accumulated >= total_qty:
            break
        qty = min(total_qty - accumulated, float(o.filled_qty))
        lots.append(
            {"quantity": qty, "timestamp": o.filled_at}  # ISO string from Alpaca
        )
        accumulated += qty

    return lots


# ─── Sell Allocation Honoring LTCG & STCG Buffer ─────────────────────────────
def allocate_and_execute_sells(api, symbol, cfg, email_mgr, price):
    """
    1) Build a true FIFO list of all open lots (each with quantity & timestamp).
    2) Walk down the FIFO list (oldest→newest). For each lot:
         • If LTCG (age >= LONG_TERM_DAYS), sell as much as needed.
         • Else if ST_far (age < LONG_TERM_DAYS - LTCG_BUFFER_DAYS), sell as much as needed.
         • Else (age ≥ LONG_TERM_DAYS - LTCG_BUFFER_DAYS and < LONG_TERM_DAYS) → ST_near:
             STOP processing further lots (cannot skip over ST_near).
    3) Issue one MARKET‐sell order per eligible lot chunk (so Alpaca’s FIFO will drain exactly that lot).
    4) If total_sold_shares == 0 (i.e. threshold was triggered but every lot was ST_near), send an email explaining “no eligible shares to sell.”
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
            api, symbol, initial_lots=cfg.get("initial_lots", [])
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

        # If this lot is ST_near (inside buffer window), we cannot skip it.
        if (
            age_days >= (LONG_TERM_DAYS - LTCG_BUFFER_DAYS)
            and age_days < LONG_TERM_DAYS
        ):
            # We hit a near-term lot, so stop entirely
            logger.info(
                f"{symbol}: encountered ST_near lot (age {age_days} days). "
                "Stopping further sells to avoid STCG."
            )
            break

        # Else if this lot is LTCG (age >= LONG_TERM_DAYS), or ST_far (age < LONG_TERM_DAYS - LTCG_BUFFER_DAYS)
        if age_days >= LONG_TERM_DAYS or age_days < (LONG_TERM_DAYS - LTCG_BUFFER_DAYS):
            qty_left_to_sell = shares_to_sell - total_sold_shares
            qty_from_this_lot = min(avail_qty, qty_left_to_sell)

            if qty_from_this_lot <= 0:
                continue

            # Place one MARKET sell order for exactly qty_from_this_lot
            try:
                order = api.submit_order(
                    symbol=symbol,
                    qty=str(qty_from_this_lot),
                    side="sell",
                    type="market",
                    time_in_force="day",
                )
            except APIError:
                logger.warning(f"Wash trade block on sell {symbol}; retrying in 1s")
                time.sleep(1)
                order = api.submit_order(
                    symbol=symbol,
                    qty=str(qty_from_this_lot),
                    side="sell",
                    type="market",
                    time_in_force="day",
                )
            wait_for_fill(api, order.id)

            # Deduct those shares from this FIFO lot in our local `positions` array
            positions[idx]["quantity"] -= qty_from_this_lot
            total_sold_shares += qty_from_this_lot

            # Classify proceeds as LTCG or STCG
            proceeds = Decimal(str(qty_from_this_lot * price))
            if age_days >= LONG_TERM_DAYS:
                total_LTCG_proceeds += proceeds
            else:
                total_STCG_proceeds += proceeds

    # 4) Clean up any fully‐sold lots
    new_positions = [lot for lot in positions if lot.get("quantity", 0) > 0]
    cfg["positions"] = new_positions

    # 5) If nothing was sold, but a sell‐trigger fired, send a “nothing sold” email
    if total_sold_shares == 0:
        # This covers the case where the trigger was hit but all lots were ST_near
        email_mgr.send_trigger_alert(
            f"{symbol} reached the sell threshold at price ${price:.2f}, "
            "but no shares were sold because all lots are within the short-term buffer window."
        )
        return

    # 6) If we did sell some shares, do the existing “sell_reallocate” logic and summary email
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
                try:
                    buy_order = api.submit_order(
                        symbol=tgt_ticker,
                        notional=str(dollars_to_reinvest),
                        side="buy",
                        type="market",
                        time_in_force="day",
                    )
                    wait_for_fill(api, buy_order.id)
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
def one_cycle(api, config: dict, email_mgr: EmailManager):
    """
    Executes one iteration of buy/sell logic for every symbol in `config`.
    - If consider_long_vs_short_term_gains = False: use your original SELL logic.
    - If True: use allocate_and_execute_sells(...) instead.
    Returns the updated `config` dictionary (with any changes to triggers, positions, etc.).
    """
    for symbol, cfg in config.items():
        price = get_current_price(api, symbol)
        if price is None:
            continue

        # ─── SELL logic ─────────────────────────────────────
        if cfg.get("consider_long_vs_short_term_gains", False):
            # 1) Ensure cfg["positions"] is populated from Alpaca if empty
            if not cfg.get("positions"):
                cfg["positions"] = sync_positions(api, symbol)

            # 2) If the price has crossed any configured sell trigger, then run the LOT-aware sell
            for trigger, qty_decimal in sorted(
                zip(cfg.get("sell_triggers", []), cfg.get("sell_quantities", [])),
                key=lambda pair: pair[0],
            ):
                if price >= trigger and trigger not in cfg.get(
                    "triggered_sell_levels", set()
                ):
                    # Do a lot-aware sell for exactly `qty_decimal` dollars
                    allocate_and_execute_sells(api, symbol, cfg, email_mgr, price)

                    # Mark the *trigger* as fired (so we don’t repeat this exact trigger next cycle)
                    cfg.setdefault("triggered_sell_levels", set()).add(trigger)
                    break  # only handle one sell‐trigger per cycle
        else:
            # ── Original “sell by dollar notional” logic, unchanged ──
            sell_pairs = sorted(
                zip(cfg.get("sell_triggers", []), cfg.get("sell_quantities", [])),
                key=lambda pair: pair[0],
            )
            for trigger, qty_decimal in sell_pairs:
                if price >= trigger and trigger not in cfg.get(
                    "triggered_sell_levels", set()
                ):
                    try:
                        order = api.submit_order(
                            symbol=symbol,
                            notional=str(qty_decimal),
                            side="sell",
                            type="market",
                            time_in_force="day",
                        )
                    except APIError:
                        logger.warning(
                            f"Wash trade block on sell {symbol}@{trigger}; retrying in 1s"
                        )
                        time.sleep(1)
                        order = api.submit_order(
                            symbol=symbol,
                            notional=str(qty_decimal),
                            side="sell",
                            type="market",
                            time_in_force="day",
                        )

                    wait_for_fill(api, order.id)
                    cfg.setdefault("triggered_sell_levels", set()).add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} sold at {trigger} (notional=${qty_decimal})"
                    )

                    # Re-allocate proceeds if requested
                    sell_realloc = cfg.get("sell_reallocate", {"enabled": False})
                    if sell_realloc.get("enabled", False):
                        total_sell_usd = qty_decimal
                        for tgt in sell_realloc.get("targets", []):
                            tgt_ticker = tgt["ticker"]
                            proportion = tgt["proportion"]  # Decimal
                            dollars_to_invest = (
                                Decimal(str(total_sell_usd)) * proportion
                            ).quantize(Decimal("0.01"))
                            if dollars_to_invest > 0:
                                try:
                                    buy_order = api.submit_order(
                                        symbol=tgt_ticker,
                                        notional=str(dollars_to_invest),
                                        side="buy",
                                        type="market",
                                        time_in_force="day",
                                    )
                                    wait_for_fill(api, buy_order.id)
                                    email_mgr.send_trigger_alert(
                                        f"{tgt_ticker} re-invested ${dollars_to_invest} "
                                        f"from sale of {symbol}@{trigger}"
                                    )
                                except Exception as e:
                                    logger.error(
                                        f"Failed to re-invest into {tgt_ticker}: {e}"
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
                    try:
                        order = api.submit_order(
                            symbol=symbol,
                            notional=str(qty_decimal),
                            side="buy",
                            type="market",
                            time_in_force="day",
                        )
                    except APIError:
                        logger.warning(
                            f"Wash trade block on buy {symbol}@{trigger}; retrying in 1s"
                        )
                        time.sleep(1)
                        order = api.submit_order(
                            symbol=symbol,
                            notional=str(qty_decimal),
                            side="buy",
                            type="market",
                            time_in_force="day",
                        )
                    wait_for_fill(api, order.id)
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
                                sell_order = api.submit_order(
                                    symbol=src_ticker,
                                    notional=str(usd_from_src),
                                    side="sell",
                                    type="market",
                                    time_in_force="day",
                                )
                                wait_for_fill(api, sell_order.id)
                                email_mgr.send_trigger_alert(
                                    f"{src_ticker} sold for ${usd_from_src} "
                                    f"to fund buy of {symbol}@{trigger}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to sell {src_ticker} for funding: {e}"
                                )

                    # 2) Now place the intended buy
                    try:
                        order = api.submit_order(
                            symbol=symbol,
                            notional=str(qty_decimal),
                            side="buy",
                            type="market",
                            time_in_force="day",
                        )
                    except APIError:
                        logger.warning(
                            f"Wash trade block on buy {symbol}@{trigger}; retrying in 1s"
                        )
                        time.sleep(1)
                        order = api.submit_order(
                            symbol=symbol,
                            notional=str(qty_decimal),
                            side="buy",
                            type="market",
                            time_in_force="day",
                        )
                    wait_for_fill(api, order.id)
                    cfg.setdefault("triggered_buy_levels", set()).add(trigger)
                    email_mgr.send_trigger_alert(
                        f"{symbol} bought at {trigger} (notional=${qty_decimal})"
                    )

                break  # only one triggered buy per cycle

    return config


# ─── Lambda Entry Point ─────────────────────────────────────────────
def lambda_handler(event, context):
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

        api = REST(
            alpaca_api_key,
            alpaca_api_secret,
            base_url="https://paper-api.alpaca.markets",
        )

        email_mgr = EmailManager(
            sender_email=SENDER_EMAIL,
            receiver_email=u.get("receiver_email"),
            sender_password=SENDER_EMAIL_PASSWORD,
        )

        trading_cfg = u.get("trading_config", {})
        # Ensure our sets are real Python sets
        trading_cfg.setdefault(
            "triggered_buy_levels", set(trading_cfg.get("triggered_buy_levels", []))
        )
        trading_cfg.setdefault(
            "triggered_sell_levels", set(trading_cfg.get("triggered_sell_levels", []))
        )
        trading_cfg.setdefault(
            "consider_long_vs_short_term_gains", False
        )  # default = off

        try:
            updated_cfg = one_cycle(api, trading_cfg, email_mgr)

            # Convert sets ➔ lists for DynamoDB storage
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
