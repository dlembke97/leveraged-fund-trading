# services/trade_logic.py
import time
import datetime
from zoneinfo import ZoneInfo
from alpaca_trade_api.rest import TimeFrame, APIError

from services.common_scripts import setup_logger
import pandas_market_calendars as mcal

logger = setup_logger(__name__)

NYSE = mcal.get_calendar("NYSE")

class TradeLogic:
    def __init__(self, api, trading_config, email_manager):
        self.api = api
        self.trading_config = trading_config
        self.email_manager = email_manager

    @staticmethod
    def is_market_open():
        # Current time in Eastern
        now = datetime.datetime.now(ZoneInfo("America/New_York"))
        today = now.date()

        # Fetch today’s NYSE schedule (empty on holidays & weekends)
        schedule = NYSE.schedule(start_date=today, end_date=today)
        if schedule.empty:
            return False

        # Check against actual open/close times
        open_time  = schedule.at[today, "market_open"].to_pydatetime()
        close_time = schedule.at[today, "market_close"].to_pydatetime()
        return open_time <= now <= close_time

    def wait_for_fill(self, order_id, poll_interval=0.5):
        """Block until the given Alpaca order is filled."""
        while True:
            o = self.api.get_order(order_id)
            if o.status == "filled":
                return
            time.sleep(poll_interval)

    def get_current_price(self, symbol):
        try:
            bars = list(self.api.get_bars(symbol, TimeFrame.Minute, limit=1))
        except Exception:
            logger.warning(f"Minute data not available for {symbol}, trying daily data.")
            bars = []

        if bars and bars[0]:
            return bars[0].c

        try:
            today = datetime.date.today()
            last_trading_day = today
            if today.weekday() == 6:
                last_trading_day -= datetime.timedelta(days=2)
            elif today.weekday() == 5:
                last_trading_day -= datetime.timedelta(days=1)

            bars = list(
                self.api.get_bars(symbol, TimeFrame.Day,
                                  start=last_trading_day.isoformat(), limit=1)
            )
            if bars:
                return bars[0].c
            else:
                logger.info(f"No historical data found for {symbol}.")
                return None
        except Exception as e:
            logger.error(f"Error fetching price for {symbol}: {e}", exc_info=True)
            return None

    def buy_stock(self, symbol, dollar_amount):
        price = self.get_current_price(symbol)
        order = None
        try:
            order = self.api.submit_order(
                symbol=symbol,
                notional=str(dollar_amount),
                side="buy",
                type="market",
                time_in_force="day",
            )
            logger.info(f"Submitted BUY {symbol} for ${dollar_amount} at approx {price}.")
        except APIError as e:
            if "potential wash trade" in str(e).lower():
                logger.warning(f"Wash‑trade block on BUY {symbol}; retrying in 1s.")
                time.sleep(1)
                order = self.api.submit_order(
                    symbol=symbol,
                    notional=str(dollar_amount),
                    side="buy",
                    type="market",
                    time_in_force="day",
                )
            else:
                raise
        # optionally wait for buy fill here if you need certainty:
        # self.wait_for_fill(order.id)
        return order

    def sell_stock(self, symbol, dollar_amount):
        price = self.get_current_price(symbol)
        order = None
        try:
            order = self.api.submit_order(
                symbol=symbol,
                notional=str(dollar_amount),
                side="sell",
                type="market",
                time_in_force="day",
            )
            logger.info(f"Submitted SELL {symbol} for ${dollar_amount} at approx {price}.")
        except APIError as e:
            if "potential wash trade" in str(e).lower():
                logger.warning(f"Wash‑trade block on SELL {symbol}; retrying in 1s.")
                time.sleep(1)
                order = self.api.submit_order(
                    symbol=symbol,
                    notional=str(dollar_amount),
                    side="sell",
                    type="market",
                    time_in_force="day",
                )
            else:
                raise

        # wait for sell to fill before reinvesting
        self.wait_for_fill(order.id)

        # Reinvest proceeds
        self.buy_stock("VTI", dollar_amount * 0.8)
        self.buy_stock("VXUS", dollar_amount * 0.2)

    def check_price_and_trade(self):
        if not self.is_market_open():
            logger.info("Market is closed. Skipping trading cycle.")
            return

        for symbol, config in self.trading_config.items():
            current_price = self.get_current_price(symbol)
            if current_price is None:
                logger.info(f"Skipping {symbol}, could not retrieve price.")
                continue

            # SELL logic
            for trigger in sorted(config["sell_triggers"]):
                if (current_price >= trigger
                        and trigger not in config["triggered_sell_levels"]):
                    self.sell_stock(symbol, 200)
                    config["last_sell_price"] = current_price
                    config["triggered_sell_levels"].add(trigger)

                    message = (
                        f"{symbol}: Sold $200 at {trigger} (price {current_price}) "
                        "→ Reinvested in VTI/VXUS"
                    )
                    logger.info(message)
                    self.email_manager.send_trigger_alert(message)

                    # reset buy triggers
                    config["triggered_buy_levels"].clear()
                    config["last_buy_price"] = None
                    break  # one trade per cycle

            # BUY logic
            for trigger in sorted(config["buy_triggers"], reverse=True):
                if (current_price <= trigger
                        and trigger not in config["triggered_buy_levels"]
                        and (config["last_buy_price"] is None
                             or current_price < config["last_buy_price"])):
                    # free funds
                    self.sell_stock("VTI", 160)
                    self.sell_stock("VXUS", 40)
                    time.sleep(2)  # ensure funds settle

                    # buy target
                    self.buy_stock(symbol, 200)
                    config["last_buy_price"] = current_price
                    config["triggered_buy_levels"].add(trigger)

                    message = (
                        f"{symbol}: Bought $200 at {trigger} (price {current_price}) "
                        "→ Sold VTI/VXUS first"
                    )
                    logger.info(message)
                    self.email_manager.send_trigger_alert(message)
                    break
