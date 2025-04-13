import time
from alpaca_trade_api.rest import TimeFrame
import datetime
from datetime import time  # Note: If you don't need this, you can remove it.
from zoneinfo import ZoneInfo

from services.common_scripts import setup_logger

# Create a logger for this module
logger = setup_logger(__name__)


class TradeLogic:
    def __init__(self, api, trading_config, email_manager):
        self.api = api
        self.trading_config = trading_config
        self.email_manager = email_manager

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
            if today.weekday() == 6:  # Sunday
                last_trading_day = today - datetime.timedelta(days=2)
            elif today.weekday() == 5:  # Saturday
                last_trading_day = today - datetime.timedelta(days=1)

            bars = list(
                self.api.get_bars(symbol, TimeFrame.Day, start=last_trading_day.isoformat(), limit=1)
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
        self.api.submit_order(
            symbol=symbol,
            notional=str(dollar_amount),
            side='buy',
            type='market',
            time_in_force='day'
        )
        logger.info(f"Bought ${dollar_amount} of {symbol} at {price}.")

    def sell_stock(self, symbol, dollar_amount):
        price = self.get_current_price(symbol)
        self.api.submit_order(
            symbol=symbol,
            notional=str(dollar_amount),
            side='sell',
            type='market',
            time_in_force='day'
        )
        logger.info(f"Sold ${dollar_amount} of {symbol} at {price}.")

        # Reinvest proceeds (80% VTI, 20% VXUS)
        reinvest_amount = dollar_amount
        self.buy_stock("VTI", reinvest_amount * 0.8)
        self.buy_stock("VXUS", reinvest_amount * 0.2)

    def check_price_and_trade(self):
        if not self.is_market_open():
            logger.info("Market is closed. Skipping trading cycle.")
            return
        for symbol, config in self.trading_config.items():
            current_price = self.get_current_price(symbol)
            if current_price is None:
                logger.info(f"Skipping {symbol}, could not retrieve price.")
                continue

            # Sell logic: Sell FNGA/TQQQ and reinvest in VTI/VXUS
            for trigger in sorted(config["sell_triggers"]):
                if current_price >= trigger and trigger not in config["triggered_sell_levels"]:
                    self.sell_stock(symbol, 200)
                    config["last_sell_price"] = current_price
                    config["triggered_sell_levels"].add(trigger)

                    # Reinvestment step (if needed)
                    self.buy_stock("VTI", 200 * 0.8)
                    self.buy_stock("VXUS", 200 * 0.2)

                    message = f"{symbol}: Sell $200 at {trigger} with current price {current_price} → Reinvested in VTI/VXUS"
                    logger.info(message)
                    self.email_manager.send_trigger_alert(message)

                    config["triggered_buy_levels"].clear()
                    config["last_buy_price"] = None
                    config["triggered_sell_levels"].clear()
                    break

            # Buy logic: Check if funds need to be freed from VTI/VXUS before buying FNGA/TQQQ
            for trigger in sorted(config["buy_triggers"], reverse=True):
                if current_price <= trigger and trigger not in config["triggered_buy_levels"]:
                    if config["last_buy_price"] is None or current_price < config["last_buy_price"]:
                        self.sell_stock("VTI", 160)
                        self.sell_stock("VXUS", 40)
                        time.sleep(2)  # Allow time for funds to settle
                        self.buy_stock(symbol, 200)
                        config["last_buy_price"] = current_price
                        config["triggered_buy_levels"].add(trigger)
                        message = f"{symbol}: Buy $200 at {trigger} with current price {current_price} → Sold VTI/VXUS first if needed"
                        logger.info(message)
                        self.email_manager.send_trigger_alert(message)
                        break
