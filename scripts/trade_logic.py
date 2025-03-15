import time
from alpaca_api import initialize_api
from alpaca_trade_api.rest import TimeFrame
import datetime
from common_scripts import EmailManager
import os

api = initialize_api()

# Configure email manager credentials
EMAIL_SENDER = os.getenv('SENDER_EMAIL')
EMAIL_RECEIVER = os.getenv('RECEIVER_EMAIL')
EMAIL_PASSWORD_SENDER = os.getenv('SENDER_EMAIL_PASSWORD')

email_manager = EmailManager(EMAIL_SENDER, EMAIL_RECEIVER, EMAIL_PASSWORD_SENDER)

# Store triggers, cooldowns, and state in a dictionary.
trading_config = {
    "FNGA": {
        "buy_triggers": [450, 300, 250],
        "sell_triggers": [650, 700, 750],
        "last_buy_price": None,
        "last_sell_price": None,
        "triggered_buy_levels": set(),
        "triggered_sell_levels": set(),
    },
    "TQQQ": {
        "buy_triggers": [50, 40, 30],
        "sell_triggers": [85, 90, 95],
        "last_buy_price": None,
        "last_sell_price": None,
        "triggered_buy_levels": set(),
        "triggered_sell_levels": set(),
    }
}

def check_price_and_trade():
    """Check price levels and execute trades based on defined triggers."""
    for symbol, config in trading_config.items():
        current_price = get_current_price(symbol)
        if current_price is None:
            print(f"Skipping {symbol}, could not retrieve price.")
            continue

        # Buy logic
        for trigger in sorted(config["buy_triggers"], reverse=True):
            if current_price <= trigger and trigger not in config["triggered_buy_levels"]:
                if config["last_buy_price"] is None or current_price < config["last_buy_price"]:
                    buy_stock(symbol, 200)
                    config["last_buy_price"] = current_price
                    config["triggered_buy_levels"].add(trigger)
                    message = f"{symbol}: Buy ${200} at {trigger} with current price {current_price}"
                    print(message)
                    email_manager.send_trigger_alert(message)
                    break  # Only one trade per cycle

        # Sell logic
        for trigger in sorted(config["sell_triggers"]):
            if current_price >= trigger and trigger not in config["triggered_sell_levels"]:
                sell_stock(symbol, 200)
                config["last_sell_price"] = current_price
                config["triggered_sell_levels"].add(trigger)
                message = f"{symbol}: Sell ${200} at {trigger} with current price {current_price}"
                print(message)
                email_manager.send_trigger_alert(message)
                
                # After a sell, reset buy triggers for the next cycle
                config["triggered_buy_levels"].clear()
                config["last_buy_price"] = None
                config["triggered_sell_levels"].clear()
                break  # Only one trade per cycle


def get_current_price(symbol):
    """Fetch the latest available price, falling back to the last closing price if needed."""
    try:
        # Try to get the most recent minute bar
        bars = list(api.get_bars(symbol, TimeFrame.Minute, limit=1))
    except Exception:
        print(f"Minute data not available for {symbol}, trying daily data.")
        bars = []
    
    # If minute data is present and valid, use it.
    # Here, we also check that the first element is truthy (i.e. not an empty list).
    if bars and bars[0]:
        return bars[0].c  # Latest available price

    # Fallback: Determine last trading day (Friday if today is Sat/Sun)
    try:
        today = datetime.date.today()
        last_trading_day = today
        if today.weekday() == 6:  # Sunday
            last_trading_day = today - datetime.timedelta(days=2)  # Go back to Friday
        elif today.weekday() == 5:  # Saturday
            last_trading_day = today - datetime.timedelta(days=1)  # Go back to Friday

        # Fetch the last daily bar starting from the determined last trading day
        bars = list(api.get_bars(symbol, TimeFrame.Day, start=last_trading_day.isoformat(), limit=1))

        if bars:
            return bars[0].c  # Last closing price
        else:
            print(f"No historical data found for {symbol}.")
            return None
    except Exception as e:
        print(f"Error fetching price for {symbol}: {e}")
        return None


def buy_stock(symbol, dollar_amount):
    """Execute a market buy order."""
    price = get_current_price(symbol)

    api.submit_order(
        symbol=symbol,
        notional=str(dollar_amount),  # Alpaca expects a string representing the dollar amount.
        side='buy',
        type='market',
        time_in_force='day'
    )
    print(f"Bought ${dollar_amount} of {symbol} at {price}.")

def sell_stock(symbol, dollar_amount):
    """Execute a market sell order and reinvest in VTI/VXUS."""
    price = get_current_price(symbol)

    api.submit_order(
        symbol=symbol,
        notional=str(dollar_amount),
        side='sell',
        type='market',
        time_in_force='day'
    )
    print(f"Sold ${dollar_amount} of {symbol} at {price}.")

    # Reinvest sale proceeds (80% VTI, 20% VXUS)
    reinvest_amount = dollar_amount
    buy_stock("VTI", reinvest_amount * 0.8)
    buy_stock("VXUS", reinvest_amount * 0.2)
