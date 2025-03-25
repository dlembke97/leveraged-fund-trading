import logging

logging.basicConfig(filename='trading_bot.log', level=logging.INFO)

def log_trade(symbol, action, quantity, price):
    logging.info(f"Trade executed: {action} {quantity} of {symbol} at ${price}")
