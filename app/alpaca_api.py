import alpaca_trade_api as tradeapi
import os

def initialize_api():
    ALPACA_PAPER_API_KEY = os.getenv("ALPACA_PAPER_API_KEY")
    ALPACA_PAPER_API_SECRET = os.getenv("ALPACA_PAPER_API_SECRET")
    BASE_URL = "https://paper-api.alpaca.markets"  # Use live URL for live trading
    api = tradeapi.REST(ALPACA_PAPER_API_KEY, ALPACA_PAPER_API_SECRET, BASE_URL)
    return api
