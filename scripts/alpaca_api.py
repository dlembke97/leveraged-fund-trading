import alpaca_trade_api as tradeapi
import os

# Initialize the Alpaca API
def initialize_api():
    # Fetch the API key and secret from environment variables
    ALPACA_PAPER_API_KEY = os.getenv("ALPACA_PAPER_API_KEY")
    ALPACA_PAPER_API_SECRET = os.getenv("ALPACA_PAPER_API_SECRET")

    BASE_URL = "https://paper-api.alpaca.markets"  # Change to live URL for live trading

    # Create the Alpaca API client
    api = tradeapi.REST(ALPACA_PAPER_API_KEY, ALPACA_PAPER_API_SECRET, BASE_URL)
    return api
