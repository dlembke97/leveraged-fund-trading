from dotenv import load_dotenv
import os
import alpaca_trade_api as tradeapi

# Load environment variables from .env file
load_dotenv()


ALPACA_PAPER_API_KEY = os.getenv('ALPACA_PAPER_API_KEY')
ALPACA_PAPER_API_SECRET = os.getenv('ALPACA_PAPER_API_SECRET')

api = tradeapi.REST(ALPACA_PAPER_API_KEY, ALPACA_PAPER_API_SECRET, base_url='https://paper-api.alpaca.markets')
