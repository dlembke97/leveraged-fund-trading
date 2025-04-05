# services/alpaca_api.py
import alpaca_trade_api as tradeapi

class AlpacaAPI:
    @staticmethod
    def initialize_api(api_key, api_secret):
        BASE_URL = "https://paper-api.alpaca.markets"  # Use live URL for live trading
        api = tradeapi.REST(api_key, api_secret, BASE_URL)
        return api
