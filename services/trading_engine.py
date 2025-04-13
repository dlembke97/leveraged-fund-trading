import time
from services.alpaca_api import AlpacaAPI
from services.trade_logic import TradeLogic
from services.common_scripts import EmailManager, setup_logger

# Set up a logger for this module
logger = setup_logger(__name__)

class TradingEngine:
    def __init__(self, user_id, alpaca_api_key, alpaca_api_secret, trading_config, email_config):
        self.user_id = user_id
        self.alpaca_api_key = alpaca_api_key
        self.alpaca_api_secret = alpaca_api_secret
        self.trading_config = trading_config
        self.email_config = email_config
        self.running = False

        # Initialize Alpaca API client for this user
        self.api = AlpacaAPI.initialize_api(self.alpaca_api_key, self.alpaca_api_secret)
        # Initialize email manager
        self.email_manager = EmailManager(
            sender_email=email_config["sender_email"],
            receiver_email=email_config["receiver_email"],
            sender_password=email_config["sender_email_password"]
        )
        # Initialize trading logic with the user’s configuration
        self.trade_logic = TradeLogic(self.api, self.trading_config, self.email_manager)

    def run(self):
        self.running = True
        while self.running:
            try:
                self.trade_logic.check_price_and_trade()
            except Exception as e:
                logger.error(f"[{self.user_id}] Error during trading cycle: {e}", exc_info=True)
            time.sleep(60)  # Trading cycle interval

    def stop(self):
        self.running = False

# Global dictionary to track running engines per user
engines = {}
