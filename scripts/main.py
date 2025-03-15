import time
from trade_logic import check_price_and_trade
from dotenv import load_dotenv

# Load environment variables at the start of the program
load_dotenv()

def run_bot():
    """Continuously runs the trading bot with error handling."""
    while True:
        try:
            check_price_and_trade()
        except Exception as e:
            print(f"Error: {e}")

        time.sleep(60)  # Runs every 60 seconds (adjust if needed)

if __name__ == "__main__":
    run_bot()
