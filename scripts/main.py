from scripts.trade_logic import check_price_and_trade

def run_bot():
    while True:
        try:
            check_price_and_trade()
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(60)  # Adjust sleep time as needed

if __name__ == "__main__":
    run_bot()
