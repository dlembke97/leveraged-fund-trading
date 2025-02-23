import alpaca_trade_api as tradeapi

def check_price_and_trade():
    # Fetch the current price for FNGU
    current_price = get_current_price('FNGU')
    
    # Buy logic
    if current_price <= 400:
        buy_stock('FNGU', 200)
    
    # Sell logic
    elif current_price >= 650:
        sell_stock('FNGU', 200)

def get_current_price(symbol):
    # Implement Alpaca API call to fetch the latest price
    # This example assumes minute-level data
    barset = api.get_barset(symbol, 'minute', limit=1)
    return barset[symbol][0].c

def buy_stock(symbol, amount):
    api.submit_order(
        symbol=symbol,
        qty=amount // get_current_price(symbol),  # Convert $200 to quantity
        side='buy',
        type='market',
        time_in_force='gtc'
    )

def sell_stock(symbol, amount):
    api.submit_order(
        symbol=symbol,
        qty=amount // get_current_price(symbol),  # Convert $200 to quantity
        side='sell',
        type='market',
        time_in_force='gtc'
    )
