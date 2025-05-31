# AWS Lambda Trading Bot

Trading logic can be configured at https://leveraged-fund-trading-7iprpeglueepf7impssuqb.streamlit.app/. If you are not a registered user, you will need to reach out to dlembke97@gmail.com to have become registered. 

## Key notes
* Current trading logic is strictly threshold based. You are in control of what/how much you buy and sell. This app simply takes the rules you give it and runs them live so you don't have to constantly monitor your portfolio
* An alpaca account is required to run the trading bot on your portfolio. You will need to input your alpaca api key and api secret on the streamlit trading app. These fields are encrypted and saved to your user in a secure dynamodb table.Eventually these should instead be stored using AWS Secrets for better security, but thats a paid service and I'm cheap so I'm sticking with dynamodb for now.
* If you enter your email in the streamlit trading app when your user is registered, you will be emailed when any trades are triggered.
* Start with paper trading credentials to make sure your configuration feels right for you before live trading.

## Alpaca set up guide
1. Create an account at https://alpaca.markets/
2. Switch to Paper trading (The upper left of the window should say "Paper")
3. Your account should automatically have (fake) funds in paper trading. Purchase some tickers that you envision using this tool with
4. Generate your API key and Secret
    a. Click the settings gear (bottom left) and click "Profile"
    b. Click "Manage Accounts"
    c. Click "Generate New Keys"
    d. In the app, enter the resulting key and secret where prompted
       (you will need to be registered to the app first and logged in)