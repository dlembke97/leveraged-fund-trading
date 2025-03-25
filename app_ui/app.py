import streamlit as st
import os

def user_input():
    st.title('Set Your Credentials')

    alpaca_api_key = st.text_input('Alpaca API Key')
    alpaca_api_secret = st.text_input('Alpaca API Secret')
    sender_email = st.text_input('Sender Email')
    receiver_email = st.text_input('Receiver Email')
    sender_email_password = st.text_input('Sender Email Password', type="password")

    if st.button('Save Credentials'):
        os.environ['ALPACA_PAPER_API_KEY'] = alpaca_api_key
        os.environ['ALPACA_PAPER_API_SECRET'] = alpaca_api_secret
        os.environ['SENDER_EMAIL'] = sender_email
        os.environ['RECEIVER_EMAIL'] = receiver_email
        os.environ['SENDER_EMAIL_PASSWORD'] = sender_email_password

        st.success('Credentials saved successfully!')

if __name__ == "__main__":
    user_input()
