# frontend/streamlit_app.py
import streamlit as st
import requests
import os

st.title("Leveraged Fund Trading Dashboard")

# Use an environment variable to point to the backend API URL.
# When running locally you might use "http://localhost:8000"
api_url = os.getenv("API_URL", "http://localhost:8000")

if st.button("Get API Status"):
    try:
        response = requests.get(f"{api_url}/")
        st.json(response.json())
    except Exception as e:
        st.error(f"Error connecting to API: {e}")

st.write("Enter your credentials:")

# A simple form for users to enter credentials (non-terminal UI)
with st.form(key="credentials_form"):
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    submit_button = st.form_submit_button(label="Submit Credentials")
    
if submit_button:
    # Here you could send the credentials to a secure endpoint or store them as needed.
    st.write(f"Credentials received for user: {username}")
