import streamlit as st
import sqlite3
from datetime import datetime
import requests
from streamlit.web.server.websocket_headers import _get_websocket_headers
import folium
from streamlit_folium import folium_static

# Set page config as the first Streamlit command
st.set_page_config(layout="wide", page_title="Data Leak Tool", page_icon="🔧")

# Database functions
def get_database_connection():
    return sqlite3.connect('/mount/src/data-leak-detector/search_history.db', check_same_thread=False)

def initialize_database():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS searches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        url TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()
    st.success("Database initialized successfully")

def log_search(ip_address, url):
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO searches (ip_address, url) VALUES (?, ?)', (ip_address, url))
    conn.commit()
    conn.close()
    st.success(f"Search logged: IP={ip_address}, URL={url}")

def get_location(ip_address):
    try:
        url = f'http://ipinfo.io/{ip_address}/json'
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            loc = data.get('loc', '').split(',')
            latitude, longitude = loc if len(loc) == 2 else (None, None)
            return float(latitude), float(longitude)
        else:
            st.warning(f"Failed to fetch location data for IP: {ip_address}. Status code: {response.status_code}")
            return None, None
    except Exception as e:
        st.error(f"Error fetching location data for IP {ip_address}: {str(e)}")
        return None, None

# Initialize database
initialize_database()

# At the beginning of your app
if 'user_ip' not in st.session_state:
    headers = _get_websocket_headers()
    st.session_state.user_ip = headers.get("X-Forwarded-For", "Unknown")

# Main app logic
st.title("Data Leak Tool")

# Display user's IP address and warnings
st.sidebar.warning(f"Your IP address: {st.session_state.user_ip}")
st.sidebar.warning("⚠️ This tool is for educational purposes only.")
st.sidebar.warning("⚠️ Do not use on systems you don't own or have explicit permission to test.")

# Get user's location
user_lat, user_lon = get_location(st.session_state.user_ip)

# Create map
if user_lat and user_lon:
    m = folium.Map(location=[user_lat, user_lon], zoom_start=10, tiles="https://tiles.openfreemap.org/styles/liberty/{z}/{x}/{y}.png", attr="OpenFreeMap")
    folium.Marker([user_lat, user_lon], popup="Your Location").add_to(m)
    st.subheader("Your Location")
    folium_static(m)
else:
    st.warning("Unable to determine your location.")

# User input
url = st.text_input("Enter a URL to scan:")
max_depth = st.slider("Maximum crawl depth:", 1, 5, 1)  # Default set to 1

if st.button("Run Analysis"):
    if url:
        with st.spinner("Analyzing... This may take a few minutes."):
            # Log the search
            log_search(st.session_state.user_ip, url)
            
            # Perform the analysis
            # ... Your existing analysis code here ...
            
            st.success(f"Analysis completed for URL: {url}")
            # ... Display your analysis results here ...
    else:
        st.error("Please enter a URL to scan.")

# Add any additional features or information you want to display

# Footer
st.sidebar.markdown("---")
st.sidebar.text("© 2023 Data Leak Detector")
