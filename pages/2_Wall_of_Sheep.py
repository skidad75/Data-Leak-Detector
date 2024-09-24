import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import ipinfo
import os

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Initialize ipinfo with your access token
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "your_default_token_here")
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

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

@st.cache_data(ttl=5)  # Cache for 5 seconds
def load_search_data():
    initialize_database()
    conn = get_database_connection()
    query = '''
        SELECT ip_address, url, timestamp
        FROM searches
        ORDER BY timestamp DESC
        LIMIT 20
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

@st.cache_data(ttl=3600)  # Cache for 1 hour
def get_location(ip_address):
    try:
        details = ipinfo_handler.getDetails(ip_address)
        return details.city, details.country, details.latitude, details.longitude
    except:
        return "Unknown", "Unknown", None, None

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

# Main content
st.title("Wall of Sheep 🐑")
data = load_search_data()

if data.empty:
    st.info("No search data available. Run some searches from the Data Leak Tool page to populate this table.")
else:
    # Apply get_location to each IP address
    locations = data['ip_address'].apply(get_location)
    data['city'], data['country'], data['latitude'], data['longitude'] = zip(*locations)
    data['location'] = data['city'] + ", " + data['country']
    data['timestamp'] = pd.to_datetime(data['timestamp'])

    if page == "Recent Searches":
        st.header("Recent Searches")
        st.dataframe(
            data[['ip_address', 'location', 'url', 'timestamp']],
            column_config={
                "ip_address": "IP Address",
                "location": "Location",
                "url": "URL Searched",
                "timestamp": st.column_config.DatetimeColumn("Timestamp", format="DD/MM/YYYY, HH:mm:ss"),
            },
            hide_index=True,
        )

    elif page == "Map View":
        st.header("User Locations")
        # Filter out rows with missing lat/long
        map_data = data[data['latitude'].notnull() & data['longitude'].notnull()]
        if not map_data.empty:
            st.map(map_data[['latitude', 'longitude']])
        else:
            st.info("No valid location data available for mapping.")

    elif page == "Statistics":
        st.header("Search Statistics")
        
        # Most searched domains
        domains = data['url'].apply(lambda x: x.split('//')[1].split('/')[0])
        domain_counts = domains.value_counts().head(10)
        st.subheader("Top 10 Searched Domains")
        st.bar_chart(domain_counts)
        
        # Searches per hour
        data['hour'] = data['timestamp'].dt.hour
        hourly_searches = data['hour'].value_counts().sort_index()
        st.subheader("Searches per Hour")
        st.line_chart(hourly_searches)
        
        # Top countries
        country_counts = data['country'].value_counts().head(10)
        st.subheader("Top 10 Countries")
        st.bar_chart(country_counts)

# Footer
st.sidebar.markdown("---")
