import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import json
import requests
import re

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Database functions
def get_database_connection():
    return sqlite3.connect('/mount/src/data-leak-detector/search_history.db', check_same_thread=False)

def initialize_database():
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS searches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
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
        url = f'http://ipinfo.io/{ip_address}/json'
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', 'Unknown')
            region = data.get('region', 'Unknown')
            country = data.get('country', 'Unknown')
            loc = data.get('loc', '').split(',')
            latitude, longitude = loc if len(loc) == 2 else (None, None)
            return city, region, country, latitude, longitude
        else:
            return "Unknown", "Unknown", "Unknown", None, None
    except Exception as e:
        st.error(f"Error fetching location data: {str(e)}")
        return "Unknown", "Unknown", "Unknown", None, None

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
    data['city'], data['region'], data['country'], data['latitude'], data['longitude'] = zip(*locations)
    data['location'] = data['city'] + ", " + data['region'] + ", " + data['country']
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
        domains = data['url'].apply(lambda x: re.findall(r"(?:https?://)?(?:www\.)?([^/]+)", x)[0] if re.findall(r"(?:https?://)?(?:www\.)?([^/]+)", x) else x)
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
