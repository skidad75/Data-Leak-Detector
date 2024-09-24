import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Database functions
def get_database_connection():
    return sqlite3.connect('search_history.db', check_same_thread=False)

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

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

def get_location(ip_address):
    # Placeholder function for location lookup
    return "Location data not available"

# Main content
st.title("Wall of Sheep 🐑")
data = load_search_data()

st.write("Debug: Data loaded from database")
st.write(f"Debug: Number of rows in data: {len(data)}")

if data.empty:
    st.info("No search data available. Run some searches from the Data Leak Tool page to populate this table.")
else:
    st.success("Search data found!")
    st.write(data)

    data['location'] = data['ip_address'].apply(get_location)
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
        st.info("Map view is currently not available without GeoIP data.")

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

# Footer
st.sidebar.markdown("---")
