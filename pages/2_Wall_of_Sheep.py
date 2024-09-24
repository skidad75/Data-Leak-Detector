import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import random

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

def get_location(ip_address):
    # Placeholder function for location lookup
    # In a real scenario, you might want to implement a proper IP geolocation service
    return "Location data not available"

def load_data():
    try:
        conn = sqlite3.connect('search_history.db')
        query = '''
            SELECT ip_address, url, timestamp
            FROM searches
            ORDER BY timestamp DESC
            LIMIT 20
        '''
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            st.warning("No search data available yet.")
            return pd.DataFrame(columns=["ip_address", "url", "timestamp"])
        
    except sqlite3.OperationalError:
        st.error("Error: The 'searches' table doesn't exist. Please run a search from the Data Leak Tool page first.")
        return pd.DataFrame(columns=["ip_address", "url", "timestamp"])
    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")
        return pd.DataFrame(columns=["ip_address", "url", "timestamp"])
    
    df['location'] = df['ip_address'].apply(get_location)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

# Main content
st.title("Wall of Sheep 🐑")
data = load_data()

if page == "Recent Searches":
    st.header("Recent Searches")
    if not data.empty:
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
    else:
        st.info("No search data available. Run some searches from the Data Leak Tool page to populate this table.")

elif page == "Map View":
    st.header("User Locations")
    st.info("Map view is currently not available without GeoIP data.")

elif page == "Statistics":
    st.header("Search Statistics")
    
    if not data.empty:
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
    else:
        st.info("No search data available for statistics. Run some searches from the Data Leak Tool page first.")

# Footer
st.sidebar.markdown("---")
