import streamlit as st
import sqlite3
import geoip2.database
import pandas as pd
from datetime import datetime

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Initialize the GeoIP2 database reader
geoip_reader = geoip2.database.Reader('path/to/GeoLite2-City.mmdb')

def get_location(ip_address):
    try:
        geo_info = geoip_reader.city(ip_address)
        return f"{geo_info.city.name}, {geo_info.country.name}"
    except:
        return "Unknown"

def load_data():
    conn = sqlite3.connect('search_history.db')
    query = '''
        SELECT ip_address, url, timestamp
        FROM searches
        ORDER BY timestamp DESC
        LIMIT 20
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    df['location'] = df['ip_address'].apply(get_location)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

# Main content
st.title('Wall of Sheep 🐑')

data = load_data()

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
    locations = data[['location']].drop_duplicates()
    locations[['lat', 'lon']] = locations['location'].apply(lambda x: pd.Series(geoip_reader.city(x.split(', ')[0]).location.latitude, geoip_reader.city(x.split(', ')[0]).location.longitude))
    st.map(locations)

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
    
    # Most active locations
    location_counts = data['location'].value_counts().head(10)
    st.subheader("Top 10 Active Locations")
    st.bar_chart(location_counts)

# Footer
st.sidebar.markdown("---")
st.sidebar.info("This is a demo application. Data shown is for illustrative purposes only.")
