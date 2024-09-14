import streamlit as st
import sqlite3
import geoip2.database
import pandas as pd
from datetime import datetime

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

st.title('Wall of Sheep')

data = load_data()

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

# Add a map of locations
st.subheader('User Locations')
locations = data[['location']].drop_duplicates()
locations[['lat', 'lon']] = locations['location'].apply(lambda x: pd.Series(geoip_reader.city(x.split(', ')[0]).location.latitude, geoip_reader.city(x.split(', ')[0]).location.longitude))
st.map(locations)
