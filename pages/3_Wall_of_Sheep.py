import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import requests
import re
import ipaddress
import pydeck as pdk
import numpy as np

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Database functions
def get_database_connection():
    try:
        return sqlite3.connect('/mount/src/data-leak-detector/search_history.db', check_same_thread=False)
    except sqlite3.Error as e:
        st.error(f"Error connecting to database: {e}")
        return None

def initialize_database():
    conn = get_database_connection()
    if conn is not None:
        try:
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
        except sqlite3.Error as e:
            st.error(f"Error initializing database: {e}")
        finally:
            conn.close()

@st.cache_data(ttl=5)  # Cache for 5 seconds
def load_search_data():
    initialize_database()
    conn = get_database_connection()
    if conn is None:
        st.error("Database connection failed")
        return pd.DataFrame()  # Return an empty DataFrame if connection fails
    
    try:
        query = '''
            SELECT ip_address, url, timestamp
            FROM searches
            ORDER BY timestamp DESC
            LIMIT 100
        '''
        df = pd.read_sql_query(query, conn)
        st.write(f"Loaded {len(df)} rows from the database")  # Debug statement
        return df
    except pd.io.sql.DatabaseError as e:
        st.error(f"Error executing SQL query: {e}")
        return pd.DataFrame()  # Return an empty DataFrame on error
    except Exception as e:
        st.error(f"Unexpected error: {e}")
        return pd.DataFrame()  # Return an empty DataFrame on error
    finally:
        conn.close()

def is_public_ip(ip_address):
    try:
        return not ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False

def get_location(ip_address):
    if not is_public_ip(ip_address):
        return None, None, None, None, None
    
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
            st.warning(f"Failed to fetch location data for IP: {ip_address}. Status code: {response.status_code}")
            return None, None, None, None, None
    except Exception as e:
        st.error(f"Error fetching location data for IP {ip_address}: {str(e)}")
        return None, None, None, None, None

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

# Main content
st.title("Wall of Sheep 🐑")
data = load_search_data()

st.write(f"Initial data shape: {data.shape}")  # Debug statement

if data.empty:
    st.info("No search data available or error occurred while fetching data. Check the error messages above or run some searches from the Data Leak Tool page to populate this table.")
else:
    # Filter out private IP addresses
    data = data[data['ip_address'].apply(is_public_ip)]
    
    st.write(f"Data shape after filtering private IPs: {data.shape}")  # Debug statement
    
    if data.empty:
        st.info("No public IP addresses found in the recent searches.")
    else:
        # Apply get_location to each public IP address
        locations = data['ip_address'].apply(get_location)
        data['city'], data['region'], data['country'], data['latitude'], data['longitude'] = zip(*locations)
        data['location'] = data.apply(lambda row: f"{row['city']}, {row['region']}, {row['country']}" if row['city'] else "Unknown", axis=1)
        data['timestamp'] = pd.to_datetime(data['timestamp'])

        st.write(f"Data shape after adding location info: {data.shape}")  # Debug statement

        # Filter out rows with unknown locations
        data = data[data['location'] != "Unknown, Unknown, Unknown"]

        st.write(f"Final data shape: {data.shape}")  # Debug statement

        if data.empty:
            st.info("No location data available for public IP addresses.")
        else:
            # Display the data based on the selected page
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
                # Convert latitude and longitude to numeric, replacing non-numeric values with NaN
                map_data = data.copy()
                map_data['latitude'] = pd.to_numeric(map_data['latitude'], errors='coerce')
                map_data['longitude'] = pd.to_numeric(map_data['longitude'], errors='coerce')
                
                # Filter out rows with NaN values
                map_data = map_data.dropna(subset=['latitude', 'longitude'])
                
                if not map_data.empty:
                    # Create a map centered on the mean of all points
                    center_lat = map_data['latitude'].mean()
                    center_lon = map_data['longitude'].mean()

                    view_state = pdk.ViewState(
                        latitude=center_lat,
                        longitude=center_lon,
                        zoom=3,
                        pitch=0
                    )

                    layer = pdk.Layer(
                        "ScatterplotLayer",
                        data=map_data,
                        get_position=['longitude', 'latitude'],
                        get_color=[255, 0, 0, 200],
                        get_radius=50000,
                        pickable=True
                    )

                    tooltip = {
                        "html": "<b>IP:</b> {ip_address}<br><b>Location:</b> {location}<br><b>URL:</b> {url}",
                        "style": {"background": "grey", "color": "white", "font-family": '"Helvetica Neue", Arial', "z-index": "10000"},
                    }

                    r = pdk.Deck(
                        map_style="mapbox://styles/mapbox/light-v9",
                        initial_view_state=view_state,
                        layers=[layer],
                        tooltip=tooltip
                    )

                    st.pydeck_chart(r)
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
