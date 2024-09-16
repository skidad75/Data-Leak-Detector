import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import random

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Optional GeoIP functionality
use_geoip = st.sidebar.checkbox("Use GeoIP (requires database file)", value=False)

if use_geoip:
    import geoip2.database
    geoip_path = st.sidebar.text_input("Path to GeoLite2-City.mmdb file")
    if geoip_path:
        try:
            geoip_reader = geoip2.database.Reader(geoip_path)
            st.sidebar.success("GeoIP database loaded successfully!")
        except FileNotFoundError:
            st.sidebar.error("GeoIP database file not found. Please check the path.")
            use_geoip = False
        except Exception as e:
            st.sidebar.error(f"Error loading GeoIP database: {str(e)}")
            use_geoip = False
    else:
        use_geoip = False

def get_location(ip_address):
    if use_geoip:
        try:
            geo_info = geoip_reader.city(ip_address)
            return f"{geo_info.city.name}, {geo_info.country.name}"
        except:
            return "Unknown"
    else:
        return "GeoIP not enabled"

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
    except (sqlite3.OperationalError, pd.io.sql.DatabaseError):
        st.warning("The 'searches' table doesn't exist. Displaying sample data instead.")
        # Generate sample data
        sample_data = []
        now = datetime.now()
        for _ in range(20):
            ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            url = random.choice(["http://example.com", "http://sample.org", "http://test.net"])
            timestamp = now - timedelta(minutes=random.randint(1, 60))
            sample_data.append({"ip_address": ip, "url": url, "timestamp": timestamp})
        df = pd.DataFrame(sample_data)
    except Exception as e:
        st.error(f"An unexpected error occurred: {str(e)}")
        df = pd.DataFrame(columns=["ip_address", "url", "timestamp"])
    
    df['location'] = df['ip_address'].apply(get_location)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

# Main content
st.title("Wall of Sheep 🐑")
st.sidebar.page_link("pages/Data_Leak_Detector.py", label="Home", icon="🏠")
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
    if use_geoip:
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
    
    # Most active locations (only if GeoIP is enabled)
    if use_geoip:
        location_counts = data['location'].value_counts().head(10)
        st.subheader("Top 10 Active Locations")
        st.bar_chart(location_counts)

# Footer
st.sidebar.markdown("---")
st.sidebar.info("This is a demo application. Data shown is for illustrative purposes only.")

# Add this line to link back to the home page
st.sidebar.page_link("Data_Leak_Detector", label="Home 🏠")
