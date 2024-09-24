import streamlit as st
import pandas as pd
from datetime import datetime
from database_utils import load_search_data

# Set page config
st.set_page_config(page_title="Wall of Sheep", page_icon="🐑", layout="wide")

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Recent Searches", "Map View", "Statistics"])

def get_location(ip_address):
    # Placeholder function for location lookup
    return "Location data not available"

# Main content
st.title("Wall of Sheep 🐑")
data = load_search_data()

if data.empty:
    st.info("No search data available. Run some searches from the Data Leak Tool page to populate this table.")
else:
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

# Footer
st.sidebar.markdown("---")
