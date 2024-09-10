import streamlit as st
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def scrape_website(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        tables = soup.find_all('table')
        
        if not tables:
            return None, "No tables found on the webpage."
        
        all_data = []
        for table in tables:
            data = []
            table_header = []
            rows = table.find_all('tr')
            
            for i, row in enumerate(rows):
                cols = row.find_all(['th', 'td'])
                if i == 0:
                    table_header = [ele.text.strip() for ele in cols]
                else:
                    data.append([ele.text.strip() for ele in cols])
            
            df = pd.DataFrame(data, columns=table_header)
            all_data.append(df)
        
        return pd.concat(all_data, ignore_index=True), None
    except Exception as e:
        return None, f"An error occurred: {str(e)}"

st.title("Web Scraper App")

input_type = st.radio("Select input type:", ("URL", "IP"))
input_value = st.text_input("Enter the URL or IP address:")

if st.button("Scrape"):
    if input_value:
        if (input_type == "URL" and is_valid_url(input_value)) or (input_type == "IP" and is_valid_ip(input_value)):
            if input_type == "IP":
                input_value = f"http://{input_value}"
            
            df, error = scrape_website(input_value)
            
            if error:
                st.error(error)
            elif df is not None and not df.empty:
                st.success("Data scraped successfully!")
                
                # Display preview
                st.subheader("Preview (First 25 rows)")
                st.dataframe(df.head(25))
                
                # Export to CSV
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="scraped_data.csv",
                    mime="text/csv",
                )
            else:
                st.warning("No data found to scrape.")
        else:
            st.error(f"Invalid {'URL' if input_type == 'URL' else 'IP address'}. Please enter a valid one.")
    else:
        st.warning("Please enter a URL or IP address.")