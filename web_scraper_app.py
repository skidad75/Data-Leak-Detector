import streamlit as st
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import pandas as pd
import re
from urllib.parse import urljoin, urlparse
from scapy.all import traceroute
import socket
import time

def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_links(url, driver):
    driver.get(url)
    soup = BeautifulSoup(driver.page_source, "html.parser")
    return [urljoin(url, link.get('href')) for link in soup.find_all('a') if link.get('href')]

def extract_emails(text):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(email_pattern, text)

def perform_traceroute(domain):
    try:
        result, _ = traceroute(domain, maxttl=30, timeout=2)
        route_data = []
        for snd, rcv in result:
            if rcv:
                ip = rcv.src
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                route_data.append({"Hop": snd.ttl, "IP": ip, "Hostname": hostname})
        return pd.DataFrame(route_data)
    except Exception as e:
        st.error(f"Traceroute error: {str(e)}")
        return None

def scrape_website(url, max_pages):
    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Chrome(service=service, options=options)
    
    try:
        visited = set()
        to_visit = [url]
        emails = set()
        base_domain = urlparse(url).netloc

        progress_bar = st.progress(0)
        status_text = st.empty()

        for i in range(max_pages):
            if not to_visit:
                break
            
            current_url = to_visit.pop(0)
            if current_url not in visited and urlparse(current_url).netloc == base_domain:
                visited.add(current_url)
                driver.get(current_url)
                soup = BeautifulSoup(driver.page_source, 'html.parser')
                
                # Extract emails from the current page
                page_emails = extract_emails(soup.get_text())
                emails.update(page_emails)
                
                # Get new links to visit
                links = get_all_links(current_url, driver)
                to_visit.extend(link for link in links if is_valid(link) and link not in visited)

            progress = min((i + 1) / max_pages, 1.0)
            progress_bar.progress(progress)
            status_text.text(f"Scraped {i + 1} pages out of {max_pages}")
            time.sleep(0.1)  # To prevent overwhelming the server

        email_list = list(emails)
        df_emails = pd.DataFrame({'Email': email_list})
        
        return df_emails, None
    except Exception as e:
        return None, f"An error occurred: {str(e)}"
    finally:
        driver.quit()

st.set_page_config(layout="wide")
st.title("Web Scraper, Email Harvester, and Network Analyzer")

col1, col2 = st.columns(2)

with col1:
    input_url = st.text_input("Enter the URL to scrape:")
    max_pages = st.number_input("Maximum number of pages to scrape:", min_value=1, value=10)

with col2:
    st.subheader("CSV Export Settings")
    csv_separator = st.selectbox("CSV Separator:", [",", ";", "\t"])
    include_index = st.checkbox("Include Index in CSV", value=False)
    
if st.button("Scrape and Analyze"):
    if input_url:
        df_emails, error = scrape_website(input_url, max_pages)
        
        if error:
            st.error(error)
        else:
            st.success("Data scraped successfully!")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Display emails only if found
                if df_emails is not None and not df_emails.empty:
                    st.subheader("Emails Found (First 10)")
                    st.dataframe(df_emails.head(10))
                    
                    # Export to CSV
                    csv_emails = df_emails.to_csv(index=include_index, sep=csv_separator)
                    
                    st.download_button(
                        label="Download All Emails CSV",
                        data=csv_emails,
                        file_name="scraped_emails.csv",
                        mime="text/csv",
                    )
                else:
                    st.warning("No emails found.")
            
            with col2:
                # Perform traceroute
                st.subheader("Network Traceroute")
                domain = urlparse(input_url).netloc
                df_traceroute = perform_traceroute(domain)
                
                if df_traceroute is not None and not df_traceroute.empty:
                    st.dataframe(df_traceroute)
                    
                    # Export traceroute to CSV
                    csv_traceroute = df_traceroute.to_csv(index=include_index, sep=csv_separator)
                    
                    st.download_button(
                        label="Download Traceroute CSV",
                        data=csv_traceroute,
                        file_name="traceroute.csv",
                        mime="text/csv",
                    )
                else:
                    st.warning("Traceroute data not available.")
    else:
        st.warning("Please enter a URL.")