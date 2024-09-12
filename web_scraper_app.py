import streamlit as st
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import pandas as pd
import re
from urllib.parse import urljoin, urlparse
import subprocess
import time
import socket

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

def perform_dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "DNS lookup failed"

def perform_traceroute(domain):
    route_data = []
    try:
        result = subprocess.run(['traceroute', '-m', '30', domain], capture_output=True, text=True, timeout=10)
        lines = result.stdout.split('\n')[1:-1]  # Skip the first line (header) and last line (empty)
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                hop = parts[0]
                ip = parts[2] if parts[2] != '*' else 'N/A'
                hostname = parts[1] if parts[1] != '*' else 'N/A'
                route_data.append({"Hop": hop, "IP": ip, "Hostname": hostname})
    except subprocess.TimeoutExpired:
        st.warning("Traceroute timed out, partial results may be available")
    except Exception as e:
        st.error(f"Traceroute error: {str(e)}")
    
    return pd.DataFrame(route_data) if route_data else None

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
        
        start_time = time.time()
        max_duration = 59  # Maximum duration in seconds

        for i in range(max_pages):
            if not to_visit or (time.time() - start_time) > max_duration:
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
            elapsed_time = time.time() - start_time
            time_progress = min(elapsed_time / max_duration, 1.0)
            overall_progress = (progress + time_progress) / 2  # Combine page and time progress
            
            progress_bar.progress(overall_progress)
            status_text.text(f"Scraped {i + 1} pages out of {max_pages} | {overall_progress:.1%} complete | Time: {elapsed_time:.1f}s")

            if elapsed_time > max_duration:
                st.warning(f"Scraping stopped after {max_duration} seconds")
                break

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