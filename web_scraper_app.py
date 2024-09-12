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
import whois
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_links(url, driver):
    driver.get(url)
    soup = BeautifulSoup(driver.page_source, 'html.parser')
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

def perform_whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Name Servers": w.name_servers
        }
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

def perform_port_scan(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def perform_traceroute(domain):
    route_data = []  # Initialize route_data before the try block
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

def find_login_pages(url, driver, max_pages=10):
    visited = set()
    to_visit = [url]
    login_pages = []
    base_domain = urlparse(url).netloc

    while to_visit and len(login_pages) < max_pages:
        current_url = to_visit.pop(0)
        if current_url not in visited and urlparse(current_url).netloc == base_domain:
            visited.add(current_url)
            driver.get(current_url)
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            
            # Check if the page might be a login page
            if is_potential_login_page(soup):
                login_pages.append(current_url)
            
            # Get new links to visit
            links = get_all_links(current_url, driver)
            to_visit.extend(link for link in links if is_valid(link) and link not in visited)

    return login_pages[:max_pages]

def is_potential_login_page(soup):
    # Check for common login page indicators
    login_keywords = ['login', 'sign in', 'signin', 'log in', 'username', 'password']
    page_text = soup.get_text().lower()
    
    if any(keyword in page_text for keyword in login_keywords):
        return True
    
    # Check for password input fields
    if soup.find('input', {'type': 'password'}):
        return True
    
    return False

def get_page_info(url):
    try:
        response = requests.get(url, timeout=5)
        ip = socket.gethostbyname(urlparse(url).netloc)
        fqdn = socket.getfqdn(urlparse(url).netloc)
        server = response.headers.get('Server', 'Unknown')
        return {'URL': url, 'IP': ip, 'FQDN': fqdn, 'Server': server}
    except Exception as e:
        return {'URL': url, 'IP': 'N/A', 'FQDN': 'N/A', 'Server': 'Error'}

@st.cache_data
def load_data(url, max_pages):
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
        max_duration = 59  # Maximum total duration in seconds

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
            overall_progress = max(progress, time_progress)
            
            progress_bar.progress(overall_progress)
            status_text.text(f"Scraped {i + 1} pages out of {max_pages} | {overall_progress:.1%} complete | Time: {elapsed_time:.1f}s")

            if elapsed_time > max_duration:
                st.warning(f"Scraping stopped after {max_duration} seconds")
                break

        email_list = list(emails)
        df_emails = pd.DataFrame({'Email': email_list})
        
        # Find login pages
        login_pages = find_login_pages(url, driver)
        with ThreadPoolExecutor(max_workers=10) as executor:
            login_page_info = list(executor.map(get_page_info, login_pages))
        
        df_login_pages = pd.DataFrame(login_page_info)
        
        return df_emails, df_login_pages, time.time() - start_time
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        return None, None, time.time() - start_time
    finally:
        driver.quit()

@st.cache_data
def perform_network_analysis(domain):
    ip_address = perform_dns_lookup(domain)
    whois_info = perform_whois_lookup(domain)
    
    common_ports = [80, 443, 22, 21, 25, 53, 3306, 8080, 8443]
    open_ports = perform_port_scan(ip_address, common_ports)
    
    headers = requests.get(f"http://{domain}").headers
    server_info = headers.get('Server', 'Not available')
    
    traceroute_data = perform_traceroute(domain)
    
    return {
        "IP Address": ip_address,
        "WHOIS Info": whois_info,
        "Open Ports": open_ports,
        "Server Info": server_info,
        "Traceroute": traceroute_data
    }

st.set_page_config(layout="wide")
st.title("Web Scraper, Email Harvester, and Network Analyzer")

col1, col2 = st.columns(2)

with col1:
    input_url = st.text_input("Enter the URL to scrape:")
    max_pages = st.number_input("Number of pages to scrape:", min_value=1, max_value=5, value=1)

with col2:
    st.subheader("CSV Export Settings")
    csv_separator = st.selectbox("CSV Separator:", [",", ";", "\t"])
    include_index = st.checkbox("Include Index in CSV", value=False)
    
if st.button("Scrape and Analyze"):
    if input_url:
        df_emails, df_login_pages, elapsed_time = load_data(input_url, max_pages)
        
        if df_emails is not None:
            st.success("Data scraped successfully!")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Display emails only if found
                if not df_emails.empty:
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
                
                # Display login pages
                if not df_login_pages.empty:
                    st.subheader("Potential Login Pages (First 10)")
                    st.dataframe(df_login_pages)
                    
                    # Export to CSV
                    csv_login_pages = df_login_pages.to_csv(index=include_index, sep=csv_separator)
                    
                    st.download_button(
                        label="Download Login Pages CSV",
                        data=csv_login_pages,
                        file_name="login_pages.csv",
                        mime="text/csv",
                    )
                else:
                    st.warning("No potential login pages found.")
            
            with col2:
                # Perform network analysis
                st.subheader("Network Analysis")
                domain = urlparse(input_url).netloc
                
                network_info = perform_network_analysis(domain)
                
                st.write(f"IP Address: {network_info['IP Address']}")
                st.write("WHOIS Information:")
                st.json(network_info['WHOIS Info'])
                st.write(f"Open Ports: {', '.join(map(str, network_info['Open Ports']))}")
                st.write(f"Server Information: {network_info['Server Info']}")
                
                if network_info['Traceroute'] is not None:
                    st.subheader("Traceroute")
                    st.dataframe(network_info['Traceroute'])
                else:
                    st.warning("Traceroute data not available.")
        
        st.write(f"Total time: {elapsed_time:.1f} seconds")
    else:
        st.warning("Please enter a URL.")

st.button("Rerun")