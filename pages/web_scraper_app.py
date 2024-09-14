import streamlit as st
import requests
from requests.exceptions import Timeout, RequestException
import concurrent.futures

# Set page config as the first Streamlit command
st.set_page_config(layout="wide", page_title="Data Leak Detector")

# Import other necessary libraries
import pandas as pd
import re
from urllib.parse import urljoin, urlparse
import subprocess
import time
import socket
import whois
from bs4 import BeautifulSoup
import ssl
import OpenSSL
from fpdf import FPDF
import io
import base64
import textwrap

def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_links(url, soup):
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
            "Creation Date": str(w.creation_date),
            "Expiration Date": str(w.expiration_date),
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
    route_data = []
    try:
        result = subprocess.run(['traceroute', '-m', '30', domain], capture_output=True, text=True, timeout=10)
        lines = result.stdout.split('\n')[1:-1]
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

def is_potential_login_page(soup, url):
    login_keywords = ['login', 'sign in', 'signin', 'log in', 'username', 'password', 'portal', 'webportal', 'web portal', 'account']
    page_text = soup.get_text().lower()
    
    # Check for login keywords in the page text
    if any(keyword in page_text for keyword in login_keywords):
        return True
    
    # Check for password input fields
    if soup.find('input', {'type': 'password'}):
        return True
    
    # Check for forms with login-related actions
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '').lower()
        if any(keyword in action for keyword in login_keywords):
            return True
    
    # Check for links with login-related text or URLs
    links = soup.find_all('a')
    for link in links:
        href = link.get('href', '').lower()
        text = link.text.lower()
        if any(keyword in href or keyword in text for keyword in login_keywords):
            return True
    
    return False

def is_potential_console_login(soup, url):
    console_keywords = ['console', 'admin', 'dashboard', 'management', 'control panel']
    page_text = soup.get_text().lower()
    
    # Check for console keywords in the page text
    if any(keyword in page_text for keyword in console_keywords):
        return True
    
    # Check for links with console-related text or URLs
    links = soup.find_all('a')
    for link in links:
        href = link.get('href', '').lower()
        text = link.text.lower()
        if any(keyword in href or keyword in text for keyword in console_keywords):
            return True
    
    return False

@st.cache_data(show_spinner=False)
def get_page_info(url):
    try:
        response = requests.get(url, timeout=5)
        ip = socket.gethostbyname(urlparse(url).netloc)
        fqdn = socket.getfqdn(urlparse(url).netloc)
        server = response.headers.get('Server', 'Unknown')
        return {'URL': url, 'IP': ip, 'FQDN': fqdn, 'Server': server}
    except Exception as e:
        return {'URL': url, 'IP': 'N/A', 'FQDN': 'N/A', 'Server': 'Error'}

@st.cache_data(show_spinner=False)
def perform_network_analysis(domain):
    ip_address = perform_dns_lookup(domain)
    whois_info = perform_whois_lookup(domain)
    
    common_ports = [80, 443, 22, 21, 25, 53, 3306, 8080, 8443]
    open_ports = perform_port_scan(ip_address, common_ports)
    
    headers = requests.get(f"http://{domain}", timeout=5).headers
    server_info = headers.get('Server', 'Not available')
    
    traceroute_data = perform_traceroute(domain)
    
    return {
        "IP Address": ip_address,
        "WHOIS Info": whois_info,
        "Open Ports": open_ports,
        "Server Info": server_info,
        "Traceroute": traceroute_data
    }

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not set'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not set'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Not set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not set')
        }
        return security_headers
    except Exception as e:
        return f"Error checking security headers: {str(e)}"

def check_ssl_cert(url):
    try:
        hostname = urlparse(url).netloc
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
        
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, s.getpeercert(binary_form=True))
        cert_info = {
            'Subject': dict(x509.get_subject().get_components()),
            'Issuer': dict(x509.get_issuer().get_components()),
            'Version': x509.get_version(),
            'Serial Number': x509.get_serial_number(),
            'Not Before': x509.get_notBefore().decode(),
            'Not After': x509.get_notAfter().decode(),
            'OCSP': cert.get('OCSP', 'Not available'),
            'Subject Alt Names': cert.get('subjectAltName', 'Not available')
        }
        return cert_info
    except Exception as e:
        return f"Error checking SSL certificate: {str(e)}"

def check_robots_txt(url):
    try:
        robots_url = urljoin(url, '/robots.txt')
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return f"No robots.txt found (Status code: {response.status_code})"
    except Exception as e:
        return f"Error checking robots.txt: {str(e)}"

def detect_data_leaks(text):
    patterns = {
        'Credit Card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'Social Security Number': r'\b\d{3}-\d{2}-\d{4}\b',
        'API Key': r'\b[A-Za-z0-9]{32,}\b',
        'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'Phone Number': r'\b\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
    }
    
    leaks = {}
    for leak_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            leaks[leak_type] = matches[:10]  # Limit to first 10 matches
    
    return leaks

def load_data(url, max_depth):
    emails = set()
    login_pages = []
    console_pages = []
    visited = set()
    to_visit = [(url, 0)]  # (url, depth)
    base_domain = urlparse(url).netloc
    security_info = {}
    data_leaks = {}

    progress_bar = st.progress(0)
    status_text = st.empty()
    email_placeholder = st.empty()
    login_placeholder = st.empty()
    console_placeholder = st.empty()
    security_placeholder = st.empty()
    leak_placeholder = st.empty()

    try:
        # Check security headers, SSL cert, and robots.txt
        security_info['Security Headers'] = check_security_headers(url)
        security_info['SSL Certificate'] = check_ssl_cert(url)
        security_info['Robots.txt'] = check_robots_txt(url)

        total_urls = 1
        processed_urls = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            while to_visit:
                current_url, depth = to_visit.pop(0)
                if current_url not in visited and urlparse(current_url).netloc == base_domain and depth <= max_depth:
                    visited.add(current_url)
                    processed_urls += 1
                    
                    future = executor.submit(process_url, current_url, depth, base_domain, max_depth)
                    try:
                        result = future.result(timeout=30)  # 30 seconds timeout for each URL
                        if result:
                            emails.update(result['emails'])
                            login_pages.extend(result['login_pages'])
                            console_pages.extend(result['console_pages'])
                            data_leaks.update(result['data_leaks'])
                            to_visit.extend(result['new_links'])
                            total_urls += len(result['new_links'])
                    except concurrent.futures.TimeoutError:
                        st.warning(f"Timeout while processing {current_url}")
                    except Exception as e:
                        st.error(f"Error processing {current_url}: {str(e)}")

                    progress = processed_urls / total_urls
                    progress_bar.progress(progress)
                    status_text.text(f"Processed {processed_urls} pages out of {total_urls} | Depth: {depth}/{max_depth} | {progress:.1%} complete")

                    # Update displays
                    df_emails = pd.DataFrame({'Email': list(emails)})
                    email_placeholder.subheader("Emails Found (First 10)")
                    email_placeholder.dataframe(df_emails.head(10))

                    if login_pages:
                        df_login_pages = pd.DataFrame([get_page_info(page) for page in login_pages])
                        login_placeholder.subheader("Potential Login Pages (First 10)")
                        login_placeholder.dataframe(df_login_pages.head(10))

                    if console_pages:
                        df_console_pages = pd.DataFrame([get_page_info(page) for page in console_pages])
                        console_placeholder.subheader("Potential Console Login Pages (First 10)")
                        console_placeholder.dataframe(df_console_pages.head(10))

                    security_placeholder.subheader("Security Information")
                    security_placeholder.json(security_info)

                    leak_placeholder.subheader("Potential Data Leaks (First 10 per type)")
                    for leak_type, leaks in data_leaks.items():
                        leak_placeholder.write(f"{leak_type}: {', '.join(list(leaks)[:10])}")

    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

    return df_emails, df_login_pages if 'df_login_pages' in locals() else pd.DataFrame(), df_console_pages if 'df_console_pages' in locals() else pd.DataFrame(), security_info, data_leaks

def process_url(url, depth, base_domain, max_depth):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        page_emails = extract_emails(soup.get_text())
        login_pages = [url] if is_potential_login_page(soup, url) else []
        console_pages = [url] if is_potential_console_login(soup, url) else []
        page_leaks = detect_data_leaks(soup.get_text())
        
        new_links = []
        if depth < max_depth:
            links = get_all_links(url, soup)
            new_links = [(link, depth + 1) for link in links if is_valid(link) and urlparse(link).netloc == base_domain]
        
        return {
            'emails': page_emails,
            'login_pages': login_pages,
            'console_pages': console_pages,
            'data_leaks': page_leaks,
            'new_links': new_links
        }
    except (Timeout, RequestException) as e:
        st.warning(f"Error accessing {url}: {str(e)}")
        return None

@st.cache_data(show_spinner=False)
def get_user_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except:
        return "Unable to retrieve IP"

def generate_pdf_report(url, emails, login_pages, console_pages, security_info, data_leaks, network_info):
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Security Analysis Report for {url}", ln=True)
    pdf.ln(10)

    # Emails
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Emails Found:", ln=True)
    pdf.set_font("Arial", "", 12)
    for _, row in emails.iterrows():
        pdf.multi_cell(0, 10, row['Email'])
    pdf.ln(5)

    # Login Pages
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Potential Login Pages:", ln=True)
    pdf.set_font("Arial", "", 12)
    for _, row in login_pages.iterrows():
        pdf.multi_cell(0, 10, row['URL'])
    pdf.ln(5)

    # Console Pages
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Potential Console Login Pages:", ln=True)
    pdf.set_font("Arial", "", 12)
    for _, row in console_pages.iterrows():
        pdf.multi_cell(0, 10, row['URL'])
    pdf.ln(5)

    # Security Information
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Security Information:", ln=True)
    pdf.set_font("Arial", "", 12)
    for key, value in security_info.items():
        pdf.multi_cell(0, 10, f"{key}: {str(value)}")
    pdf.ln(5)

    # Data Leaks
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Potential Data Leaks:", ln=True)
    pdf.set_font("Arial", "", 12)
    for leak_type, leaks in data_leaks.items():
        pdf.multi_cell(0, 10, f"{leak_type}: {', '.join(list(leaks)[:10])}")
    pdf.ln(5)

    # Network Information
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Network Information:", ln=True)
    pdf.set_font("Arial", "", 12)
    for key, value in network_info.items():
        pdf.multi_cell(0, 10, f"{key}: {str(value)}")
    pdf.ln(5)

    # Generate PDF
    pdf_buffer = io.BytesIO()
    pdf.output(pdf_buffer)
    pdf_buffer.seek(0)
    return pdf_buffer

# Main Streamlit app
# Remove the following line:
# st.title("Data Leak Detector")

# Display user's IP address and warnings
user_ip = get_user_ip()
st.sidebar.warning(f"Your IP address: {user_ip}")
st.sidebar.warning("⚠️ This tool is for educational purposes only.")
st.sidebar.warning("⚠️ Do not use on systems you don't own or have explicit permission to test.")

# Add a link to the Wall of Sheep page
st.sidebar.markdown("### Quick Links")
st.sidebar.page_link("/", label="Home 🏠")

# User input
url = st.text_input("Enter a URL to scan:")
max_depth = st.slider("Maximum crawl depth:", 1, 5, 1)  # Default set to 1

# Run button
if st.button("Run Analysis"):
    if url:
        with st.spinner("Analyzing... This may take a few minutes."):
            # Perform the analysis
            emails, login_pages, console_pages, security_info, data_leaks = load_data(url, max_depth)
            
            # Perform network analysis
            network_info = perform_network_analysis(urlparse(url).netloc)

            # Display results
            st.subheader("Analysis Results")
            
            # Display emails
            st.write("Emails Found:")
            st.dataframe(emails)

            # Display login pages
            st.write("Potential Login Pages:")
            st.dataframe(login_pages)

            # Display console pages
            st.write("Potential Console Login Pages:")
            st.dataframe(console_pages)

            # Display security info
            st.write("Security Information:")
            st.json(security_info)

            # Display data leaks
            st.write("Potential Data Leaks:")
            for leak_type, leaks in data_leaks.items():
                st.write(f"{leak_type}: {', '.join(list(leaks)[:10])}")

            # Display network info
            st.write("Network Information:")
            st.json(network_info)

        # Generate PDF report
        if st.button("Generate PDF Report"):
            pdf_buffer = generate_pdf_report(url, emails, login_pages, console_pages, security_info, data_leaks, network_info)
            b64 = base64.b64encode(pdf_buffer.getvalue()).decode()
            href = f'<a href="data:application/pdf;base64,{b64}" download="security_report.pdf">Download PDF Report</a>'
            st.markdown(href, unsafe_allow_html=True)
    else:
        st.error("Please enter a URL to scan.")
