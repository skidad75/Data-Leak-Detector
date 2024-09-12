import streamlit as st
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import pandas as pd
import re
from urllib.parse import urljoin, urlparse

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

def scrape_website(url):
    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    driver = webdriver.Chrome(service=service, options=options)
    
    try:
        visited = set()
        to_visit = [url]
        emails = set()
        base_domain = urlparse(url).netloc

        while to_visit:
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

        email_list = list(emails)
        df_emails = pd.DataFrame({'Email': email_list})
        
        return df_emails, None
    except Exception as e:
        return None, f"An error occurred: {str(e)}"
    finally:
        driver.quit()

st.title("Web Scraper and Email Harvester")

input_url = st.text_input("Enter the URL to scrape:")

if st.button("Scrape"):
    if input_url:
        df_emails, error = scrape_website(input_url)
        
        if error:
            st.error(error)
        elif df_emails is not None and not df_emails.empty:
            st.success("Data scraped successfully!")
            
            # Display emails
            st.subheader("Emails Found (First 10)")
            st.dataframe(df_emails.head(10))
            
            # Export to CSV
            csv_emails = df_emails.to_csv(index=False)
            
            st.download_button(
                label="Download All Emails CSV",
                data=csv_emails,
                file_name="scraped_emails.csv",
                mime="text/csv",
            )
        else:
            st.warning("No emails found to scrape.")
    else:
        st.warning("Please enter a URL.")