import streamlit as st
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import pandas as pd
import time

def scrape_website(url):
    # Set up Selenium WebDriver
    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # Run in headless mode
    driver = webdriver.Chrome(service=service, options=options)
    
    try:
        driver.get(url)
        
        # Wait for the page to load
        time.sleep(5)
        
        # Parse the page source with BeautifulSoup
        soup = BeautifulSoup(driver.page_source, 'html.parser')
        
        # Extract basic information
        title = soup.title.string if soup.title else "No title found"
        
        # Find all text paragraphs
        paragraphs = soup.find_all('p')
        text_content = "\n".join([p.text.strip() for p in paragraphs[:5]])  # Limit to first 5 paragraphs
        
        # Find all links
        links = soup.find_all('a', href=True)
        link_data = [{'text': a.text.strip(), 'href': a['href']} for a in links[:10]]  # Limit to first 10 links
        
        # Find all headings
        headings = soup.find_all(['h1', 'h2', 'h3'])
        heading_data = [{'level': h.name, 'text': h.text.strip()} for h in headings[:5]]  # Limit to first 5 headings
        
        # Create DataFrames
        df_info = pd.DataFrame({'Title': [title], 'Content Preview': [text_content]})
        df_links = pd.DataFrame(link_data)
        df_headings = pd.DataFrame(heading_data)
        
        return df_info, df_links, df_headings, None
    except Exception as e:
        return None, None, None, f"An error occurred: {str(e)}"
    finally:
        driver.quit()

st.title("Web Scraper App")

input_url = st.text_input("Enter the URL to scrape:")

if st.button("Scrape"):
    if input_url:
        df_info, df_links, df_headings, error = scrape_website(input_url)
        
        if error:
            st.error(error)
        elif df_info is not None and df_links is not None and df_headings is not None:
            st.success("Data scraped successfully!")
            
            # Display basic info
            st.subheader("Basic Information")
            st.dataframe(df_info)
            
            # Display headings
            st.subheader("Headings Found (First 5)")
            st.dataframe(df_headings)
            
            # Display links
            st.subheader("Links Found (First 10)")
            st.dataframe(df_links)
            
            # Export to CSV
            csv_info = df_info.to_csv(index=False)
            csv_links = df_links.to_csv(index=False)
            csv_headings = df_headings.to_csv(index=False)
            
            st.download_button(
                label="Download Basic Info CSV",
                data=csv_info,
                file_name="scraped_info.csv",
                mime="text/csv",
            )
            
            st.download_button(
                label="Download Links CSV",
                data=csv_links,
                file_name="scraped_links.csv",
                mime="text/csv",
            )
            
            st.download_button(
                label="Download Headings CSV",
                data=csv_headings,
                file_name="scraped_headings.csv",
                mime="text/csv",
            )
        else:
            st.warning("No data found to scrape.")
    else:
        st.warning("Please enter a URL.")