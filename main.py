import streamlit as st

st.set_page_config(page_title="Data Leak Detector", page_icon="🕵️", layout="wide")

st.title("Data Leak Detector 🕵️")

st.markdown("""
## Welcome to the Data Leak Detector

This tool is designed to help you identify potential data leaks and security vulnerabilities in websites. It crawls web pages, analyzes their content, and provides insights into possible security risks.

### Key Features:

- **Web Crawling**: Systematically browse and analyze web pages.
- **Email Detection**: Identify exposed email addresses.
- **Login Page Detection**: Locate potential login pages.
- **Security Headers Analysis**: Check for important security headers.
- **Data Leak Detection**: Identify possible leaks of sensitive information.
- **Network Information**: Gather details about the website's hosting.

### How to Use:

1. Navigate to the "Web Scraper" page.
2. Enter the URL you want to analyze.
3. Set the maximum crawl depth.
4. Click "Run Analysis" and wait for the results.

### Pages:

""")

# Update these lines
st.page_link("pages/web_scraper_app.py", label="Web Scraper 🌐")
st.page_link("pages/Wall_of_Sheep.py", label="Wall of Sheep 🐑")

st.markdown("""
### Important Note:

This tool is for educational and ethical testing purposes only. Always ensure you have permission to scan and analyze a website before using this tool. Unauthorized scanning may be illegal in some jurisdictions.

### Disclaimer:

The developers of this tool are not responsible for any misuse or damage caused by this program. Use at your own risk and always adhere to ethical guidelines and legal requirements when conducting security assessments.
""")

st.sidebar.markdown("### Quick Links")
st.sidebar.page_link("pages/web_scraper_app.py", label="Start Scanning 🚀")
st.sidebar.page_link("pages/Wall_of_Sheep.py", label="View Wall of Sheep 🐑")

st.sidebar.markdown("---")
st.sidebar.info("Developed with ❤️ by Your Team")
