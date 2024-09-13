# Data Leak Detector

## Description

Data Leak Detector is a Streamlit-based application designed to identify potential data leaks and security vulnerabilities in websites. It combines web scraping, email harvesting, and network analysis to provide insights into website structure, security configurations, and potential exposure of sensitive information.

## Demo

You can try out the Data Leak Detector at: https://dataleaks.streamlit.app/

## Features

- Web scraping with depth control (up to 7 pages)
- Email harvesting from scraped pages
- Detection of potential login pages and console login pages
- Network analysis including DNS lookup, WHOIS information, and port scanning
- Security header checking
- SSL/TLS certificate information
- Robots.txt file analysis
- User IP address display
- Export functionality for collected data (CSV format)
- Potential data leak detection (credit cards, SSNs, API keys, etc.)
- Traceroute visualization

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/data-leak-detector.git
   cd data-leak-detector
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the Streamlit app:
   ```
   streamlit run web_scraper_app.py
   ```

   Alternatively, you can use the online demo at https://dataleaks.streamlit.app/

2. Open your web browser and navigate to the URL provided by Streamlit (usually http://localhost:8501) if running locally.

3. Enter the URL you want to analyze in the input field.

4. Adjust the maximum depth to scan (1-7) and customize CSV export settings if needed.

5. Click "Scrape and Analyze" to start the process.

6. View the results in the app interface, including:
   - Detected emails
   - Potential login pages and console login pages
   - Security information (headers, SSL certificate, robots.txt)
   - Network analysis (IP, WHOIS, open ports, traceroute)
   - Potential data leaks

7. Use the download buttons to export data as needed.

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have permission to scan and analyze any website you don't own. The authors are not responsible for any misuse or damage caused by this program. Use responsibly and at your own risk.

## License

This project is licensed under the MIT License - see the LICENSE file for details.