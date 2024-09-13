# Data Leak Detector

## Description

Data Leak Detector is a Streamlit-based application designed to identify potential data leaks and security vulnerabilities in websites. It combines web scraping, email harvesting, and network analysis to provide insights into website structure, security configurations, and potential exposure of sensitive information.

## Demo

You can try out the Data Leak Detector at: https://dataleaks.streamlit.app/

## Features

- Web scraping with depth control (up to 7 pages)
- Email harvesting from scraped pages
- Detection of potential login pages and forms
- Identification of input fields that may handle sensitive data
- Network analysis including DNS lookup, WHOIS information, and port scanning
- Security header checking
- SSL/TLS certificate information
- Robots.txt file analysis
- Sitemap.xml analysis
- User IP address display
- Export functionality for collected data (CSV format)
- Visual representation of scraped website structure
- Customizable risk scoring based on detected vulnerabilities
- Cookie analysis and detection of third-party cookies
- JavaScript file analysis for potential security risks
- Detection of external links and resources

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/web-scraper-analyzer.git
   cd web-scraper-analyzer
   ```

2. Create and activate a Conda environment:
   ```
   conda env create -f environment.yml
   conda activate scraper
   ```

## Usage

1. Run the Streamlit app:
   ```
   streamlit run web_scraper_app.py
   ```

   Alternatively, you can use the online demo at https://dataleaks.streamlit.app/

2. Open your web browser and navigate to the URL provided by Streamlit (usually http://localhost:8501) if running locally.

3. Enter the URL you want to analyze in the input field.

4. Adjust the number of pages to scrape (1-7) and customize analysis settings if needed.

5. Click "Analyze Website" to start the process.

6. View the results in the app interface, including:
   - Website structure visualization
   - Detected emails and their sources
   - Identified login pages and forms
   - Security headers analysis
   - SSL/TLS certificate details
   - Cookie analysis
   - JavaScript file analysis
   - External links and resources
   - Sitemap and robots.txt information
   - Overall risk score and breakdown

7. Use the download buttons to export data as needed.

## Ethical Considerations

This tool is intended for educational and research purposes only. Always ensure you have permission to scan and analyze any website you don't own. Unauthorized use may be illegal and unethical.

## Dependencies

- Python 3.12
- Streamlit
- Pandas
- Requests
- BeautifulSoup4
- python-whois
- pyOpenSSL
- (See environment.yml for full list)

## Contributing

Contributions to improve the tool are welcome. Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes and commit (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature-branch`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have permission to scan and analyze any website you don't own. The authors are not responsible for any misuse or damage caused by this program. Use responsibly and at your own risk.