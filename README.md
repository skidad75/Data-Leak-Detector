# Web Scraper, Email Harvester, and Network Analyzer

## Description

This Streamlit-based application provides a comprehensive tool for web scraping, email harvesting, and network analysis. It's designed for educational and research purposes, offering insights into website structure, security configurations, and network details.

## Features

- Web scraping with depth control (up to 5 pages)
- Email harvesting from scraped pages
- Detection of potential login pages
- Network analysis including DNS lookup, WHOIS information, and port scanning
- Security header checking
- SSL/TLS certificate information
- Robots.txt file analysis
- User IP address display
- Export functionality for collected data (CSV format)

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

2. Open your web browser and navigate to the URL provided by Streamlit (usually http://localhost:8501).

3. Enter the URL you want to analyze in the input field.

4. Adjust the number of pages to scrape (1-5) and CSV export settings if needed.

5. Click "Scrape and Analyze" to start the process.

6. View the results in the app interface and use the download buttons to export data as needed.

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

This tool is for educational purposes only. The authors are not responsible for any misuse or damage caused by this program. Use at your own risk.