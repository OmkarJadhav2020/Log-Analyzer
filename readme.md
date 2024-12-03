# Log Analyzer

The **Log Analyzer** is a Python-based tool for analyzing server logs. It parses log files, extracts meaningful insights such as IP request counts, most accessed endpoints, and detects suspicious activities like repeated failed login attempts. Results can be displayed interactively and exported to a CSV file for further use.

## Features

- **Request Analysis by IP**: Count and display the number of requests made by each IP address.
- **Endpoint Access Analysis**: Identify the most frequently accessed endpoint and its count.
- **Suspicious Activity Detection**: Detect IPs with failed login attempts exceeding a specified threshold.
- **CSV Export**: Save all analysis results to a CSV file.
- **Interactive Menu**: Menu-driven interface for seamless user interaction.

## Requirements

- Python 3.6+
- Required libraries:
  - `re`
  - `csv`
  - `collections`
  - `tabulate`

## Usage

Clone the repository and run the script:

```bash
git clone https://github.com/OmkarJadhav2020/Log-Analyzer.git
cd Log-Analyzer
python script.py
```

## Menu-Driven Interface
Run the program and follow the prompts to interact with the menu. You can choose specific options to perform the following tasks:

- Parse and analyze the log file.
- View requests by IP.
- Display the most accessed endpoint.
- Detect suspicious activities.
- Export results to a CSV file.

## Contributing
Feel free to submit issues, fork the repository, and create pull requests. Contributions are welcome!

## License
This project is licensed under the MIT License.

