import re
import csv
from collections import defaultdict
from tabulate import tabulate


class LogAnalyzer:
    """
    A class for analyzing server logs and extracting useful insights.

    Attributes:
        file_path (str): Path to the log file.
        threshold (int): Threshold for detecting suspicious activity (default is 10).
        log_data (list): A list of dictionaries containing parsed log data. Each dictionary contains:
                         - 'ip': IP address 
                         - 'method': HTTP method (e.g., GET, POST).
                         - 'endpoint': The accessed URL.
                         - 'status': HTTP status code (e.g., 200, 401, 404).
    """

    def __init__(self, file_path, threshold=10):
        """
        Initializes the LogAnalyzer object.

        Args:
            file_path (str): The file path to the log file.
            threshold (int): The threshold for failed login attempts to be flagged as suspicious activity.
        """
        self.file_path = file_path
        self.threshold = threshold
        self.log_data = []

    def parse_log_file(self):
        """
        Parses the log file and extracts relevant information.

        This method reads the log file line by line and uses a regex pattern to extract:
        - IP 
        - HTTP method 
        - Endpoint 
        - Status code.

        The parsed data is stored as a dictionary in `self.log_data`.

        Returns:
            None
        """
        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    match = re.match(
                        r'(?P<ip>\d+\.\d+\.\d+\.\d+) .* "(?P<method>\w+) (?P<endpoint>.+?) HTTP.*" (?P<status>\d+) .*', line
                    )
                    if match:
                        self.log_data.append(match.groupdict())
        except FileNotFoundError:
            print(f"Error: File '{self.file_path}' not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def count_requests_by_ip(self):
        """
        Counts the number of requests made by each IP address.

        Returns:
            list: A list of tuples sorted by request count in descending order. 
                  Each tuple contains:
                  - IP address (str)
                  - Number of requests (int)
        """
        ip_count = defaultdict(int)
        for entry in self.log_data:
            ip_count[entry['ip']] += 1
        return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

    def most_frequent_endpoint(self):
        """
        Finds the most frequently accessed endpoint.

        Returns:
            tuple: The endpoint with the highest access count and the count itself.
        """
        endpoint_count = defaultdict(int)
        for entry in self.log_data:
            endpoint_count[entry['endpoint']] += 1
        return max(endpoint_count.items(), key=lambda x: x[1])

    def detect_suspicious_activity(self):
        """
        Identifies IP addresses with failed login attempts exceeding the threshold.

        Returns:
            dict: A dictionary of IP addresses and their failed login attempt counts.
                  Only includes IPs where the count exceeds the threshold.
        """
        failed_attempts = defaultdict(int)
        for entry in self.log_data:
            if entry['status'] == '401':
                failed_attempts[entry['ip']] += 1
        return {ip: count for ip, count in failed_attempts.items() if count > self.threshold}

    def save_to_csv(self, ip_requests, most_accessed, suspicious_activities, output_file='log_analysis_results.csv'):
        """
        Saves analysis results to a CSV file.

        Args:
            ip_requests (list): List of tuples containing IP addresses and their request counts.
            most_accessed (tuple): The most accessed endpoint and its count.
            suspicious_activities (dict): Dictionary of suspicious IPs and their failed login attempt counts.
            output_file (str): Name of the output CSV file.
        """
        try:
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)

                # Write IP Request Counts
                writer.writerow(['--- Requests Per IP ---'])
                writer.writerow(['IP Address', 'Request Count'])
                writer.writerows(ip_requests)
                writer.writerow([])

                # Write Most Accessed Endpoint
                writer.writerow(['--- Most Accessed Endpoint ---'])
                writer.writerow(['Endpoint', 'Access Count'])
                writer.writerow(most_accessed)
                writer.writerow([])

                # Write Suspicious Activity
                writer.writerow(['--- Suspicious Activity ---'])
                writer.writerow(['IP Address', 'Failed Login Attempts'])
                writer.writerows(suspicious_activities.items())
        except Exception as e:
            print(f"Error saving results to CSV: {e}")

    def display_menu(self):
        """
        Displays a menu to the user for selecting an analysis action.

        Returns:
            None
        """
        while True:
            print("\n--- Log Analysis Menu ---")
            print("1. Count requests by IP")
            print("2. Find the most accessed endpoint")
            print("3. Detect suspicious activity")
            print("4. Save analysis results to CSV")
            print("5. Exit")
            
            choice = input("Enter your choice: ").strip()
            
            if choice == '1':
                ip_requests = self.count_requests_by_ip()
                print("\nRequests per IP:")
                print(tabulate(ip_requests, headers=['IP Address', 'Request Count'], tablefmt='grid'))
            elif choice == '2':
                most_accessed = self.most_frequent_endpoint()
                print("\nMost Frequently Accessed Endpoint:")
                print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
            elif choice == '3':
                suspicious_activities = self.detect_suspicious_activity()
                print("\nSuspicious Activity Detected:")
                if suspicious_activities:
                    print(tabulate(suspicious_activities.items(), headers=['IP Address', 'Failed Login Attempts'], tablefmt='grid'))
                else:
                    print("No suspicious activity detected.")
            elif choice == '4':
                ip_requests = self.count_requests_by_ip()
                most_accessed = self.most_frequent_endpoint()
                suspicious_activities = self.detect_suspicious_activity()
                self.save_to_csv(ip_requests, most_accessed, suspicious_activities)
                print("Results saved to log_analysis_results.csv")
            elif choice == '5':
                print("Exiting Log Analyzer.")
                break
            else:
                print("Invalid choice. Please select a valid option.")


if __name__ == '__main__':
    log_file = input("Enter the log file name (e.g., sample.log): ").strip()
    threshold = input("Enter the threshold for failed login attempts (default: 10): ").strip()

    # Validate threshold
    try:
        threshold = int(threshold) if threshold else 10
    except ValueError:
        print("Invalid threshold value. Using default value: 10")
        threshold = 10

    analyzer = LogAnalyzer(log_file, threshold)
    analyzer.parse_log_file()
    if analyzer.log_data:
        analyzer.display_menu()
