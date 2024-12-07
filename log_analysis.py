import re
import csv
from collections import Counter

# File paths
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

# Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

# Function to parse log file
def parse_log_file(file_path):
    with open(file_path, "r") as f:
        lines = f.readlines()
    return lines

# Count requests per IP
def count_requests_per_ip(log_lines):
    ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"
    ip_addresses = [re.match(ip_pattern, line).group(1) for line in log_lines if re.match(ip_pattern, line)]
    return Counter(ip_addresses)

# Find the most accessed endpoint
def find_most_accessed_endpoint(log_lines):
    endpoint_pattern = r"\"[A-Z]+ (/\S*) HTTP"
    endpoints = [re.search(endpoint_pattern, line).group(1) for line in log_lines if re.search(endpoint_pattern, line)]
    endpoint_counts = Counter(endpoints)
    return endpoint_counts.most_common(1)[0]

# Detect suspicious activity
def detect_suspicious_activity(log_lines):
    failed_login_pattern = r"\"POST /login HTTP.*401"
    failed_attempts = {}
    for line in log_lines:
        if re.search(failed_login_pattern, line):
            ip = re.match(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    return {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

# Save results to CSV
def save_results_to_csv(ip_counts, most_accessed, suspicious_activities, output_file):
    with open(output_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed)
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main script execution
if __name__ == "__main__":
    log_lines = parse_log_file(LOG_FILE)
    ip_counts = count_requests_per_ip(log_lines)
    most_accessed = find_most_accessed_endpoint(log_lines)
    suspicious_activities = detect_suspicious_activity(log_lines)

    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip:20} {count}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities.items():
        print(f"{ip:20} {count}")

    save_results_to_csv(ip_counts, most_accessed, suspicious_activities, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")
