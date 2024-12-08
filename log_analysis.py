import re

# Parse the log file and extract information
def parse_log_file( logsample):
    ip_counts = {}
    endpoint_counts = {}
    failed_logins = {}

  with open("logs/log_sample.txt", 'r') as file:

        for line in file:
            # Extract IP, endpoint, and status using regex
            match = re.match(r'(\S+) - - \[.*\] "\S+ (\S+) \S+" (\d+)', line)
            if match:
                ip = match.group(1)
                endpoint = match.group(2)
                status = match.group(3)

                # Count requests per IP
                if ip not in ip_counts:
                    ip_counts[ip] = 0
                ip_counts[ip] += 1

                # Count requests per endpoint
                if endpoint not in endpoint_counts:
                    endpoint_counts[endpoint] = 0
                endpoint_counts[endpoint] += 1

                # Track failed logins
                if status == '401':
                    if ip not in failed_logins:
                        failed_logins[ip] = 0
                    failed_logins[ip] += 1

    return ip_counts, endpoint_counts, failed_logins

# Save results to a CSV file
def save_to_csv(ip_counts, endpoint_counts, failed_logins):
    with open('log_analysis_results.csv', 'w') as file:
        file.write('Requests per IP Address:\n')
        file.write('IP Address,Request Count\n')
        for ip, count in ip_counts.items():
            file.write(f'{ip},{count}\n')

        file.write('\nMost Accessed Endpoints:\n')
        file.write('Endpoint,Access Count\n')
        for endpoint, count in endpoint_counts.items():
            file.write(f'{endpoint},{count}\n')

        file.write('\nSuspicious Activity (Failed Login Attempts):\n')
        file.write('IP Address,Failed Login Count\n')
        for ip, count in failed_logins.items():
            if count > 10:  # Only save IPs with more than 10 failed attempts
                file.write(f'{ip},{count}\n')

# Main function
def main():
    log_file = 'log_sample.txt'  # Log file name
    print("Analyzing log file...\n")

    # Parse log file
    ip_counts, endpoint_counts, failed_logins = parse_log_file(log_file)

    # Display IP request counts
    print("Requests per IP Address:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count} requests")

    # Display most accessed endpoint
    print("\nMost Accessed Endpoint:")
    most_accessed = max(endpoint_counts, key=endpoint_counts.get)
    print(f"{most_accessed}: {endpoint_counts[most_accessed]} accesses")

    # Display suspicious activity
    print("\nSuspicious Activity (Failed Login Attempts):")
    for ip, count in failed_logins.items():
        if count > 10:
            print(f"{ip}: {count} failed login attempts")

    # Save results to CSV
    save_to_csv(ip_counts, endpoint_counts, failed_logins)
    print("\nResults saved to 'log_analysis_results.csv'.")

# Run the script
if __name__ == '__main__':
    main()
