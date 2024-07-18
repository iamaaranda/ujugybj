import socket
import argparse
import time

# ANSI color escape sequences
GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
WHITE = '\033[0m'
RESET = '\033[0m'

# Global variables to store connection statistics
attempted_connections = 0
successful_connections = 0
failed_connections = 0
total_rtt = 0
min_rtt = float('inf')
max_rtt = 0

def tcp_ping(host, port, timeout=3):
    global attempted_connections, successful_connections, failed_connections, total_rtt, min_rtt, max_rtt
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        sock.connect((host, port))
        end_time = time.time()
        rtt_ms = (end_time - start_time) * 1000  # Calculate RTT in milliseconds
        if rtt_ms > 600:
            print(f"{RED}Connection timed out to {host}:{port}.{RESET}")
        else:
            print(f"{WHITE}Connected to {GREEN}{host}{WHITE}: time={GREEN}{rtt_ms:.2f}ms{WHITE} protocol=TCP port={GREEN}{port}{WHITE}")
        successful_connections += 1
        total_rtt += rtt_ms
        if rtt_ms < min_rtt:
            min_rtt = rtt_ms
        if rtt_ms > max_rtt:
            max_rtt = rtt_ms
        return True, rtt_ms
    except socket.error:
        print(f"{RED}Connection timed out to {host}:{port}.{RESET}")
        failed_connections += 1
        return False, None
    finally:
        sock.close()
        attempted_connections += 1

def print_connection_statistics():
    global attempted_connections, successful_connections, failed_connections, total_rtt, min_rtt, max_rtt
    if attempted_connections > 0:
        success_rate = (successful_connections / attempted_connections) * 100 if attempted_connections > 0 else 0
        print(f"\nConnection statistics:")
        print(f"\tAttempted = {CYAN}{attempted_connections}{WHITE}, Connected = {CYAN}{successful_connections}{WHITE}, Failed = {CYAN}{failed_connections}{WHITE} ({CYAN}{success_rate:.2f}%{WHITE})")
        if successful_connections > 0:
            print("Approximate connection times:")
            print(f"\tMinimum = {CYAN}{min_rtt:.2f}ms{WHITE}, Maximum = {CYAN}{max_rtt:.2f}ms{WHITE}, Average = {CYAN}{total_rtt / successful_connections:.2f}ms{RESET}{WHITE}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Continuous TCP ping tool")
    parser.add_argument("address", help="Hostname or IP address followed by port number (e.g., 192.168.1.1:80)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Timeout in seconds (default: 3)")
    parser.add_argument("-i", "--interval", type=int, default=1, help="Interval between pings in seconds (default: 1)")
    args = parser.parse_args()

    try:
        host, port = args.address.split(":")
        port = int(port)
    except ValueError:
        print(f"{RED}Invalid address format. Use ip:port or hostname:port.{RESET}")
        exit(1)

    timeout = args.timeout
    interval = args.interval

    print(f"paping v2 - Copyright (c) 2024 Randomname23233")
    print(f"\nConnecting to {YELLOW}{host}{WHITE} on {YELLOW}TCP {port}{WHITE}:\n")

    try:
        while True:
            success, rtt = tcp_ping(host, port, timeout)
            time.sleep(interval)
    except KeyboardInterrupt:
        print_connection_statistics()
