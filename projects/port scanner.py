import socket
from concurrent.futures import ThreadPoolExecutor

# scan function
def scan_port(target, port, timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"
        print(f"Port {port}: OPEN ({service})")

# main 

def run():
    print("Welcome to the Port Scanner!")
    target = input("Enter the target IP address or hostname: ")

    # added this part because last code took 10 minutes to scan all ports, so I added threading to speed it up
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1, 1025):
            executor.submit(scan_port, target, port)

    print("Scanning completed.")

run()