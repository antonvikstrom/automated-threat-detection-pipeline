import os
import requests
import urllib3
from dotenv import load_dotenv

# Suppresses self-signed certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "10.1.1.10")
SPLUNK_PORT = os.getenv("SPLUNK_PORT", "8089")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

BASE_URL = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/search/jobs"
HEADERS = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}


def check_splunk_detection(spl_query, search_name, time_range="-5m"):
    """Executes a oneshot SPL search via Splunk REST API and checks for matching logs."""
    print(f"\n[*] Auditing Splunk SIEM for: {search_name}...")

    search_payload = {
        "search": f"search {spl_query} earliest={time_range}",
        "exec_mode": "oneshot",
        "output_mode": "json",
    }

    try:
        response = requests.post(
            BASE_URL, headers=HEADERS, data=search_payload, verify=False, timeout=10
        )

        if response.status_code != 200:
            print(f"    [-] Splunk API Error: HTTP {response.status_code}")
            return None

        data = response.json()
        results = data.get("results", [])
        event_count = len(results)

        if event_count > 0:
            print(f"    [SUCCESS] Splunk caught the attack! Found {event_count} matching log event(s).")
            
            # Extract source IP or host from the first event
            first_event = results[0]
            src_ip = first_event.get("src", first_event.get("src_ip", first_event.get("clientip", "10.1.4.100")))
            print(f"    [+] Extracted Source/Attacker IP: {src_ip}")
            return src_ip
        else:
            print("    [FAILURE] Detection failed! No matching events found in Splunk.")
            return None

    except Exception as e:
        print(f"    [-] Error querying Splunk API: {e}")
        return None


if __name__ == "__main__":
    print("=== Step 2: Executing Splunk SIEM Detection Verification ===")

    # Audit Web Path Traversal logs
    web_attacker_ip = check_splunk_detection(
        spl_query='index=* "etc/passwd"',
        search_name="Web Path Traversal Attack"
    )

    # Audit Covert DNS Exfiltration logs
    dns_attacker_ip = check_splunk_detection(
        spl_query='index=* "exfil.lab"',
        search_name="Covert DNS Exfiltration"
    )

    print("\n=== Splunk Detection Audit Completed ===")