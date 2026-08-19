import ipaddress
import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")


def check_ip_reputation(ip_address):
    """Enriches an extracted IP address using AbuseIPDB or local subnet logic."""
    print(f"\n[*] Enriching Threat Intelligence for IP: {ip_address}...")

    try:
        ip_obj = ipaddress.ip_address(ip_address)

        # Handle Private / Internal Lab Subnets
        if ip_obj.is_private:
            print(f"    [INFO] IP {ip_address} is an internal lab address (RFC 1918).")
            print(
                "    [+] Threat Assessment: INTERNAL_ATTACK_SOURCE (Kali Attack Machine)"
            )
            return {
                "ip": ip_address,
                "status": "Internal",
                "score": 0,
                "label": "Internal Lab Host",
            }

        # Handle Public IPs via AbuseIPDB API
        if not ABUSEIPDB_API_KEY:
            print("    [!] Warning: ABUSEIPDB_API_KEY not found in .env file.")
            print("    [+] Defaulting to mock enrichment output.")
            return {"ip": ip_address, "status": "Unknown", "score": 0}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

        response = requests.get(url, headers=headers, params=params, timeout=5)

        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "N/A")
            usage = data.get("usageType", "Unknown")

            print(f"    [+] Country: {country} | Usage: {usage}")
            print(f"    [+] Abuse Confidence Score: {score}%")

            return {
                "ip": ip_address,
                "country": country,
                "score": score,
                "usage": usage,
            }
        else:
            print(
                f"    [-] Threat Intel API request failed with HTTP {response.status_code}"
            )
            return None

    except ValueError:
        print(f"    [-] Invalid IP address format: {ip_address}")
        return None


if __name__ == "__main__":
    print("=== Step 3: Executing Threat Intelligence Enrichment (Standalone Test) ===")

    # Test 1: Internal RFC1918 Address
    check_ip_reputation("10.0.0.1")

    # Test 2: Public IP
    check_ip_reputation("185.220.101.5")

    print("\n=== Standalone Test Completed ===")