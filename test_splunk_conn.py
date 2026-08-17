import os
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

SPLUNK_HOST = os.getenv("SPLUNK_HOST")
SPLUNK_PORT = os.getenv("SPLUNK_PORT")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")

url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/services/authentication/users?output_mode=json"
headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}

try:
    response = requests.get(url, headers=headers, verify=False, timeout=5)
    if response.status_code == 200:
        print("[SUCCESS] Connected to Splunk REST API successfully!")
    else:
        print(f"[FAILURE] HTTP {response.status_code}: {response.text}")
except Exception as e:
    print(f"[ERROR] Connection failed: {e}")