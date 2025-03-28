import os
import json
import requests
import functions_framework
import time
from datetime import datetime, timedelta
from google.cloud import storage
from dotenv import load_dotenv

# Load environment variables from .env file for local development
# Explicitly load .env.local, searching upwards from the current file directory
# Use override=True if you want .env.local to take precedence over system env vars
load_dotenv(dotenv_path='.env.local', verbose=True) # Added dotenv_path and verbose for debugging

# --- Configuration ---
OTX_API_KEY = os.environ.get("OTX_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY") # New: Read VirusTotal API Key
GCS_RAW_BUCKET = os.environ.get("GCS_RAW_BUCKET")
ALIENVAULT_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
# Define GCS paths
GCS_AV_PREFIX = "raw/alienvault"
GCS_VT_PREFIX = "raw/virustotal" # New: Define VirusTotal prefix
# VirusTotal Config
VT_API_URL_BASE = "https://www.virustotal.com/api/v3"
VT_REQUEST_DELAY_SECONDS = 1 # Delay between VT API calls

# --- Helper Functions ---

def save_to_gcs(bucket_name, blob_prefix, filename, data):
    """Saves data to a GCS bucket."""
    if not bucket_name:
        print("Error: GCS_RAW_BUCKET environment variable not set.")
        return False
    try:
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob_path = f"{blob_prefix}/{filename}"
        blob = bucket.blob(blob_path)

        print(f"Saving {len(data)} items to GCS bucket '{bucket_name}' at '{blob_path}'...")
        # Convert data to JSON string for saving
        json_data = json.dumps(data, indent=4)
        blob.upload_from_string(json_data, content_type='application/json')
        print(f"Successfully saved data to {blob.public_url if hasattr(blob, 'public_url') else f'gs://{bucket_name}/{blob_path}'}")
        return True
    except Exception as e:
        print(f"Error saving data to GCS: {e}")
        return False

# --- Data Collection Functions ---

def collect_alienvault_pulses(api_key, since_datetime):
    """Collects pulses from AlienVault OTX API."""
    print("Collecting AlienVault OTX pulses...")
    if not api_key or api_key == "YOUR_OTX_API_KEY_HERE":
        print("Error: OTX_API_KEY environment variable not set or is placeholder.")
        return [] # Return empty list on error

    headers = {'X-OTX-API-KEY': api_key}
    all_pulses = []
    page = 1
    params = {
        "modified_since": since_datetime.isoformat(),
        "limit": 100, # Adjust limit as needed (max 100 for free tier?)
        "page": page
    }

    try:
        while True:
            params["page"] = page
            print(f"Fetching page {page}...")
            response = requests.get(ALIENVAULT_API_URL, headers=headers, params=params, timeout=30)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            data = response.json()
            pulses = data.get('results', [])
            all_pulses.extend(pulses)

            print(f"Fetched {len(pulses)} pulses. Total so far: {len(all_pulses)}")

            if data.get('next'):
                page += 1
            else:
                break # No more pages

        print(f"Finished fetching AlienVault pulses. Total collected: {len(all_pulses)}")
        return all_pulses

    except requests.exceptions.RequestException as e:
        print(f"Error fetching AlienVault pulses: {e}")
        return [] # Return empty list on error
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response from AlienVault: {e}")
        return [] # Return empty list on error
    except Exception as e:
        print(f"An unexpected error occurred during AlienVault collection: {e}")
        return [] # Return empty list on error


def collect_virustotal_data(api_key):
    """Collects data from VirusTotal API (v3) for specific indicators."""
    print("Collecting VirusTotal data...")
    if not api_key or api_key == "YOUR_VT_API_KEY_HERE":
        print("Error: VT_API_KEY environment variable not set or is placeholder.")
        return [] # Return empty list on error

    headers = {"x-apikey": api_key}
    # Example: Query reports for a predefined list of IP addresses
    test_ips = ["8.8.8.8", "1.1.1.1"] # Replace/extend later
    collected_reports = []

    print(f"Querying VirusTotal for {len(test_ips)} IP addresses...")
    for ip in test_ips:
        endpoint = f"{VT_API_URL_BASE}/ip_addresses/{ip}"
        try:
            print(f"  Fetching report for {ip}...")
            response = requests.get(endpoint, headers=headers, timeout=20)
            response.raise_for_status() # Check for HTTP errors
            report = response.json()
            collected_reports.append(report)
            print(f"    Successfully fetched report for {ip}.")

        except requests.exceptions.RequestException as e:
            print(f"Error fetching VirusTotal report for {ip}: {e}")
            # Decide how to handle errors: skip, add error marker, etc.
            # For now, we just print and continue
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response from VirusTotal for {ip}: {e}")

        # Add delay to respect potential API rate limits
        print(f"Waiting {VT_REQUEST_DELAY_SECONDS}s before next VT request...")
        time.sleep(VT_REQUEST_DELAY_SECONDS)

    print(f"Finished fetching VirusTotal reports. Collected: {len(collected_reports)}")
    return collected_reports


# --- Main Cloud Function ---

@functions_framework.cloud_event
def collect_osint_data(cloud_event):
    """
    Cloud Function triggered by CloudEvent (e.g., Pub/Sub, Scheduler).
    Collects data from various OSINT sources and saves it to GCS.
    """
    print("Starting OSINT collection...")
    today_str = datetime.now().strftime('%Y-%m-%d')
    yesterday = datetime.now() - timedelta(days=1)

    # --- Collect AlienVault Data ---
    alienvault_pulses = collect_alienvault_pulses(OTX_API_KEY, yesterday)
    if alienvault_pulses: # Only save if data was collected
        av_filename = f"{today_str}-pulses.json"
        save_to_gcs(GCS_RAW_BUCKET, GCS_AV_PREFIX, av_filename, alienvault_pulses)
    else:
        print("Skipping GCS save for AlienVault due to collection errors or no data.")


    # --- Collect VirusTotal Data ---
    virustotal_data = collect_virustotal_data(VT_API_KEY)
    if virustotal_data: # Only save if data was collected
        # Update filename for VT IP reports
        vt_filename = f"{today_str}-vt_ip_reports.json"
        save_to_gcs(GCS_RAW_BUCKET, GCS_VT_PREFIX, vt_filename, virustotal_data)
    else:
        print("Skipping GCS save for VirusTotal due to collection errors or no data.")


    # --- TODO: Add calls to other OSINT source collectors ---


    print("OSINT collection finished successfully (or with partial errors).")
    return 'OK' # Return success status for Cloud Function execution

# --- Local Testing ---
# You can add a main block to test locally without functions-framework if needed
# if __name__ == "__main__":
#     print("Running locally...")
#     # Simulate a cloud event object if needed by the function signature
#     class MockCloudEvent:
#         def __init__(self, data=None):
#             self.data = data or {}
#     mock_event = MockCloudEvent()
#     collect_osint_data(mock_event)
