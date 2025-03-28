import functions_framework
import requests
import os
import json
import datetime
from google.cloud import storage
from dotenv import load_dotenv

# Load environment variables from .env file for local development
load_dotenv()

# Configuration (ideally from environment variables)
OTX_API_KEY = os.environ.get("OTX_API_KEY")
GCS_BUCKET_NAME = os.environ.get("GCS_RAW_BUCKET") # Use the bucket for raw data
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# GCS Client (initialize outside the function for potential reuse)
storage_client = storage.Client()

@functions_framework.cloud_event
def collect_osint_data(cloud_event):
    """
    Cloud Function triggered by Pub/Sub (or scheduler) to collect OSINT data.
    Currently focuses on AlienVault OTX pulses.
    """
    print("Starting OSINT collection...")

    if not OTX_API_KEY or OTX_API_KEY == "YOUR_OTX_API_KEY_HERE":
        print("Error: OTX_API_KEY environment variable not set or is placeholder.")
        return "OTX API Key not configured", 500
    if not GCS_BUCKET_NAME or GCS_BUCKET_NAME == "your-gcs-raw-data-bucket-name":
        print("Error: GCS_RAW_BUCKET environment variable not set or is placeholder.")
        return "GCS Bucket Name not configured", 500

    try:
        # --- Collect AlienVault OTX Pulses ---
        print("Collecting AlienVault OTX pulses...")
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        # Get pulses modified since yesterday (adjust timeframe as needed)
        yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S')
        params = {"modified_since": yesterday, "limit": 100} # Limit results per call

        all_pulses = []
        next_page_url = OTX_API_URL

        while next_page_url:
            response = requests.get(next_page_url, headers=headers, params=params)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            pulses = data.get("results", [])
            all_pulses.extend(pulses)
            print(f"Fetched {len(pulses)} pulses. Total so far: {len(all_pulses)}")

            next_page_url = data.get("next")
            params = None # Params are only needed for the first request

            if len(all_pulses) > 1000: # Safety break to avoid excessive collection
                 print("Warning: Reached safety limit of 1000 pulses.")
                 break

        if not all_pulses:
            print("No new AlienVault pulses found since yesterday.")
            # We can optionally save an empty file, but for now just exit cleanly.
            return "No new data", 200

        # --- Save data to GCS ---
        print(f"Saving {len(all_pulses)} pulses to GCS...")
        today_date = datetime.datetime.now().strftime('%Y-%m-%d')
        # Structure: raw/<source>/<date>-<type>.json
        file_name = f"raw/alienvault/{today_date}-pulses.json"
        bucket = storage_client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(file_name)

        # Save all collected pulses as a single JSON object/array
        # For potential future consistency, wrap in a main key e.g., 'pulses'
        # output_data = {"pulses": all_pulses} # If needed

        blob.upload_from_string(
            json.dumps(all_pulses, indent=2), # Saving as a JSON array directly
            content_type="application/json"
        )
        print(f"Successfully saved data to gs://{GCS_BUCKET_NAME}/{file_name}")

        # --- TODO: Add other OSINT sources (e.g., VirusTotal) here ---

        print("OSINT collection finished successfully.")
        return "OK", 200

    except requests.exceptions.RequestException as e:
        print(f"HTTP Request Error fetching OTX data: {e}")
        return f"HTTP Error: {e}", 500
    except storage.exceptions.GoogleCloudError as e:
        print(f"GCS Error: {e}")
        return f"GCS Error: {e}", 500
    except json.JSONDecodeError as e:
         print(f"Error decoding JSON response from OTX API: {e}")
         return f"JSON Decode Error: {e}", 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return f"Error: {e}", 500
