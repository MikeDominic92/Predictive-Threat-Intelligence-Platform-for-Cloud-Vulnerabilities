import os
import json
import requests
import functions_framework
import time
import feedparser
from datetime import datetime, timedelta, timezone
from google.cloud import storage
from dotenv import load_dotenv
from functions.data_acquisition.gcp_scc import collect_scc_findings

# Load environment variables from .env file for local development
# Explicitly load .env.local, searching upwards from the current file directory
# Use override=True if you want .env.local to take precedence over system env vars
load_dotenv(dotenv_path='.env.local', verbose=True) # Added dotenv_path and verbose for debugging

# --- Configuration ---
ALIENVAULT_API_KEY = os.environ.get("ALIENVAULT_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") # VirusTotal API Key
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME")
NVD_API_KEY = os.environ.get("NVD_API_KEY") # Optional NVD API Key
GCP_ORGANIZATION_ID = os.environ.get('GCP_ORGANIZATION_ID') # New: Get Org ID
# Using public pulses endpoint which has different permission requirements
ALIENVAULT_BASE_URL = "https://otx.alienvault.com" # Define Base URL
ALIENVAULT_API_URL = f"{ALIENVAULT_BASE_URL}/api/v1/pulses/subscribed"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0" # Add NVD API URL
VT_API_URL_BASE = "https://www.virustotal.com/api/v3"
# Define GCS paths
GCS_AV_PREFIX = "raw/alienvault"
GCS_VT_PREFIX = "raw/virustotal" # New: Define VirusTotal prefix
GCS_NVD_PREFIX = "raw/nvd" # New: Define NVD prefix
GCS_RSS_PREFIX = "raw/rss" # New: Define RSS prefix
GCS_SCC_PREFIX = "raw/scc" # New: Define SCC prefix
# VirusTotal Config
VT_REQUEST_DELAY_SECONDS = 1 # Delay between VT API calls

# List of RSS Feeds to Collect (Customize this list)
RSS_FEEDS = {
    "Mandiant": "https://www.mandiant.com/resources/blog/rss.xml",
    "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
    "Unit42": "https://unit42.paloaltonetworks.com/feed/",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackerNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/",
    # Add more feeds as needed
}

# --- Helper Functions ---

def save_to_gcs(bucket_name, blob_prefix, filename, data):
    """Saves data to a GCS bucket."""
    if not bucket_name:
        print("Error: GCS_BUCKET_NAME environment variable not set.")
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

def collect_rss_feeds(feed_urls_dict):
    """Collects entries from a dictionary of RSS feeds."""
    print("Collecting RSS feed entries...")
    all_feed_data = {}
    total_entries_collected = 0

    for feed_name, feed_url in feed_urls_dict.items():
        print(f"  Fetching feed: {feed_name} ({feed_url})")
        try:
            # Set user-agent to avoid potential blocking
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            # Use feedparser's built-in etag and modified headers for conditional fetching
            parsed_feed = feedparser.parse(feed_url, agent=headers['User-Agent'])

            if parsed_feed.bozo:
                 # Check if bozo_exception is present and log it
                if isinstance(parsed_feed.bozo_exception, feedparser.CharacterEncodingOverride):
                    print(f"    Warning: Character encoding override for {feed_name}. Data might be partially parsed.")
                else:
                    print(f"    Warning: Malformed feed ({feed_name}). Error: {parsed_feed.bozo_exception}")
                    # Continue processing entries if possible, but log the warning
            
            feed_entries = []
            if 'entries' in parsed_feed:
                for entry in parsed_feed.entries:
                    # Attempt to parse published date, handle various formats
                    published_parsed = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        try:
                            # feedparser returns a time.struct_time, convert to datetime
                            ts = time.mktime(entry.published_parsed)
                            published_parsed = datetime.fromtimestamp(ts, timezone.utc).isoformat()
                        except Exception as date_err:
                            print(f"      Warning: Could not parse date for entry in {feed_name}: {date_err}")
                    
                    feed_entries.append({
                        'title': getattr(entry, 'title', None),
                        'link': getattr(entry, 'link', None),
                        'published_iso': published_parsed,
                        'published_raw': getattr(entry, 'published', None),
                        'summary': getattr(entry, 'summary', None),
                        'content': getattr(entry, 'content', None), # Some feeds have full content
                        'id': getattr(entry, 'id', getattr(entry, 'link', None)), # Use link as fallback ID
                    })
                print(f"    Fetched {len(feed_entries)} entries from {feed_name}.")
                all_feed_data[feed_name] = feed_entries
                total_entries_collected += len(feed_entries)
            else:
                 print(f"    No 'entries' found in the parsed feed for {feed_name}.")
                 all_feed_data[feed_name] = []

        except Exception as e:
            print(f"  Error fetching or parsing feed {feed_name}: {e}")
            all_feed_data[feed_name] = [] # Add empty list on error
        finally:
            time.sleep(1) # Small delay between fetching feeds

    print(f"Finished fetching RSS feeds. Total entries collected: {total_entries_collected}")
    return all_feed_data

# --- Data Collection Functions ---

def collect_alienvault_pulses(api_key, since_datetime, max_pages=None):
    """Collects pulses from AlienVault OTX API, fetching full details for each.""" 
    print("Collecting AlienVault OTX pulses...")
    if not api_key or api_key == "your-alienvault-api-key" or api_key == "your-new-test-api-key":
        print(f"Error: ALIENVAULT_API_KEY environment variable value '{api_key}' appears to be a placeholder.")
        return {"pulses": []} # Return empty dict with pulses key

    headers = {'X-OTX-API-KEY': api_key}
    all_detailed_pulses = [] # Changed variable name
    pulses_fetched_basic = 0 # Counter for basic pulses before detail fetch
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
            
            # Exit if max_pages reached
            if max_pages is not None and page > max_pages:
                print(f"Reached max pages limit ({max_pages})")
                break
            response = requests.get(ALIENVAULT_API_URL, headers=headers, params=params, timeout=30)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            data = response.json()
            pulses = data.get('results', [])
            pulses_fetched_basic += len(pulses)
            print(f"Fetched {len(pulses)} basic pulses on page {page}. Total basic so far: {pulses_fetched_basic}")

            # Fetch full details for each pulse
            for pulse in pulses:
                pulse_id = pulse.get('id')
                if not pulse_id:
                    print("Warning: Found pulse without ID, skipping detail fetch.")
                    all_detailed_pulses.append(pulse) # Append basic info if ID missing
                    continue

                detail_url = f"{ALIENVAULT_BASE_URL}/api/v1/pulses/{pulse_id}"
                try:
                    print(f"  Fetching details for pulse {pulse_id}...")
                    detail_response = requests.get(detail_url, headers=headers, timeout=30)
                    detail_response.raise_for_status()
                    detailed_pulse_data = detail_response.json()
                    all_detailed_pulses.append(detailed_pulse_data)

                except requests.exceptions.RequestException as detail_err:
                    print(f"  Error fetching details for pulse {pulse_id}: {detail_err}. Appending basic pulse info.")
                    all_detailed_pulses.append(pulse) # Append basic info on error
                except json.JSONDecodeError as json_err:
                    print(f"  Error decoding JSON for pulse {pulse_id} details: {json_err}. Appending basic pulse info.")
                    all_detailed_pulses.append(pulse) # Append basic info on error
                finally:
                    time.sleep(1) # Add delay to respect API rate limits

            print(f"Processed page {page}. Total detailed pulses collected: {len(all_detailed_pulses)}")

            if data.get('next'):
                page += 1
            else:
                break # No more pages

        print(f"Finished fetching AlienVault pulses. Total detailed pulses collected: {len(all_detailed_pulses)}")
        # Return in expected format (dictionary with 'pulses' key)
        return {"pulses": all_detailed_pulses}

    except requests.exceptions.RequestException as e:
        print(f"Error fetching AlienVault pulses list: {e}") # Clarified error source
        return {"pulses": []} # Return empty dict with pulses key
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response from AlienVault list endpoint: {e}") # Clarified error source
        return {"pulses": []} # Return empty dict with pulses key
    except Exception as e:
        print(f"An unexpected error occurred during AlienVault collection: {e}")
        return {"pulses": []} # Return empty dict with pulses key


def collect_virustotal_data(api_key):
    """Collects data from VirusTotal API (v3) for specific indicators."""
    print("Collecting VirusTotal data...")
    if not api_key or api_key == "your-virustotal-api-key":
        print("Error: VIRUSTOTAL_API_KEY environment variable not set or is placeholder.")
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


def collect_nvd_data(start_date_iso, end_date_iso, api_key=None, results_per_page=2000):
    """Collects CVE data from the NVD API 2.0 within a date range."""
    print(f"Collecting NVD CVEs modified between {start_date_iso} and {end_date_iso}...")
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
        print("Using NVD API Key.")
    else:
        print("No NVD API Key found, using public access (lower rate limits).")

    all_cves = []
    start_index = 0
    total_results_available = -1 # Initialize to enter the loop

    try:
        while total_results_available == -1 or start_index < total_results_available:
            params = {
                'lastModStartDate': start_date_iso,
                'lastModEndDate': end_date_iso,
                'resultsPerPage': results_per_page,
                'startIndex': start_index
            }

            print(f"Fetching NVD CVEs starting at index {start_index}...")
            # NVD API suggests a delay between requests without an API key
            if not api_key:
                time.sleep(6) # 6-second delay for public access
            else:
                time.sleep(0.6) # 0.6-second delay with API key

            response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=60) # Increased timeout
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            all_cves.extend([v['cve'] for v in vulnerabilities]) # Extract the 'cve' object

            if total_results_available == -1:
                total_results_available = data.get('totalResults', 0)
                print(f"Total CVEs available in timeframe: {total_results_available}")

            print(f"Fetched {len(vulnerabilities)} CVEs. Total collected so far: {len(all_cves)}")

            if not vulnerabilities or (start_index + len(vulnerabilities)) >= total_results_available:
                break # Exit if no more results or we've fetched all

            start_index += results_per_page

        print(f"Finished fetching NVD CVEs. Total collected: {len(all_cves)}")
        return {"cves": all_cves} # Return in a dictionary structure

    except requests.exceptions.Timeout:
        print(f"Error: NVD API request timed out (startIndex: {start_index}). Partial results: {len(all_cves)}")
        return {"cves": all_cves} # Return potentially partial results on timeout
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD CVEs: {e}")
        return {"cves": []}
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response from NVD: {e}")
        return {"cves": []}
    except Exception as e:
        print(f"An unexpected error occurred during NVD collection: {e}")
        return {"cves": []}


# --- Main Cloud Function ---

# Cloud Function entry point - Using HTTP trigger with authentication for increased security
@functions_framework.http
def collect_osint_data(request):
    """
    Cloud Function triggered by HTTP request.
    Collects data from various OSINT sources and saves it to GCS.
    
    Args:
        request: HTTP request object
    """
    print("Starting OSINT collection via HTTP trigger - secured with authentication and dedicated service account...")
    today_str = datetime.now().strftime('%Y-%m-%d')
    yesterday = datetime.now() - timedelta(days=1)

    # --- Collect AlienVault Data ---
    alienvault_pulses = collect_alienvault_pulses(ALIENVAULT_API_KEY, yesterday)
    
    # Always save a test file with a unique timestamp to verify function execution
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    av_filename = f"test-{timestamp}.json"
    
    # Create a minimal payload if no data was collected
    if not alienvault_pulses or not isinstance(alienvault_pulses, dict) or 'pulses' not in alienvault_pulses:
        alienvault_pulses = {"pulses": [{"id": "test_pulse", "name": "Minimal AV Sample"}]}
        
    save_to_gcs(GCS_BUCKET_NAME, GCS_AV_PREFIX, av_filename, alienvault_pulses)
    print(f"Saved AlienVault test file: {av_filename}")


    # --- Collect VirusTotal Data ---
    virustotal_data = collect_virustotal_data(VIRUSTOTAL_API_KEY)
    
    # Always save a test file with a unique timestamp to verify function execution
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')  # Re-generate timestamp to be slightly different
    vt_filename = f"test-{timestamp}.json"
    
    # Create a minimal payload if no data was collected
    if not virustotal_data or not isinstance(virustotal_data, list) or len(virustotal_data) == 0:
        virustotal_data = [{"ip": "8.8.8.8", "test": True, "message": "Minimal VT Sample"}]
        
    save_to_gcs(GCS_BUCKET_NAME, GCS_VT_PREFIX, vt_filename, virustotal_data)
    print(f"Saved VirusTotal test file: {vt_filename}")


    # --- Collect NVD Data ---
    nvd_data = collect_nvd_data(yesterday.isoformat(), today_str, NVD_API_KEY)
    
    # Always save a test file with a unique timestamp to verify function execution
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')  # Re-generate timestamp to be slightly different
    nvd_filename = f"test-{timestamp}.json"
    
    # Create a minimal payload if no data was collected
    if not nvd_data or not isinstance(nvd_data, dict) or 'cves' not in nvd_data:
        nvd_data = {"cves": [{"id": "test_cve", "name": "Minimal NVD Sample"}]}
        
    save_to_gcs(GCS_BUCKET_NAME, GCS_NVD_PREFIX, nvd_filename, nvd_data)
    print(f"Saved NVD test file: {nvd_filename}")


    # --- Collect RSS Feeds ---
    rss_data = collect_rss_feeds(RSS_FEEDS)
    
    # Always save a test file with a unique timestamp to verify function execution
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')  # Re-generate timestamp to be slightly different
    rss_filename = f"test-{timestamp}.json"
    
    # Create a minimal payload if no data was collected
    if not rss_data:
        rss_data = {"feeds": [{"name": "Minimal RSS Sample"}]}
        
    save_to_gcs(GCS_BUCKET_NAME, GCS_RSS_PREFIX, rss_filename, rss_data)
    print(f"Saved RSS test file: {rss_filename}")


    # --- Collect SCC Findings ---
    scc_data = {"findings": []} # Initialize scc_data
    if GCP_ORGANIZATION_ID:
        # Example: Collect active findings from the last 24 hours for testing
        scc_filter = f'state="ACTIVE" AND event_time >= "{yesterday.isoformat()}"'
        scc_data = collect_scc_findings(GCP_ORGANIZATION_ID, filter_str=scc_filter)
    else:
        print("Skipping SCC collection: GCP_ORGANIZATION_ID not set.")

    # Always save a test file with a unique timestamp to verify function execution
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')  # Re-generate timestamp to be slightly different
    scc_filename = f"scc_findings_{timestamp}.json"
    
    # Create a minimal payload if no data was collected
    if not scc_data or not isinstance(scc_data, dict) or 'findings' not in scc_data:
        scc_data = {"findings": [{"id": "test_finding", "name": "Minimal SCC Sample"}]}
        
    save_to_gcs(GCS_BUCKET_NAME, GCS_SCC_PREFIX, scc_filename, scc_data)
    print(f"Saved SCC test file: {scc_filename}")


    # --- TODO: Add calls to other OSINT source collectors ---


    print("OSINT collection finished successfully (or with partial errors).")
    return 'OK' # Return success status for Cloud Function execution

# --- Local Testing ---
# Run locally without functions-framework
if __name__ == "__main__":
    print("Running OSINT collector locally...")
    print(f"Environment variables check:\n- ALIENVAULT_API_KEY: {'SET' if ALIENVAULT_API_KEY else 'MISSING'}\n- VIRUSTOTAL_API_KEY: {'SET' if VIRUSTOTAL_API_KEY else 'MISSING'}\n- GCS_BUCKET_NAME: {'SET' if GCS_BUCKET_NAME else 'MISSING'}\n- NVD_API_KEY: {'SET' if NVD_API_KEY else 'NOT SET (Optional)'}\n- GCP_ORGANIZATION_ID: {'SET' if GCP_ORGANIZATION_ID else 'MISSING (Required for SCC)'}") # Updated check

    # Don't run if any required environment variables are missing
    # Adjusted check to ensure core functionality runs even if SCC ID is missing, but SCC collection won't
    if not all([ALIENVAULT_API_KEY, VIRUSTOTAL_API_KEY, GCS_BUCKET_NAME]):
        print("\nERROR: Missing required environment variables (ALIENVAULT_API_KEY, VIRUSTOTAL_API_KEY, GCS_BUCKET_NAME).")
        print("Hint: Create a .env file or set them directly in your environment.")
        exit(1)
        
    print("\nStarting data collection...")
    mock_event = None
    collect_osint_data(mock_event)
