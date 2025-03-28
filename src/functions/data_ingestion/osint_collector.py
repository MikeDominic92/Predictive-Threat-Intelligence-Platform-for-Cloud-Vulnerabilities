import os
import json
import datetime
import requests
import feedparser
from google.cloud import storage

# API keys should be stored in environment variables or Secret Manager in production
ALIENVAULT_API_KEY = os.environ.get("ALIENVAULT_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# Cloud Storage bucket for raw data
RAW_BUCKET = os.environ.get("RAW_BUCKET", "threat-intel-raw")

def collect_osint(event, context):
    """Cloud Function to collect OSINT from various sources.
    
    Args:
        event: The Cloud Functions event payload.
        context: Metadata for the event.
    """
    # Parse the message data from Pub/Sub
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    message_data = json.loads(pubsub_message)
    sources = message_data.get('sources', ['alienvault', 'virustotal'])
    
    collection_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results = {}
    
    # Collect from each source
    for source in sources:
        if source == "alienvault":
            results[source] = collect_from_alienvault()
        elif source == "virustotal":
            results[source] = collect_from_virustotal()
        # Add more collectors for other sources
    
    # Save collected data to Cloud Storage
    save_to_storage(results, collection_timestamp)
    
    # Log the summary
    print(f"Collected threat intelligence from {len(sources)} sources at {collection_timestamp}")
    
def collect_from_alienvault():
    """Collect threat intelligence from AlienVault OTX."""
    # Example implementation - this would be expanded in a real system
    try:
        # AlienVault OTX API for pulse indicators
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Process and return relevant data
            return {
                "pulses": data.get("results", []),
                "count": len(data.get("results", [])),
                "timestamp": datetime.datetime.now().isoformat()
            }
        else:
            print(f"Error collecting from AlienVault: {response.status_code}")
            return {"error": f"Status code: {response.status_code}"}
    
    except Exception as e:
        print(f"Exception collecting from AlienVault: {str(e)}")
        return {"error": str(e)}

def collect_from_virustotal():
    """Collect threat intelligence from VirusTotal."""
    # Example implementation - this would be expanded in a real system
    try:
        # VirusTotal API for recent malicious files
        url = "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Process and return relevant data
            return {
                "files": data.get("data", []),
                "count": len(data.get("data", [])),
                "timestamp": datetime.datetime.now().isoformat()
            }
        else:
            print(f"Error collecting from VirusTotal: {response.status_code}")
            return {"error": f"Status code: {response.status_code}"}
    
    except Exception as e:
        print(f"Exception collecting from VirusTotal: {str(e)}")
        return {"error": str(e)}

def save_to_storage(data, timestamp):
    """Save collected data to Google Cloud Storage."""
    try:
        client = storage.Client()
        bucket = client.get_bucket(RAW_BUCKET)
        
        # Create a blob for each source
        for source, source_data in data.items():
            blob_name = f"raw/{source}/{timestamp}.json"
            blob = bucket.blob(blob_name)
            
            # Upload the data as JSON
            blob.upload_from_string(
                json.dumps(source_data, indent=2),
                content_type="application/json"
            )
            
            print(f"Saved {source} data to gs://{RAW_BUCKET}/{blob_name}")
    
    except Exception as e:
        print(f"Error saving to Cloud Storage: {str(e)}")

# For local testing
if __name__ == "__main__":
    # Simulate a Pub/Sub message
    event = {
        'data': base64.b64encode(json.dumps({"sources": ["alienvault"]}).encode('utf-8'))
    }
    context = {}
    collect_osint(event, context)
