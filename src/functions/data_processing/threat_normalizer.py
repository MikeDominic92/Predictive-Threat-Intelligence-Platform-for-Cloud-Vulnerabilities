import os
import base64
import json
import datetime
from google.cloud import storage
from google.cloud import bigquery
import pandas as pd
import numpy as np

# BigQuery dataset and table for normalized data
PROJECT_ID = os.environ.get("PROJECT_ID", "predictive-threat-intelligence")
DATASET_ID = os.environ.get("DATASET_ID", "threat_intelligence")
TABLE_ID = os.environ.get("TABLE_ID", "normalized_threats")

def normalize_threat_data(event, context):
    """Cloud Function to normalize threat data when new data is added to the bucket.
    
    Args:
        event (dict): The Cloud Functions event payload
        context: Metadata for the event
    """
    # Get the file information from the event
    bucket_name = event['bucket']
    file_name = event['name']
    
    # Only process raw data files
    if not file_name.startswith('raw/'):
        return
    
    # Parse source from file path
    path_parts = file_name.split('/')
    if len(path_parts) < 3:
        return
    
    source = path_parts[1]  # e.g., 'alienvault', 'virustotal'
    
    print(f"Processing {source} data from {file_name}")
    
    # Get the file content
    content = read_file_from_gcs(bucket_name, file_name)
    if not content:
        print(f"Failed to read file: {bucket_name}/{file_name}")
        return
    
    # Normalize based on source type
    normalized_data = []
    if source == "alienvault":
        normalized_data = normalize_alienvault_data(content)
    elif source == "virustotal":
        normalized_data = normalize_virustotal_data(content)
    # Add more normalizers for other sources
    
    if normalized_data:
        # Write to BigQuery
        write_to_bigquery(normalized_data)
        
        # Also save normalized version to Cloud Storage for archiving
        save_normalized_to_gcs(bucket_name, file_name, normalized_data)
        
        print(f"Processed {len(normalized_data)} threat indicators from {source}")
    else:
        print(f"No threat indicators found in {file_name}")

def read_file_from_gcs(bucket_name, file_name):
    """Read a file from Google Cloud Storage."""
    try:
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(bucket_name)
        blob = bucket.blob(file_name)

        # Check if the blob exists before trying to download
        if blob.exists():
            content = blob.download_as_string()
            return json.loads(content)
        else:
            print(f"File not found in GCS: gs://{bucket_name}/{file_name}")
            return None
            
    except json.JSONDecodeError:
        print(f"Error processing file {file_name}: Invalid JSON content.")
        return None
    except Exception as e:
        print(f"Error reading from GCS: {str(e)}")
        return None

def normalize_alienvault_data(data):
    """Normalize AlienVault OTX data to standard format."""
    normalized = []
    try:
        pulses = data.get("pulses", [])
        
        for pulse in pulses:
            pulse_id = pulse.get("id")
            pulse_name = pulse.get("name")
            pulse_description = pulse.get("description")
            pulse_tags = pulse.get("tags", [])
            created = pulse.get("created")
            
            for indicator in pulse.get("indicators", []):
                normalized.append({
                    "source": "alienvault",
                    "type": indicator.get("type"),
                    "value": indicator.get("indicator"),
                    "threat_type": "indicator",
                    "confidence_score": calculate_confidence(pulse, indicator),
                    "severity": calculate_severity(pulse, indicator),
                    "description": pulse_description,
                    "tags": pulse_tags,
                    "pulse_id": pulse_id,
                    "pulse_name": pulse_name,
                    "created": created,
                    "processed_at": datetime.datetime.now().isoformat()
                })
        
        return normalized
    except Exception as e:
        print(f"Error normalizing AlienVault data: {str(e)}")
        return []

def normalize_virustotal_data(data):
    """Normalize VirusTotal data to standard format."""
    normalized = []
    try:
        files = data.get("files", [])
        
        for file in files:
            attributes = file.get("attributes", {})
            normalized.append({
                "source": "virustotal",
                "type": "file",
                "value": file.get("id", ""),
                "threat_type": "malware",
                "confidence_score": calculate_vt_confidence(attributes),
                "severity": calculate_vt_severity(attributes),
                "description": attributes.get("meaningful_name", "Unknown malware"),
                "tags": extract_vt_tags(attributes),
                "file_type": attributes.get("type_tag", ""),
                "sha256": attributes.get("sha256", ""),
                "created": attributes.get("creation_date", ""),
                "processed_at": datetime.datetime.now().isoformat()
            })
        
        return normalized
    except Exception as e:
        print(f"Error normalizing VirusTotal data: {str(e)}")
        return []

def calculate_confidence(pulse, indicator):
    """Calculate confidence score for AlienVault indicator."""
    # Example implementation - would be more sophisticated in production
    base_score = 0.5  # Start with neutral confidence
    
    # Adjust based on pulse factors
    if pulse.get("adversary"):
        base_score += 0.1
    if len(pulse.get("tags", [])) > 3:
        base_score += 0.1
    
    return min(base_score, 1.0)  # Cap at 1.0

def calculate_severity(pulse, indicator):
    """Calculate severity score for AlienVault indicator."""
    # Example implementation - would be more sophisticated in production
    # Look for known high-severity tags
    tags = pulse.get("tags", [])
    high_severity_tags = ["ransomware", "exploit", "zero-day", "apt"]
    
    if any(tag.lower() in high_severity_tags for tag in tags):
        return "high"
    elif len(tags) > 5:  # More context generally indicates higher severity
        return "medium"
    else:
        return "low"

def calculate_vt_confidence(attributes):
    """Calculate confidence score for VirusTotal data."""
    # Example implementation - would be more sophisticated in production
    detection_ratio = attributes.get("last_analysis_stats", {}).get("malicious", 0) / \
                     max(1, sum(attributes.get("last_analysis_stats", {}).values()))
    
    return min(detection_ratio, 1.0)

def calculate_vt_severity(attributes):
    """Calculate severity score for VirusTotal data."""
    # Example implementation - would be more sophisticated in production
    malicious_engines = attributes.get("last_analysis_stats", {}).get("malicious", 0)
    
    if malicious_engines > 20:
        return "high"
    elif malicious_engines > 5:
        return "medium"
    else:
        return "low"

def extract_vt_tags(attributes):
    """Extract meaningful tags from VirusTotal attributes."""
    tags = []
    
    # Add file type
    if "type_tag" in attributes:
        tags.append(attributes["type_tag"])
    
    # Add detection names (limit to avoid too many tags)
    for engine, result in list(attributes.get("last_analysis_results", {}).items())[:5]:
        if result.get("category") == "malicious" and "result" in result:
            tags.append(result["result"])
    
    return list(set(tags))  # Remove duplicates

def write_to_bigquery(normalized_data):
    """Write normalized data to BigQuery."""
    try:
        client = bigquery.Client()
        table_id = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
        
        # Load data into BigQuery
        errors = client.insert_rows_json(table_id, normalized_data)
        
        if errors:
            print(f"Errors inserting rows to BigQuery: {errors}")
        else:
            print(f"Successfully inserted {len(normalized_data)} rows to {table_id}")
    
    except Exception as e:
        print(f"Error writing to BigQuery: {str(e)}")

def save_normalized_to_gcs(bucket_name, raw_file_name, normalized_data):
    """Save normalized data back to GCS for archiving."""
    try:
        normalized_file_name = raw_file_name.replace('raw/', 'normalized/')
        
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(bucket_name)
        blob = bucket.blob(normalized_file_name)
        
        blob.upload_from_string(
            json.dumps(normalized_data, indent=2),
            content_type='application/json'
        )
        
        print(f"Saved normalized data to gs://{bucket_name}/{normalized_file_name}")
    
    except Exception as e:
        print(f"Error saving normalized data to GCS: {str(e)}")

# For local testing
if __name__ == "__main__":
    # Simulate a GCS event
    event = {
        'bucket': 'predictive-threat-intelligence-threat-intel-raw',
        'name': 'raw/alienvault/20230415_120000.json'
    }
    context = {}
    normalize_threat_data(event, context)
