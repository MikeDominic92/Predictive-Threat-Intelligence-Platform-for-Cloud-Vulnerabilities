import os
import base64
import json
import logging
from dotenv import load_dotenv
from dotenv import find_dotenv

# Import local modules
from . import utils
from .normalizers import alienvault, virustotal, gcp_scc, gcp_asset

# Configure logging
logging.basicConfig(level=logging.INFO) # Set default log level

def normalize_threat_data(event, context):
    """Cloud Function to normalize threat data when new data is added to the bucket.
    
    Args:
        event (dict): The Cloud Functions event payload
        context: Metadata for the event
    """
    try:
        # Load configuration once
        project_id = os.environ.get("PROJECT_ID")
        dataset_id = os.environ.get("DATASET_ID")
        table_id = os.environ.get("TABLE_ID")
        bucket_name = event['bucket']

        if not all([project_id, dataset_id, table_id]):
            logging.error("Missing required environment variables (PROJECT_ID, DATASET_ID, TABLE_ID)")
            return # Or raise an exception

        file_name = event['name']
        logging.info(f"Processing {file_name} from bucket {bucket_name}")

        # Only process raw data files
        if not file_name.startswith('raw/') or 'placeholder' in file_name:
            logging.info(f"Skipping non-raw or placeholder file: {file_name}")
            return
        
        # Parse source from file path
        path_parts = file_name.split('/')
        # Expecting format: raw/<source>/<filename>
        if len(path_parts) < 3 or path_parts[0] != 'raw':
            logging.warning(f"Skipping file with unexpected path format: {file_name}")
            return

        source = path_parts[1].lower() # e.g., 'alienvault', 'virustotal'

        logging.info(f"Processing {source} data from {file_name}")
        logging.info(f"Attempting to read from GCS: gs://{bucket_name}/{file_name}") # Added logging

        # Get the file content
        content = utils.read_file_from_gcs(bucket_name, file_name)
        if content is None:
            logging.error(f"Failed to read file: {bucket_name}/{file_name}")
            return

        # Normalize based on source type
        normalized_data = []

        if source == 'alienvault':
            logging.info(f"Calling normalize_alienvault_data for {file_name}")
            normalized_data = alienvault.normalize_alienvault_data(content)
            logging.info(f"Normalization resulted in {len(normalized_data)} items.") # Added logging
        elif source == 'virustotal':
            logging.info(f"Calling normalize_virustotal_data for {file_name}")
            # Wrap the single report dictionary into a list for the normalizer
            normalized_data = virustotal.normalize_virustotal_data([content])
            logging.info(f"Normalization resulted in {len(normalized_data)} items.") # Added logging
        elif source == 'scc':
            logging.info(f"Calling normalize_gcp_scc_data for {file_name}")
            normalized_data = gcp_scc.normalize_gcp_scc_data(content)
            logging.info(f"Normalization resulted in {len(normalized_data)} items.")
        elif source == 'asset':
            logging.info(f"Calling normalize_gcp_asset_data for {file_name}")
            normalized_data = gcp_asset.normalize_gcp_asset_data(content)
            logging.info(f"Normalization resulted in {len(normalized_data)} items.")
        else:
            logging.warning(f"Unknown data source type: {source}")

        if normalized_data:
            logging.info(f"Attempting to write {len(normalized_data)} items to BigQuery (Source: {source}).") # Added logging
            bq_success = utils.write_to_bigquery(normalized_data, source, project_id, dataset_id, table_id)
            logging.info(f"Finished BigQuery write attempt for {file_name}.") # Log regardless of success

            # Attempt to save normalized data back to GCS
            if bq_success: # Optionally only save if BQ write succeeded, or save regardless
                logging.info(f"Attempting to save normalized data to GCS for {file_name}.")
                utils.save_normalized_to_gcs(bucket_name, file_name, normalized_data)
                logging.info(f"Finished GCS save attempt for {file_name}.")
            else:
                logging.warning(f"Skipping GCS save for {file_name} because BigQuery write failed.")

            logging.info(f"Processed {len(normalized_data)} threat indicators from {source}")
            return bq_success # Return the success status of the BigQuery write
        else:
            logging.info(f"No threat indicators found or normalized in {file_name}")
    except Exception as e:
        logging.error(f"Error processing GCS event for file {file_name}: {e}", exc_info=True)
        # Decide if you want to raise the exception or return a failure indicator
        # raise e # Option 1: Propagate the error
        return False # Option 2: Indicate failure without stopping potential further processing

# --- Local Testing ---
if __name__ == "__main__":
    # Load environment variables from .env file
    load_dotenv(find_dotenv())
    
    # Check for required environment variables
    project_id = os.environ.get("PROJECT_ID")
    dataset_id = os.environ.get("DATASET_ID")
    table_id = os.environ.get("TABLE_ID")
    bucket_name = os.environ.get("GCS_BUCKET_NAME")
    
    print("Environment variables check:")
    print(f"- PROJECT_ID: {'SET' if project_id else 'MISSING'}")
    print(f"- DATASET_ID: {'SET' if dataset_id else 'MISSING'}")
    print(f"- TABLE_ID: {'SET' if table_id else 'MISSING'}")
    print(f"- GCS_BUCKET_NAME: {'SET' if bucket_name else 'MISSING'}")
    
    if not all([project_id, dataset_id, table_id, bucket_name]):
        print("\nERROR: Missing required environment variables. Please set all required variables and try again.")
        print("Hint: Create a .env file in the project root or set them directly in your environment.")
        exit(1)
    
    # Set up test files for different data sources
    test_files = {
        'alienvault': "raw/alienvault/sample.json",
        'virustotal': "raw/virustotal/sample.json",
        'scc': "raw/scc/sample.json",
        'asset': "raw/asset/sample.json"
    }
    
    # Choose which source to test
    test_source = 'alienvault'  # Change this to 'scc' or 'asset' to test GCP normalizers
    test_file = test_files[test_source]
    
    # Simulate a GCS event
    mock_event = {
        'bucket': bucket_name,
        'name': test_file,
        'metageneration': '1',
    }
    
    print(f"\nStarting normalization test with file: {test_file} (Source: {test_source})")
    print(f"Target BigQuery table: {project_id}.{dataset_id}.{table_id}")
    
    # Run the normalization function
    result = normalize_threat_data(mock_event, None)
    
    print(f"\nNormalization result: {'SUCCESS' if result else 'FAILED'}")
