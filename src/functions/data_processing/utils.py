# Utility functions for data processing
import os
import json
import logging
from google.cloud import storage
from google.cloud import bigquery

# Configure logging if not already configured by the main function
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=logging.INFO)

# BigQuery configuration (can be overridden by environment variables)
PROJECT_ID = os.environ.get("PROJECT_ID", "predictive-threat-intelligence")
DATASET_ID = os.environ.get("DATASET_ID", "threat_intelligence")
TABLE_ID = os.environ.get("TABLE_ID", "normalized_threats")

def read_file_from_gcs(bucket_name, file_name):
    """Read a file from Google Cloud Storage and parse as JSON."""
    gcs_path = f"gs://{bucket_name}/{file_name}"
    logging.info(f"Attempting GCS Read: {gcs_path}") # More detailed log
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(file_name)

        if blob.exists():
            logging.info(f"Downloading {gcs_path}")
            content = blob.download_as_string()
            logging.info(f"Successfully downloaded {gcs_path}")
            try:
                data = json.loads(content)
                logging.info(f"Successfully parsed JSON from {gcs_path}")
                return data
            except json.JSONDecodeError as json_e:
                logging.error(f"JSON Decode Error for {gcs_path}: {str(json_e)}")
                return None
        else:
            logging.error(f"File not found in GCS: {gcs_path}")
            return None

    except Exception as e:
        # Log the full exception for Cloud Storage errors
        logging.error(f"GCS Read Error for {gcs_path}: {str(e)}", exc_info=True)
        return None

def write_to_bigquery(normalized_data, source, project_id, dataset_id, table_id):
    """Writes normalized data records to the specified BigQuery table.

    Args:
        normalized_data (list): A list of dictionaries representing normalized records.
        source (str): The original data source (e.g., 'alienvault', 'virustotal').
        project_id (str): Google Cloud project ID.
        dataset_id (str): BigQuery dataset ID.
        table_id (str): BigQuery table ID.
    """
    if not normalized_data:
        logging.info(f"No data to write to BigQuery for source: {source}")
        return

    if not all([project_id, dataset_id, table_id]):
        logging.error("BigQuery config (project_id, dataset_id, table_id) was not provided to write_to_bigquery.")
        return

    table_full_id = f"{project_id}.{dataset_id}.{table_id}"
    logging.info(f"Attempting BigQuery Write to: {table_full_id} (Source: {source}) with {len(normalized_data)} rows.")

    try:
        # Initialize the client with the project ID
        client = bigquery.Client(project=project_id)
        
        # Create dataset and table references directly without string parsing
        dataset_ref = client.dataset(dataset_id)
        table_ref = dataset_ref.table(table_id)
        
        # Get the table or create it if it doesn't exist
        try:
            logging.info(f"Getting BigQuery table object using dataset_ref.table approach")
            table = client.get_table(table_ref)
            logging.info(f"Successfully got table object: {table.project}.{table.dataset_id}.{table.table_id}")
        except Exception as e:
            logging.error(f"Failed to get table: {str(e)}")
            return False

        # Log immediately before insert
        logging.info(f"Preparing to insert {len(normalized_data)} rows into table: {table.project}.{table.dataset_id}.{table.table_id}")
        errors = [] # Initialize errors list
        insert_exception = None
        try:
            # --- Specific try block for insert_rows_json ---
            logging.info(f"Calling insert_rows_json with table ref: {table.project}.{table.dataset_id}.{table.table_id}")
            errors = client.insert_rows_json(table, normalized_data)
            logging.info(f"insert_rows_json call completed successfully")
            # --- End specific try block ---
        except Exception as insert_err:
            insert_exception = insert_err
            logging.error(f"Exception from insert_rows_json: {str(insert_err)}", exc_info=True)
            # Create a synthetic error entry to ensure we don't report success
            errors = [{'index': -1, 'errors': [{'reason': 'exception', 'message': str(insert_err)}]}]

        # Explicitly log the errors variable content
        logging.info(f"BigQuery insert errors variable content: {errors}")

        if errors:
            # Log the detailed errors returned by BigQuery
            logging.error(f"BigQuery Insert Errors for {table.project}.{table.dataset_id}.{table.table_id} (Source: {source}):")
            for error in errors:
                logging.error(f"  Row index {error.get('index', '?')}: {error.get('errors')}")
            # Return False to indicate failure
            return False
        else:
            logging.info(f"Successfully inserted {len(normalized_data)} rows into {table.project}.{table.dataset_id}.{table.table_id} from {source}.")
            # Return True to indicate success
            return True

    except Exception as e:
        # Log the full exception for BigQuery errors
        logging.error(f"Outer BigQuery Write Exception for {table_full_id} (Source: {source}): {str(e)}", exc_info=True)
        return False

def save_normalized_to_gcs(bucket_name, raw_file_name, normalized_data):
    """Save normalized data back to GCS under the 'normalized/' prefix."""
    if not normalized_data:
        logging.info(f"No normalized data to save to GCS for {raw_file_name}.")
        return

    # Initialize normalized_file_name to handle potential errors
    normalized_file_name = f"normalized/error/unknown_path_{os.path.basename(raw_file_name)}" 
    gcs_dest_path = f"gs://{bucket_name}/{normalized_file_name}"

    try:
        # Construct the destination path
        path_parts = raw_file_name.split('/')
        if len(path_parts) > 1 and path_parts[0] == 'raw':
            source = path_parts[1]
            base_filename = path_parts[-1]
            normalized_file_name = f"normalized/{source}/{base_filename}"
            gcs_dest_path = f"gs://{bucket_name}/{normalized_file_name}"
        else:
            logging.warning(f"Raw file path '{raw_file_name}' has unexpected format. Saving to default error path: {gcs_dest_path}")

        logging.info(f"Attempting GCS Save: {gcs_dest_path}")
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(normalized_file_name)

        logging.info(f"Uploading {len(normalized_data)} normalized items to {gcs_dest_path}")
        blob.upload_from_string(
            json.dumps(normalized_data, indent=2),
            content_type='application/json'
        )

        logging.info(f"Successfully saved normalized data to {gcs_dest_path}")

    except Exception as e:
        # Log the full exception for Cloud Storage errors
        logging.error(f"GCS Save Error for {gcs_dest_path}: {str(e)}", exc_info=True)
