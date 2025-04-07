import pandas as pd
from google.cloud import bigquery
from google.cloud import storage
import joblib
import logging
import tempfile
import os

# Import configuration
from . import config 

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_data_from_bigquery(limit=None):
    """Loads normalized threat data from the configured BigQuery table.

    Args:
        limit (int, optional): Maximum number of rows to load. Defaults to None (load all).

    Returns:
        pandas.DataFrame: DataFrame containing the normalized threat data.
                          Returns an empty DataFrame if the table is empty or an error occurs.
    """
    client = bigquery.Client(project=config.PROJECT_ID)
    query = f"SELECT * FROM `{config.NORMALIZED_TABLE_FQN}`"
    if limit:
        query += f" LIMIT {limit}"
    
    logger.info(f"Loading data from BigQuery table: {config.NORMALIZED_TABLE_FQN}")
    try:
        # Use the basic to_dataframe() method without type handling arguments
        # This ensures compatibility with all versions of google-cloud-bigquery
        df = client.query(query).to_dataframe(create_bqstorage_client=True)
        logger.info(f"Successfully loaded {len(df)} rows from BigQuery.")
        # Ensure 'tags' column exists and is treated as object type for potential list/string processing
        if 'tags' not in df.columns:
            df['tags'] = pd.Series([[] for _ in range(len(df))], dtype='object')
        else:
            # Handle potential None values if any
            df['tags'] = df['tags'].apply(lambda x: x if x is not None else [])
        return df
    except Exception as e:
        logger.error(f"Error loading data from BigQuery: {e}", exc_info=True)
        # Return an empty DataFrame with expected columns if possible, or just empty
        # This helps downstream code handle errors gracefully
        # You might want to define expected columns more explicitly
        return pd.DataFrame() 

def save_model_to_gcs(model, gcs_path):
    """Saves a trained model object to Google Cloud Storage using joblib.

    Args:
        model: The trained model object (e.g., a scikit-learn model).
        gcs_path (str): The GCS path (gs://bucket-name/path/to/model.joblib).
    """
    try:
        # Parse bucket name and blob path from gcs_path
        if not gcs_path.startswith("gs://"):
            raise ValueError("GCS path must start with gs://")
        path_parts = gcs_path.replace("gs://", "").split("/", 1)
        bucket_name = path_parts[0]
        blob_name = path_parts[1]

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)

        # Save model to a temporary local file first
        with tempfile.NamedTemporaryFile(delete=False, suffix=".joblib") as temp_file:
            local_path = temp_file.name
            joblib.dump(model, local_path)
        
        # Upload the temporary file to GCS
        logger.info(f"Uploading model to {gcs_path}...")
        blob.upload_from_filename(local_path)
        logger.info("Model successfully saved to GCS.")

        # Clean up the temporary file
        os.remove(local_path)

    except Exception as e:
        logger.error(f"Error saving model to GCS: {e}", exc_info=True)
        raise # Re-raise the exception to signal failure

def load_model_from_gcs(gcs_path):
    """Loads a model object from Google Cloud Storage.

    Args:
        gcs_path (str): The GCS path (gs://bucket-name/path/to/model.joblib).

    Returns:
        The loaded model object.
    """
    try:
        # Parse bucket name and blob path
        if not gcs_path.startswith("gs://"):
            raise ValueError("GCS path must start with gs://")
        path_parts = gcs_path.replace("gs://", "").split("/", 1)
        bucket_name = path_parts[0]
        blob_name = path_parts[1]

        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)

        # Download model to a temporary local file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".joblib") as temp_file:
            local_path = temp_file.name
            logger.info(f"Downloading model from {gcs_path}...")
            blob.download_to_filename(local_path)
        
        # Load model from the temporary file
        logger.info("Loading model from temporary file...")
        model = joblib.load(local_path)
        logger.info("Model successfully loaded from GCS.")

        # Clean up the temporary file
        os.remove(local_path)

        return model

    except Exception as e:
        logger.error(f"Error loading model from GCS: {e}", exc_info=True)
        raise # Re-raise the exception
