# main.py - Cloud Functions entry point for Threat Normalization

# Import the specific function needed from the module within the src package
from src.functions.data_processing.threat_normalizer import normalize_threat_data

# Define the function that Cloud Functions will call
def process_gcs_event(event, context):
    """Entry point function triggered by GCS events.

    Args:
         event (dict): Event payload.
         context (google.cloud.functions.Context): Metadata for the event.
    """
    # Pass the event and context directly to the imported orchestrator function
    # Note: The imported function should handle logging and errors internally
    return normalize_threat_data(event, context)

# Logging configuration is typically handled by the Cloud Functions environment
# or can be initialized within the normalize_threat_data function if needed globally.
