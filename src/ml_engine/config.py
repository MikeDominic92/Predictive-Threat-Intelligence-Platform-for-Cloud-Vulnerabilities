import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- GCP Configuration ---
PROJECT_ID = os.getenv("PROJECT_ID")
DATASET_ID = os.getenv("DATASET_ID")
TABLE_ID = os.getenv("TABLE_ID")
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")

if not all([PROJECT_ID, DATASET_ID, TABLE_ID, GCS_BUCKET_NAME]):
    raise ValueError(
        "Please set PROJECT_ID, DATASET_ID, TABLE_ID, and GCS_BUCKET_NAME " 
        "environment variables (e.g., in a .env file)"
    )

NORMALIZED_TABLE_FQN = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
MODEL_GCS_PATH = f"gs://{GCS_BUCKET_NAME}/ml_models/indicator_risk_model.joblib"
PREPROCESSOR_GCS_PATH = f"gs://{GCS_BUCKET_NAME}/ml_models/indicator_risk_preprocessor.joblib" # Path for the feature preprocessor
MODEL_LOCAL_PATH = "indicator_risk_model.joblib" # Temporary local path for saving/loading

# --- Feature Engineering Configuration ---
# Define which columns from BigQuery will be used as features
# Note: 'tags' might need special handling (e.g., TF-IDF, multi-hot encoding)
# Start simple: indicator_type, source
CATEGORICAL_FEATURES = [
    "indicator_type",
    "source", 
    # 'tags' # Add later after assessing complexity
]

NUMERICAL_FEATURES = [
    # Add numerical features if available, e.g., 
    # 'pulse_count', 'reference_count' - Requires data analysis
]

ALL_FEATURES = CATEGORICAL_FEATURES + NUMERICAL_FEATURES

# --- Target Variable Definition ---
# How we define 'risk'. This is crucial and often requires domain expertise.
# Simple initial approach: If 'malware' is in tags, consider it high risk.
# We will refine this later.
TARGET_VARIABLE = "risk_label" # Name of the column we will create
HIGH_RISK_TAGS = ["malware", "apt", "botnet", "ransomware", "phishing"] # Example tags indicating high risk

# --- Model Configuration ---
MODEL_TYPE = "RandomForestClassifier" # Could be changed later
TEST_SIZE = 0.2 # 20% of data for testing
RANDOM_STATE = 42 # For reproducibility
