import logging
import sys
import os

# Ensure the src directory is in the Python path
# This allows importing modules from ml_engine when running the script directly
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(script_dir) 
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from ml_engine import utils, feature_engineering, predictor, config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function to run the model training pipeline."""
    logger.info("--- Starting Indicator Risk Model Training Pipeline ---")

    # 1. Load Data
    logger.info("Step 1: Loading normalized data from BigQuery...")
    # Consider adding a limit= argument for testing, e.g., limit=10000
    df = utils.load_data_from_bigquery() 
    if df.empty:
        logger.error("Failed to load data or data is empty. Exiting pipeline.")
        return
    logger.info(f"Loaded {len(df)} records.")

    # 2. Create Target Variable
    logger.info("Step 2: Creating target variable...")
    y = feature_engineering.create_target_variable(df)
    if y.empty:
        logger.error("Failed to create target variable. Exiting pipeline.")
        return

    # 3. Preprocess Features
    logger.info("Step 3: Preprocessing features...")
    X_processed, preprocessor = feature_engineering.preprocess_features(df, config.ALL_FEATURES)
    if X_processed.empty or preprocessor is None:
        logger.error("Failed to preprocess features. Exiting pipeline.")
        return
    logger.info(f"Features preprocessed. Shape: {X_processed.shape}")

    # 4. Train Model
    logger.info("Step 4: Training the model...")
    model = predictor.train_model(X_processed, y)
    if model is None:
        logger.error("Model training failed. Exiting pipeline.")
        return
    logger.info("Model training completed successfully.")

    # 5. Save Artifacts (Model and Preprocessor)
    logger.info("Step 5: Saving trained model and preprocessor to GCS...")
    try:
        utils.save_model_to_gcs(model, config.MODEL_GCS_PATH)
        logger.info(f"Model saved to {config.MODEL_GCS_PATH}")
        utils.save_model_to_gcs(preprocessor, config.PREPROCESSOR_GCS_PATH)
        logger.info(f"Preprocessor saved to {config.PREPROCESSOR_GCS_PATH}")
    except Exception as e:
        logger.error(f"Failed to save artifacts to GCS: {e}", exc_info=True)
        # Decide if you want to stop the whole process if saving fails
        # For now, just log the error.

    logger.info("--- Indicator Risk Model Training Pipeline Finished ---")

if __name__ == "__main__":
    # Ensure environment variables are loaded (config.py does this, but good practice)
    # from dotenv import load_dotenv
    # load_dotenv()
    main()
