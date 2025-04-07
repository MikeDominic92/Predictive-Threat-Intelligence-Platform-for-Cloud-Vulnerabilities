import logging
import sys
import os
import pandas as pd
import argparse

# Ensure the src directory is in the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(script_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from ml_engine import utils, predictor, config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def predict_indicator_risk(indicator_type, source, tags=None):
    """
    Predicts the risk level of threat indicators using the trained model.
    
    Args:
        indicator_type (str): Type of the indicator (e.g., 'domain', 'ip', 'url')
        source (str): Source of the indicator (e.g., 'alienvault', 'virustotal')
        tags (list, optional): List of tags associated with the indicator. Defaults to None.
        
    Returns:
        dict: Dictionary containing the prediction result and confidence
    """
    logger.info(f"Predicting risk for indicator - Type: {indicator_type}, Source: {source}")
    
    # Create a DataFrame with a single row for our indicator
    indicator_data = {
        'indicator_type': [indicator_type],
        'source': [source],
        'tags': [tags if tags else []]
    }
    df_indicator = pd.DataFrame(indicator_data)
    
    # Load model and preprocessor from GCS
    try:
        logger.info(f"Loading model from {config.MODEL_GCS_PATH}...")
        model = utils.load_model_from_gcs(config.MODEL_GCS_PATH)
        
        logger.info(f"Loading preprocessor from {config.PREPROCESSOR_GCS_PATH}...")
        preprocessor = utils.load_model_from_gcs(config.PREPROCESSOR_GCS_PATH)
    except Exception as e:
        logger.error(f"Error loading model or preprocessor: {e}")
        return {"error": "Failed to load model or preprocessor", "details": str(e)}
    
    # Make prediction
    try:
        # Use only the features our model was trained on
        X_new = df_indicator[config.ALL_FEATURES]
        
        # Get prediction
        prediction = predictor.predict_risk(X_new, preprocessor, model)
        
        # Get prediction probability if model supports it
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(preprocessor.transform(X_new))
            confidence = probabilities[0][int(prediction[0])]
        else:
            confidence = None
            
        risk_level = "HIGH" if prediction[0] == 1 else "LOW"
        
        result = {
            "indicator_type": indicator_type,
            "source": source,
            "risk_prediction": risk_level,
            "confidence": f"{confidence:.2f}" if confidence is not None else "N/A"
        }
        
        logger.info(f"Prediction result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        return {"error": "Failed to make prediction", "details": str(e)}

def main():
    """Command-line interface for the prediction script."""
    parser = argparse.ArgumentParser(description='Predict risk level for threat indicators.')
    parser.add_argument('--indicator-type', required=True, help='Type of the indicator (e.g., domain, ip, url)')
    parser.add_argument('--source', required=True, help='Source of the indicator (e.g., alienvault, virustotal)')
    parser.add_argument('--tags', nargs='*', help='Tags associated with the indicator')
    
    args = parser.parse_args()
    
    result = predict_indicator_risk(args.indicator_type, args.source, args.tags)
    
    # Pretty print the result
    print("\n===== INDICATOR RISK PREDICTION =====")
    for key, value in result.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    print("=====================================\n")

if __name__ == "__main__":
    main()
