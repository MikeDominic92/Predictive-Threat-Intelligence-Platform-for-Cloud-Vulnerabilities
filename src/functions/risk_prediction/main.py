import os
import logging
import json
import sys
import pandas as pd
from google.cloud import storage
import functions_framework
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set up the path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.abspath(os.path.join(current_dir, '../../'))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Import our ml modules
from ml_engine import utils, predictor, config

# Define global variables to cache the model and preprocessor
model = None
preprocessor = None

def load_models():
    """
    Loads the ML model and preprocessor from GCS.
    Uses global variables for caching to improve performance on subsequent invocations.
    """
    global model, preprocessor
    
    if model is None or preprocessor is None:
        try:
            logger.info(f"Loading model from {config.MODEL_GCS_PATH}...")
            model = utils.load_model_from_gcs(config.MODEL_GCS_PATH)
            
            logger.info(f"Loading preprocessor from {config.PREPROCESSOR_GCS_PATH}...")
            preprocessor = utils.load_model_from_gcs(config.PREPROCESSOR_GCS_PATH)
            
            logger.info("Model and preprocessor loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading model or preprocessor: {e}")
            raise RuntimeError(f"Failed to load ML models: {str(e)}")
    else:
        logger.info("Using cached model and preprocessor.")
    
    return model, preprocessor

def validate_request(request_json):
    """
    Validates the incoming request data.
    
    Args:
        request_json (dict): The JSON request payload
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not request_json:
        return False, "Request body is empty or not valid JSON"
    
    required_fields = ['indicator_type', 'source']
    missing_fields = [field for field in required_fields if field not in request_json]
    
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    valid_indicator_types = ['ip', 'domain', 'url', 'file_hash', 'email']
    if request_json['indicator_type'] not in valid_indicator_types:
        return False, f"Invalid indicator_type. Must be one of: {', '.join(valid_indicator_types)}"
    
    valid_sources = ['alienvault', 'virustotal', 'mandiant', 'recorded_future', 'other']
    if request_json['source'] not in valid_sources:
        return False, f"Invalid source. Must be one of: {', '.join(valid_sources)}"
    
    return True, ""

def predict_risk(indicator_data):
    """
    Makes a prediction using the loaded model and preprocessor.
    
    Args:
        indicator_data (dict): Dictionary with indicator data
        
    Returns:
        dict: Dictionary with prediction results
    """
    try:
        # Create a DataFrame from the indicator data
        indicator_df = pd.DataFrame({
            'indicator_type': [indicator_data.get('indicator_type')],
            'source': [indicator_data.get('source')],
            'tags': [indicator_data.get('tags', [])]
        })
        
        # Use only the features our model was trained on
        X_new = indicator_df[config.ALL_FEATURES]
        
        # Get model and preprocessor
        model, preprocessor = load_models()
        
        # Make prediction
        prediction = predictor.predict_risk(X_new, preprocessor, model)
        
        # Get prediction probability if model supports it
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(preprocessor.transform(X_new))
            confidence = float(probabilities[0][int(prediction[0])])
        else:
            confidence = None
            
        risk_level = "HIGH" if prediction[0] == 1 else "LOW"
        
        # Generate feature importance if applicable
        feature_importance = None
        if hasattr(model, 'feature_importances_'):
            # Get feature names from preprocessor if available
            if hasattr(preprocessor, 'get_feature_names_out'):
                try:
                    feature_names = preprocessor.get_feature_names_out()
                    # Limit to top 5 features for brevity
                    top_indices = model.feature_importances_.argsort()[-5:][::-1]
                    feature_importance = {
                        str(feature_names[i]): float(model.feature_importances_[i]) 
                        for i in top_indices
                    }
                except:
                    pass
        
        result = {
            "indicator": {
                "type": indicator_data.get('indicator_type'),
                "value": indicator_data.get('value', 'N/A'),
                "source": indicator_data.get('source'),
                "tags": indicator_data.get('tags', [])
            },
            "prediction": {
                "risk_level": risk_level,
                "confidence": round(confidence * 100, 2) if confidence is not None else None,
                "feature_importance": feature_importance
            },
            "model_info": {
                "model_type": model.__class__.__name__,
                "version": "1.0"
            }
        }
        
        return result
    
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        raise RuntimeError(f"Prediction failed: {str(e)}")

@functions_framework.http
def predict_indicator_risk(request):
    """
    Cloud Function entry point for threat indicator risk prediction.
    
    Args:
        request (flask.Request): HTTP request object.
        
    Returns:
        The response text or any set of values that can be turned into a
        Response object using `make_response`.
    """
    # Set CORS headers
    if request.method == 'OPTIONS':
        # Allows GET requests from any origin with the Content-Type
        # header and caches preflight response for 3600s
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '3600'
        }
        return ('', 204, headers)
    
    headers = {
        'Access-Control-Allow-Origin': '*'
    }
    
    try:
        # Parse the request
        request_json = request.get_json(silent=True)
        
        # Validate request
        is_valid, error_message = validate_request(request_json)
        if not is_valid:
            return (json.dumps({"error": error_message}), 400, headers)
        
        # Make prediction
        result = predict_risk(request_json)
        
        # Return prediction result
        return (json.dumps(result), 200, headers)
    
    except RuntimeError as re:
        logger.error(f"Runtime error: {str(re)}")
        return (json.dumps({"error": str(re)}), 500, headers)
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return (json.dumps({"error": "An unexpected error occurred"}), 500, headers)

# For local testing
if __name__ == "__main__":
    # Sample request data
    test_data = {
        "indicator_type": "domain",
        "value": "example.com",
        "source": "alienvault",
        "tags": ["suspicious", "phishing"]
    }
    
    # Make prediction
    try:
        result = predict_risk(test_data)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")
