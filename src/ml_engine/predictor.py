import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import logging
import matplotlib.pyplot as plt
import seaborn as sns

# Import configuration and utilities
from . import config
from . import utils # Although not directly used here, good practice to import sibling modules if needed

logger = logging.getLogger(__name__)

def train_model(X, y):
    """Trains a classification model on the provided features and target.

    Splits data, trains the model specified in config, evaluates on the test set, 
    and logs performance metrics.

    Args:
        X (pd.DataFrame): Processed feature DataFrame.
        y (pd.Series): Target variable Series.

    Returns:
        object: The trained scikit-learn model object.
                Returns None if training fails or data is unsuitable.
    """
    if X.empty or y.empty or len(X) != len(y):
        logger.error("Input data X or y is empty or mismatched in length. Cannot train model.")
        return None
    if y.nunique() < 2:
         logger.error(f"Target variable has {y.nunique()} unique values. Need at least 2 for classification. Cannot train model.")
         return None

    logger.info(f"Splitting data into training and testing sets (Test size: {config.TEST_SIZE}).")
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=config.TEST_SIZE, 
            random_state=config.RANDOM_STATE, 
            stratify=y # Stratify ensures proportion of classes is maintained in splits
        )
    except ValueError as e:
        logger.error(f"Error during train/test split, possibly due to insufficient samples for stratification: {e}")
        # Fallback without stratification if needed, though less ideal
        logger.warning("Attempting train/test split without stratification.")
        try:
             X_train, X_test, y_train, y_test = train_test_split(
                X, y, 
                test_size=config.TEST_SIZE, 
                random_state=config.RANDOM_STATE
            )
        except Exception as split_err:
             logger.error(f"Failed to split data even without stratification: {split_err}")
             return None

    logger.info(f"Training a {config.MODEL_TYPE} model...")
    
    # --- Model Selection (Expandable) ---
    # Currently hardcoded to RandomForest based on config, but could be made dynamic
    if config.MODEL_TYPE == "RandomForestClassifier":
        # Add class_weight='balanced' if dealing with imbalanced datasets
        model = RandomForestClassifier(random_state=config.RANDOM_STATE, class_weight='balanced')
    # Add other model types here with elif if needed
    # elif config.MODEL_TYPE == "LogisticRegression":
    #     model = LogisticRegression(random_state=config.RANDOM_STATE, class_weight='balanced')
    else:
        logger.error(f"Unsupported model type specified in config: {config.MODEL_TYPE}")
        return None
    # --- End Model Selection ---

    try:
        model.fit(X_train, y_train)
        logger.info("Model training complete.")
    except Exception as e:
        logger.error(f"Error during model fitting: {e}", exc_info=True)
        return None

    # --- Evaluation ---
    logger.info("Evaluating model on the test set...")
    try:
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        matrix = confusion_matrix(y_test, y_pred)
        
        logger.info(f"Test Set Accuracy: {accuracy:.4f}")
        logger.info(f"Test Set Classification Report:\n{report}")
        logger.info(f"Test Set Confusion Matrix:\n{matrix}")
        
        # Optional: Plot confusion matrix (consider saving to a file/GCS if running in a non-interactive environment)
        # try:
        #     plt.figure(figsize=(8, 6))
        #     sns.heatmap(matrix, annot=True, fmt="d", cmap="Blues", 
        #                 xticklabels=model.classes_, yticklabels=model.classes_)
        #     plt.xlabel("Predicted Label")
        #     plt.ylabel("True Label")
        #     plt.title("Confusion Matrix")
        #     plt.show() # Or plt.savefig('confusion_matrix.png')
        # except Exception as plot_err:
        #     logger.warning(f"Could not generate confusion matrix plot: {plot_err}")
            
    except Exception as e:
        logger.error(f"Error during model evaluation: {e}", exc_info=True)
        # Return the model anyway, but log that evaluation failed

    return model

def predict_risk(X_new, preprocessor, model):
    """Makes risk predictions on new data using a trained model and preprocessor.

    Args:
        X_new (pd.DataFrame): DataFrame of new indicators with the same original features 
                              used for training (before preprocessing).
        preprocessor (sklearn.compose.ColumnTransformer): The *fitted* preprocessor object 
                                                        from the training phase.
        model: The *trained* scikit-learn model object.

    Returns:
        np.ndarray: An array of predictions (e.g., 0 or 1 for risk level).
                   Returns None if prediction fails.
    """
    if X_new.empty:
        logger.warning("Input DataFrame X_new is empty. No predictions to make.")
        return None
    if preprocessor is None or model is None:
        logger.error("Preprocessor or model is not provided or invalid. Cannot make predictions.")
        return None

    logger.info(f"Preprocessing {len(X_new)} new records for prediction...")
    try:
        # Ensure X_new has the same columns the preprocessor was trained on
        # Note: Column order matters for ColumnTransformer unless remainder='passthrough' 
        # and original columns were selected explicitly. Careful handling needed.
        # A safer approach is to ensure X_new has exactly the columns 
        # preprocessor.feature_names_in_ before transform.
        
        # Apply the *fitted* preprocessor (DO NOT refit)
        X_new_processed_np = preprocessor.transform(X_new)
        
        # Convert to DataFrame with correct feature names if needed (depends on model input needs)
        # This assumes the model expects feature names, which isn't always true, but good practice.
        try:
            feature_names = preprocessor.get_feature_names_out()
            X_new_processed = pd.DataFrame(X_new_processed_np, columns=feature_names, index=X_new.index)
        except AttributeError: # Handle older scikit-learn versions if necessary
             logger.warning("Could not get feature names from preprocessor. Using NumPy array for prediction.")
             X_new_processed = X_new_processed_np
             
    except Exception as e:
        logger.error(f"Error during preprocessing of new data: {e}", exc_info=True)
        return None

    logger.info("Making predictions on preprocessed data...")
    try:
        predictions = model.predict(X_new_processed)
        logger.info(f"Successfully generated {len(predictions)} predictions.")
        return predictions
    except Exception as e:
        logger.error(f"Error during model prediction: {e}", exc_info=True)
        return None
