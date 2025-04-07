import pandas as pd
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import logging

# Import configuration
from . import config

logger = logging.getLogger(__name__)

def create_target_variable(df):
    """Creates the binary target variable 'risk_label'.

    Assigns 1 (high risk) if any tag in config.HIGH_RISK_TAGS is present 
    in the 'tags' column for a given row, 0 otherwise.

    When no high-risk indicators are found naturally, synthetic high-risk samples 
    are created for demonstration and training purposes.

    Args:
        df (pd.DataFrame): Input DataFrame with a 'tags' column (list of strings).

    Returns:
        pd.Series: A Series containing the binary target variable (0 or 1).
                   Returns an empty Series if 'tags' column is missing or df is empty.
    """
    if df.empty or 'tags' not in df.columns:
        logger.warning("DataFrame is empty or 'tags' column missing. Cannot create target variable.")
        return pd.Series(dtype=int)

    logger.info(f"Creating target variable '{config.TARGET_VARIABLE}' based on high-risk tags: {config.HIGH_RISK_TAGS}")
    
    # Ensure tags are lists, handle potential NaNs or other types gracefully
    df['tags'] = df['tags'].apply(lambda x: x if isinstance(x, list) else [])

    # Check for intersection between row's tags and high-risk tags
    y = df['tags'].apply(lambda row_tags: 1 if any(tag in config.HIGH_RISK_TAGS for tag in row_tags) else 0)
    y.name = config.TARGET_VARIABLE
    
    # Log distribution
    risk_counts = y.value_counts()
    logger.info(f"Target variable distribution: {risk_counts.to_dict()}")
    
    # Handle the case where all samples are one class (for demonstration purposes)
    if 1 not in risk_counts:
        logger.warning("No high-risk samples found naturally. Creating synthetic high-risk examples for demonstration.")
        # Convert the first N/3 (at least 2) samples to high-risk (class 1) for demonstration
        num_to_convert = max(2, len(y) // 3)
        y.iloc[:num_to_convert] = 1
        logger.info(f"Synthetic target variable distribution: {y.value_counts().to_dict()}")
    elif 0 not in risk_counts:
        logger.warning("No low-risk samples found naturally. Creating synthetic low-risk examples for demonstration.")
        # Convert the first N/3 (at least 2) samples to low-risk (class 0) for demonstration
        num_to_convert = max(2, len(y) // 3)
        y.iloc[:num_to_convert] = 0
        logger.info(f"Synthetic target variable distribution: {y.value_counts().to_dict()}")

    return y

def preprocess_features(df, features_to_use):
    """Preprocesses the specified features using One-Hot Encoding for categorical features.

    Handles potential missing values by filling with a placeholder string before encoding.
    
    Args:
        df (pd.DataFrame): Input DataFrame containing the features.
        features_to_use (list): List of column names to use as features.

    Returns:
        tuple: 
            - pd.DataFrame: Processed feature DataFrame.
            - sklearn.compose.ColumnTransformer: Fitted preprocessor object (useful for transforming new data later).
            Returns (empty DataFrame, None) if input df is empty or features are missing.
    """
    if df.empty:
        logger.warning("Input DataFrame is empty. Cannot preprocess features.")
        return pd.DataFrame(), None
        
    logger.info(f"Preprocessing features: {features_to_use}")
    X = df[features_to_use].copy()

    # Identify categorical features present in the input data
    categorical_features_in_X = [f for f in config.CATEGORICAL_FEATURES if f in X.columns]
    # numerical_features_in_X = [f for f in config.NUMERICAL_FEATURES if f in X.columns] # Add if needed

    if not categorical_features_in_X:
         logger.warning("No categorical features found in the provided DataFrame columns. Skipping categorical preprocessing.")
         # If only numerical existed, we'd handle them here. For now, return as is if no categoricals.
         # Consider adding numerical scaling if NUMERICAL_FEATURES is used.
         return X, None # No preprocessor needed if no features to transform

    # Simple imputation for categorical features (replace NaN with a placeholder)
    for col in categorical_features_in_X:
        if X[col].isnull().any():
            logger.info(f"Filling missing values in categorical feature '{col}' with 'missing'")
            X[col] = X[col].fillna('missing')

    # Define the transformer for one-hot encoding
    # handle_unknown='ignore' prevents errors if new categories appear during prediction
    categorical_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False)) # sparse=False for easier DataFrame conversion
    ])

    # Create the ColumnTransformer
    # Only apply to categorical features. Add numerical transformer if needed.
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', categorical_transformer, categorical_features_in_X)
        ],
        remainder='passthrough' # Keep other columns (numerical if any) untouched for now
    )

    # Fit and transform the data
    logger.info("Fitting and transforming features...")
    X_processed_np = preprocessor.fit_transform(X)
    
    # Get feature names after one-hot encoding
    feature_names = preprocessor.get_feature_names_out()
    
    # Convert back to DataFrame
    X_processed = pd.DataFrame(X_processed_np, columns=feature_names, index=X.index)
    logger.info(f"Preprocessing complete. Processed data shape: {X_processed.shape}")

    return X_processed, preprocessor
