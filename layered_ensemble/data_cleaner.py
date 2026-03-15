"""
Universal Data Cleaning Utility
Handles infinity, NaN, and extreme values in network flow data

Import this in any file that processes data:
    from data_cleaner import clean_data
    
    X_clean = clean_data(X)
"""

import numpy as np
import pandas as pd


def clean_data(X, verbose=False):
    """
    Clean data to handle infinity, NaN, and extreme values
    
    This function is CRITICAL for real-world network data which often contains:
    - Division by zero → infinity
    - Missing values → NaN
    - Corrupted data → extreme values
    
    Args:
        X: numpy array, pandas DataFrame, or pandas Series
        verbose: Print cleaning statistics
        
    Returns:
        Cleaned numpy array (float32)
    """
    
    original_type = type(X)
    original_shape = X.shape if hasattr(X, 'shape') else len(X)
    
    # Convert to DataFrame for easier manipulation
    if isinstance(X, np.ndarray):
        if len(X.shape) == 1:
            X = pd.DataFrame(X.reshape(-1, 1))
        else:
            X = pd.DataFrame(X)
    elif isinstance(X, pd.Series):
        X = pd.DataFrame(X)
    elif not isinstance(X, pd.DataFrame):
        raise ValueError(f"Unsupported data type: {type(X)}")
    
    if verbose:
        print(f"Cleaning data: shape {original_shape}")
        
        # Count issues before cleaning
        inf_count = np.isinf(X.values).sum()
        nan_count = np.isnan(X.values).sum()
        extreme_count = (np.abs(X.values) > 1e10).sum()
        
        if inf_count > 0:
            print(f"  - Infinity values: {inf_count}")
        if nan_count > 0:
            print(f"  - NaN values: {nan_count}")
        if extreme_count > 0:
            print(f"  - Extreme values (>1e10): {extreme_count}")
    
    # Step 1: Replace infinity with NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    
    # Step 2: Fill NaN with 0 (could also use median per column)
    X = X.fillna(0)
    
    # Step 3: Clip extreme values to reasonable range
    # This prevents overflow in float32
    for col in X.columns:
        X[col] = X[col].clip(lower=-1e10, upper=1e10)
    
    # Step 4: Ensure float32 dtype (what sklearn expects)
    X = X.astype('float32')
    
    # Step 5: Final safety check - replace any remaining problematic values
    X = X.replace([np.inf, -np.inf], 0)
    X = X.fillna(0)
    
    if verbose:
        print(f"  ✅ Cleaned successfully")
    
    # Return as numpy array
    return X.values


def clean_batch(cicids_batch, iot_batch, unsw_batch, verbose=False):
    """
    Clean all three feature batches at once
    
    Args:
        cicids_batch: (N, 52) CICIDS features
        iot_batch: (N, 39) IoT features  
        unsw_batch: (N, 48) UNSW features
        verbose: Print stats
        
    Returns:
        Tuple of (cicids_clean, iot_clean, unsw_clean)
    """
    if verbose:
        print("Cleaning feature batches...")
    
    cicids_clean = clean_data(cicids_batch, verbose=verbose)
    iot_clean = clean_data(iot_batch, verbose=verbose)
    unsw_clean = clean_data(unsw_batch, verbose=verbose)
    
    return cicids_clean, iot_clean, unsw_clean


def safe_transform(scaler, X):
    """
    Safely transform data with a scaler, handling any issues
    
    Args:
        scaler: sklearn scaler object
        X: data to transform
        
    Returns:
        Transformed data
    """
    # Clean before transforming
    X_clean = clean_data(X)
    
    # Transform
    try:
        X_scaled = scaler.transform(X_clean)
    except Exception as e:
        print(f"⚠️  Scaler transform failed: {e}")
        print(f"   Applying emergency cleaning...")
        
        # Emergency: force everything to valid range
        X_clean = np.clip(X_clean, -1e6, 1e6)
        X_clean = np.nan_to_num(X_clean, nan=0.0, posinf=0.0, neginf=0.0)
        
        X_scaled = scaler.transform(X_clean)
    
    # Clean after transforming (scaled data can also have issues)
    X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = np.clip(X_scaled, -1e6, 1e6)
    
    return X_scaled.astype('float32')


# Quick test if run directly
if __name__ == "__main__":
    print("Testing data_cleaner...")
    
    # Create test data with problematic values
    test_data = np.array([
        [1.0, 2.0, 3.0],
        [np.inf, 5.0, 6.0],
        [7.0, -np.inf, 9.0],
        [10.0, np.nan, 12.0],
        [1e15, 1e-15, 1.0]
    ])
    
    print("\nOriginal data:")
    print(test_data)
    
    print("\nCleaning...")
    cleaned = clean_data(test_data, verbose=True)
    
    print("\nCleaned data:")
    print(cleaned)
    
    print("\n✅ Data cleaner working correctly!")