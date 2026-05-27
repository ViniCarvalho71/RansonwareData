import shap
import joblib
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_shap_analysis(X_sample: pd.DataFrame, model_path: Path):
    logging.info("Running SHAP analysis...")
    rf = joblib.load(model_path)
    
    explainer = shap.TreeExplainer(rf)
    shap_values = explainer.shap_values(X_sample)
    
    if isinstance(shap_values, list):
        sv = shap_values[1] # Assumes index 1 is ransomware
    elif isinstance(shap_values, np.ndarray) and len(shap_values.shape) == 3:
        sv = shap_values[:, :, 1]
    else:
        sv = shap_values
        
    return sv

def run_lime_analysis(X_train: np.ndarray, feature_names: list, model_path: Path, instance_to_explain: np.ndarray):
    from lime.lime_tabular import LimeTabularExplainer
    logging.info("Running LIME analysis...")
    rf = joblib.load(model_path)
    
    lime_explainer = LimeTabularExplainer(
        X_train,
        feature_names=feature_names,
        class_names=["0", "1"],
        mode="classification"
    )
    
    exp = lime_explainer.explain_instance(
        instance_to_explain,
        rf.predict_proba,
        num_features=10
    )
    
    return exp.as_list()

def main():
    root = Path(__file__).resolve().parent.parent
    models_dir = root / 'models'
    
    # Load sample inference data just to test
    df_inf = pd.read_csv(root / 'logs' / 'inference_results.csv')
    
    with open(models_dir / 'metadata.json', 'r') as f:
        meta = json.load(f)
    train_features = meta['features']
    
    # Needs scaling to match training
    scaler = joblib.load(models_dir / 'preprocessor.joblib')
    
    X = df_inf.drop(columns=['Label', 'ProcessId', '_log_file', 'prob_ransomware', 'pred_label'], errors='ignore')
    for col in train_features:
        if col not in X.columns:
            X[col] = 0
            
    X = X[train_features]
    X_scaled = pd.DataFrame(scaler.transform(X), columns=X.columns)
    
    if len(X_scaled) > 0:
        sv = run_shap_analysis(X_scaled.iloc[:10], models_dir / 'modelo_ransomware.joblib')
        logging.info("SHAP values calculated successfully (first 10 instances)")

if __name__ == "__main__":
    main()