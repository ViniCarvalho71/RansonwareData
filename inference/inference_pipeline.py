import pandas as pd
import joblib
import json
import logging
from pathlib import Path
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

sys.path.append(str(Path(__file__).parent.parent))
from parser.evtx_parser import parse_all_evtx
from parser.feature_engineering import extract_behavioral_features

def main():
    root = Path(__file__).resolve().parent.parent
    logs_dir = root / 'RansomwaresLogs'
    models_dir = root / 'models'
    
    logging.info(f"Parsing logs from {logs_dir}")
    df_raw = parse_all_evtx(logs_dir)
    
    df_behavioral = extract_behavioral_features(df_raw)
    
    logging.info("Loading artifacts")
    rf = joblib.load(models_dir / 'modelo_ransomware.joblib')
    scaler = joblib.load(models_dir / 'preprocessor.joblib')
    with open(models_dir / 'metadata.json', 'r') as f:
        meta = json.load(f)
    
    train_features = meta['features']
    
    X = df_behavioral.drop(columns=['Label', 'ProcessId', '_log_file'], errors='ignore')
    
    # Align columns
    for col in train_features:
        if col not in X.columns:
            X[col] = 0
    X = X[train_features]
    
    X_scaled = pd.DataFrame(scaler.transform(X), columns=X.columns)
    
    logging.info("Predicting...")
    # Get probabilities
    if hasattr(rf, 'predict_proba'):
        probs = rf.predict_proba(X_scaled)
        classes = list(getattr(rf, 'classes_', [0, 1]))
        pos_index = classes.index(1) if 1 in classes else classes[-1]
        probs_ransomware = probs[:, pos_index]
    else:
        probs_ransomware = rf.predict(X_scaled)
        
    df_behavioral['prob_ransomware'] = probs_ransomware
    df_behavioral['pred_label'] = (probs_ransomware > 0.15).astype(int)
    
    summary = df_behavioral[['ProcessId', 'prob_ransomware', 'pred_label', 'total_events']].copy()
    
    out_dir = root / 'logs'
    out_dir.mkdir(exist_ok=True)
    out_csv = out_dir / 'inference_results.csv'
    
    df_behavioral.to_csv(out_csv, index=False)
    logging.info(f"Results saved to {out_csv}")
    
    ransomware_detected = (summary['pred_label'] == 1).sum()
    logging.info(f"Ransomware behaviors detected: {ransomware_detected} / {len(summary)}")

if __name__ == '__main__':
    main()
