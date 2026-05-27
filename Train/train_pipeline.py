import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

sys.path.append(str(Path(__file__).parent.parent))
from parser.feature_engineering import extract_behavioral_features

def main():
    root = Path(__file__).resolve().parent.parent
    dataset_path = root / 'Datasets' / 'LMD-2023-dataset.csv'
    
    logging.info(f"Loading dataset from {dataset_path}")
    df_raw = pd.read_csv(dataset_path, low_memory=False)
    df_raw = df_raw[df_raw['Label'] != 2].copy()
    
    df_behavioral = extract_behavioral_features(df_raw)
    
    y = df_behavioral['Label']
    X = df_behavioral.drop(columns=['Label', 'ProcessId', '_log_file'], errors='ignore')
    
    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    
    joblib.dump(scaler, root / 'models' / 'preprocessor.joblib')
    logging.info("Saved preprocessor to models/preprocessor.joblib")
    
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    logging.info("Training RandomForestClassifier...")
    rf.fit(X_train, y_train)
    
    joblib.dump(rf, root / 'models' / 'modelo_ransomware.joblib')
    logging.info("Saved model to models/modelo_ransomware.joblib")
    
    y_pred = rf.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Also save training columns structure
    metadata = {'features': list(X.columns)}
    import json
    with open(root / 'models' / 'metadata.json', 'w') as f:
        json.dump(metadata, f)
    logging.info("Saved metadata.json")

if __name__ == '__main__':
    main()
