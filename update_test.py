import json

with open('c:/Projetos/RansonwareData/Tests/TestWithLogs.ipynb', 'r', encoding='utf-8') as f:
    nb = json.load(f)

for cell in nb['cells']:
    if cell['cell_type'] == 'code':
        source = ''.join(cell['source'])
        
        # Replace the model and dataset path logic
        if 'reliable_features =' in source and 'df_train = pd.read_csv' in source:
            cell['source'] = [
                "import joblib\n",
                "import sys\n",
                "sys.path.append('..')\n",
                "from parser.feature_engineering import extract_behavioral_features\n",
                "\n",
                "df_train_raw = pd.read_csv(DATASET_PATH, low_memory=False)\n",
                "df_train_raw = df_train_raw[df_train_raw['Label'] != 2].copy()\n",
                "\n",
                "print('Extracting baseline behavioral features...')\n",
                "df_train_behavioral = extract_behavioral_features(df_train_raw)\n",
                "X_train = df_train_behavioral.drop(columns=['Label', 'ProcessId', '_log_file'], errors='ignore')\n",
                "\n",
                "scaler = joblib.load(ROOT / 'Train' / 'preprocessor.joblib')\n",
                "X_train_scaled = pd.DataFrame(scaler.transform(X_train), columns=X_train.columns)\n"
            ]
            
        elif 'def parse_evtx_file(path):' in source:
            cell['source'] = [
                "import sys\n",
                "sys.path.append('..')\n",
                "from parser.evtx_parser import parse_all_evtx\n",
                "\n",
                "print('Parsing all EVTX files...')\n",
                "df_logs_raw = parse_all_evtx(LOGS_DIR)\n",
                "print('events:', len(df_logs_raw), 'columns:', len(df_logs_raw.columns))\n",
                "\n",
                "df_logs = extract_behavioral_features(df_logs_raw)\n",
                "df_logs.head()\n"
            ]
            
        elif 'X_logs = align_and_preprocess(df_logs)' in source:
            cell['source'] = [
                "from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, recall_score\n",
                "\n",
                "X_logs = df_logs.drop(columns=['Label', 'ProcessId', '_log_file'], errors='ignore')\n",
                "# Align missing columns with train features\n",
                "for col in X_train.columns:\n",
                "    if col not in X_logs.columns:\n",
                "        X_logs[col] = 0\n",
                "X_logs = X_logs[X_train.columns]\n",
                "X_logs_scaled = pd.DataFrame(scaler.transform(X_logs), columns=X_logs.columns)\n",
                "\n",
                "pred_original = rf.predict(X_logs_scaled)\n",
                "classes = list(getattr(rf, 'classes_', [0, 1]))\n",
                "pos_label = 1 if 1 in classes else classes[-1]\n",
                "\n",
                "if hasattr(rf, 'predict_proba'):\n",
                "    prob = rf.predict_proba(X_logs_scaled)\n",
                "    pos_index = classes.index(pos_label) if pos_label in classes else 0\n",
                "    prob_pos = prob[:, pos_index]\n",
                "else:\n",
                "    prob_pos = np.full(len(pred_original), np.nan)\n",
                "\n",
                "threshold = 0.15\n",
                "pred = np.where(prob_pos > threshold, pos_label, 0)\n",
                "\n",
                "df_logs['pred_label'] = pred\n",
                "df_logs['prob_ransomware'] = prob_pos\n",
                "\n",
                "# Print summary\n",
                "summary = df_logs.groupby('ProcessId').agg(\n",
                "    total_events=('total_events', 'mean'),\n",
                "    predicted_ransomware_rate=('pred_label', lambda x: float(np.mean(x == pos_label))),\n",
                "    avg_prob_ransomware=('prob_ransomware', 'mean'),\n",
                "    max_prob_ransomware=('prob_ransomware', 'max')\n",
                ").reset_index()\n",
                "\n",
                "print('Predicao por Processo (Ransomware se Prob > 0.15):')\n",
                "summary['log_pred_label'] = np.where(summary['avg_prob_ransomware'] > threshold, pos_label, 0)\n",
                "print(summary)\n"
            ]

with open('c:/Projetos/RansonwareData/Tests/TestWithLogs.ipynb', 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1)

print('Updated TestWithLogs.ipynb')
