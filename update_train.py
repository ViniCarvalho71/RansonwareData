import json

with open('c:/Projetos/RansonwareData/Train/train_v2.ipynb', 'r', encoding='utf-8') as f:
    nb = json.load(f)

for cell in nb['cells']:
    if cell['cell_type'] == 'code':
        source = ''.join(cell['source'])
        
        if 'reliable_features =' in source:
            cell['source'] = [
                "import sys\n",
                "sys.path.append('..')\n",
                "from parser.feature_engineering import extract_behavioral_features\n",
                "\n",
                "print('Extracting behavioral features...')\n",
                "df_behavioral = extract_behavioral_features(df)\n",
                "\n",
                "y = df_behavioral['Label']\n",
                "X = df_behavioral.drop(columns=['Label', 'ProcessId', '_log_file'], errors='ignore')\n",
                "print('Behavioral features:', X.columns.tolist())\n"
            ]
            
        elif 'categorical_features = X.columns.tolist()' in source:
            cell['source'] = [
                "import joblib\n",
                "from sklearn.impute import SimpleImputer\n",
                "\n",
                "imputer = SimpleImputer(strategy='constant', fill_value=0)\n",
                "\n",
                "X_encoded = pd.DataFrame(\n",
                "    imputer.fit_transform(X),\n",
                "    columns=X.columns\n",
                ")\n",
                "\n",
                "joblib.dump(imputer, 'preprocessor.joblib')\n",
                "\n",
                "print('Preprocessor salvo em preprocessor.joblib')\n"
            ]

with open('c:/Projetos/RansonwareData/Train/train_v2.ipynb', 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1)

print('Updated train_v2.ipynb')
