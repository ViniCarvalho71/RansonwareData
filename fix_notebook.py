import nbformat as nbf

nb = nbf.v4.new_notebook()

cells = [
    nbf.v4.new_markdown_cell('# Treinamento do Modelo e Explainable AI (XAI)\nEste notebook contém o fluxo completo de pré-processamento focado em *behavioral features*, treino com *RandomForest* e explicações de IA usando **SHAP** e **LIME**.'),
    nbf.v4.new_code_cell('''import pandas as pd
import numpy as np
import joblib
import json
import shap
from lime.lime_tabular import LimeTabularExplainer
import matplotlib.pyplot as plt
import sys
sys.path.append("..")

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split 
from sklearn.metrics import classification_report, confusion_matrix

print("Bibliotecas importadas!")'''),
    nbf.v4.new_markdown_cell('## 1. Carregando Dataset LMD-2023'),
    nbf.v4.new_code_cell('''df_raw = pd.read_csv('../Datasets/LMD-2023-dataset.csv', low_memory=False)
df_raw = df_raw[df_raw['Label'] != 2].copy()
print(f"Linhas carregadas: {len(df_raw)}")'''),
    nbf.v4.new_markdown_cell('## 2. Engenharia de Features (Behavioral)'),
    nbf.v4.new_code_cell('''from parser.feature_engineering import extract_behavioral_features

print("Extraindo features comportamentais...")
df_behavioral = extract_behavioral_features(df_raw)

y = df_behavioral['Label']
X = df_behavioral.drop(columns=['Label', 'ProcessId', '_log_file'], errors='ignore')

# Salvar metadados das features (Importante para Inferência)
with open("../models/metadata.json", "w") as f:
    json.dump({"features": X.columns.tolist()}, f)

print(f"Nomes das features ({len(X.columns)}):", X.columns.tolist())'''),
    nbf.v4.new_markdown_cell('## 3. Pré-processamento (StandardScaler)'),
    nbf.v4.new_code_cell('''scaler = StandardScaler()
X_encoded = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

joblib.dump(scaler, '../models/preprocessor.joblib')
print('Scaler salvo em ../models/preprocessor.joblib')'''),
    nbf.v4.new_markdown_cell('## 4. Treinamento da IA (RandomForest)'),
    nbf.v4.new_code_cell('''X_train, X_test, y_train, y_test = train_test_split(X_encoded, y, test_size=0.2, random_state=42)

rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

joblib.dump(rf, "../models/modelo_ransomware.joblib")
print("Modelo salvo em ../models/modelo_ransomware.joblib")

y_pred = rf.predict(X_test)
print("\\nClassification Report:")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))'''),
    nbf.v4.new_markdown_cell('## 5. Explainable AI - SHAP (Global e Local)'),
    nbf.v4.new_code_cell('''# Coletamos uma amostra para SHAP analisar rapidamente (ex: 500 instancias)
sample_size = min(500, len(X_test))
X_sample = X_test.iloc[:sample_size]

explainer = shap.TreeExplainer(rf)
shap_values = explainer.shap_values(X_sample)

# Random Forest pode retornar shap_values por classe. Queremos a index 1 (Ransomware)
if isinstance(shap_values, list):
    shap_class_1 = shap_values[1] 
elif isinstance(shap_values, np.ndarray) and len(shap_values.shape) == 3:
    shap_class_1 = shap_values[:, :, 1]
else:
    shap_class_1 = shap_values

# Global Explanation (Summary Plot)
print("--- SHAP Global Summary Plot ---")
shap.summary_plot(shap_class_1, X_sample, show=True)'''),
    nbf.v4.new_code_cell('''# Local Explanation (Waterfall Plot)
instance_idx = 0
sv = shap_class_1[instance_idx]
base_value = explainer.expected_value
if isinstance(base_value, list) or isinstance(base_value, np.ndarray):
    base_value = float(base_value[1] if len(base_value) > 1 else base_value[0])

print(f"--- SHAP Local (Instância {instance_idx}) ---")
exp = shap.Explanation(
    values=sv,
    base_values=base_value,
    data=X_sample.iloc[instance_idx].values,
    feature_names=X_sample.columns.tolist()
)
try:
    shap.plots.waterfall(exp, max_display=10)
    plt.show()
except Exception as e:
    print('waterfall failed:', e)'''),
    nbf.v4.new_markdown_cell('## 6. Explainable AI - LIME (Local)'),
    nbf.v4.new_code_cell('''lime_explainer = LimeTabularExplainer(
    X_train.values,
    feature_names=X_train.columns.tolist(),
    class_names=["Benign", "Ransomware"],
    mode="classification"
)

instance_to_explain = X_sample.iloc[instance_idx].values

exp_lime = lime_explainer.explain_instance(
    instance_to_explain,
    rf.predict_proba,
    num_features=10
)

print(f"--- LIME Local (Instância {instance_idx}) ---")
fig = exp_lime.as_pyplot_figure()
plt.tight_layout()
plt.show()

display(pd.DataFrame(exp_lime.as_list(), columns=['Feature', 'Contribution']))''')
]

nb['cells'] = cells

with open('c:/Projetos/RansonwareData/Train/train_v2.ipynb', 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print('Notebook train_v2.ipynb reconstruído de ponta a ponta com sucesso!')
