import pefile
import math
import os
import csv
import hashlib
import pandas as pd

# Lista de APIs suspeitas relacionadas a ransomware
SUSPECT_APIS = [
    "CreateFile", "WriteFile", "DeleteFile", "FindFirstFile",
    "CryptEncrypt", "CryptAcquireContext", "CryptGenKey", "CryptImportKey",
    "VirtualAlloc", "VirtualFree", "VirtualProtect", "GetProcAddress",
    "LoadLibrary", "InternetOpen", "InternetConnect", "WinHttpOpen"
]

# Calcular entropia de uma seção
def calc_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

# Extrair features de um único arquivo PE
def extract_features(filepath):
    try:
        pe = pefile.PE(filepath)

        features = {
            "filename": os.path.basename(filepath),
            "sha256": hashlib.sha256(open(filepath, 'rb').read()).hexdigest(),
            "num_sections": len(pe.sections),
            "has_rsrc_section": 0,
            "max_entropy": 0,
            "avg_entropy": 0,
            "total_imports": 0,
            "suspicious_api_count": 0,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "is_dll": 1 if pe.FILE_HEADER.Characteristics & 0x2000 else 0,
            "image_size": pe.OPTIONAL_HEADER.SizeOfImage,
            "is_64bit": 1 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 0
        }

        entropies = []
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            entropy = calc_entropy(section.get_data())
            entropies.append(entropy)
            if '.rsrc' in name.lower():
                features["has_rsrc_section"] = 1
        features["max_entropy"] = max(entropies) if entropies else 0
        features["avg_entropy"] = sum(entropies)/len(entropies) if entropies else 0

        suspicious_count = 0
        total_imports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        imp_name = imp.name.decode(errors='ignore')
                        if any(api.lower() in imp_name.lower() for api in SUSPECT_APIS):
                            suspicious_count += 1
        features["total_imports"] = total_imports
        features["suspicious_api_count"] = suspicious_count

        return features
    except Exception as e:
        print(f"[!] Erro ao processar {filepath}: {e}")
        return None

# Processar todos os arquivos PE válidos em um diretório
def process_dir(folder):
    dataset = []
    for file in os.listdir(folder):
        path = os.path.join(folder, file)
        if os.path.isfile(path):
            try:
                pe = pefile.PE(path)  # tenta abrir como PE direto
                features = extract_features(path)
                if features:
                    dataset.append(features)
            except pefile.PEFormatError:
                print(f"[✘] {file} não é um PE válido")
            except Exception as e:
                print(f"[!] Erro ao processar {file}: {e}")
    return dataset

# Salvar em CSV
def save_to_csv(data, output_file):
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"[+] Arquivo salvo: {output_file}")

# -------- Ponto de entrada --------
if __name__ == "__main__":
    pasta = "filtrados"  
    saida = "features_extraidas.csv"

    dados = process_dir(pasta)
    save_to_csv(dados, saida)
