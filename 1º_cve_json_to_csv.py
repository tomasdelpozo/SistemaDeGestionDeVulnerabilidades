import json
import pandas as pd
import os

# Crear carpeta de salida si no existe
os.makedirs("csv_generados", exist_ok=True)

# Cargar el JSON de NVD
with open("nvd_data.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Lista para almacenar los datos extraídos
cve_list = []

# Recorrer cada CVE en el JSON
for item in data["CVE_Items"]:
    cve_id = item["cve"]["CVE_data_meta"]["ID"]

    # Extraer información del CPE (Common Platform Enumeration)
    cpe_entries = item.get("configurations", {}).get("nodes", [])
    part, vendor, product = [], [], []

    for node in cpe_entries:
        for match in node.get("cpe_match", []):
            cpe_uri = match.get("cpe23Uri", "")
            parts = cpe_uri.split(":")
            if len(parts) > 4:
                part.append(parts[2])
                vendor.append(parts[3])
                product.append(parts[4])

    # Extraer impacto de CVSS v3 (si existe)
    impact_data = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
    cvss_score = impact_data.get("baseScore", "N/A")
    attack_vector = impact_data.get("attackVector", "N/A")
    exploitability_score = item.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore", "N/A")

    # Agregar a la lista
    cve_list.append({
        "CVE_ID": cve_id,
        "part": ",".join(set(part)),
        "vendor": ",".join(set(vendor)),
        "product": ",".join(set(product)),
        "cvss_score": cvss_score,
        "attack_vector": attack_vector,
        "exploitability_score": exploitability_score
    })

# Convertir lista a DataFrame
df = pd.DataFrame(cve_list)

# Limpiar espacios y normalizar valores vacíos
df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
df.replace(["", "N/A", "None", None], pd.NA, inplace=True)

# Eliminar filas con cualquier valor vacío o nulo
df_cleaned = df.dropna()

# Guardar el CSV limpio
df_cleaned.to_csv("csv_generados/info_cve_cleaned.csv", index=False, encoding="utf-8")

print(f" Archivo limpio generado: 'csv_generados/info_cve_cleaned.csv' ({len(df_cleaned)} filas).")
