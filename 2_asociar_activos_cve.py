import pandas as pd
import ast  # convertir texto a objetos reales de python

# Cargar archivos
df_activos = pd.read_csv("activos.csv")
df_cve = pd.read_csv("csv_generados/info_cve_cleaned.csv")

# Convertir la columna 'apps' de string a lista
df_activos["apps"] = df_activos["apps"].apply(ast.literal_eval)

# Lista para almacenar las asociaciones por activo
asociaciones = []

# Recorrer cada activo usando itertuples (más rápido)
for activo in df_activos.itertuples():
    activo_id = activo.id
    so = activo.so.lower()
    apps = set(app.lower() for app in activo.apps)  # Normalizar a minúsculas

    # Variables para agrupar
    cvss_scores = [] #lista que permite elementos iguales
    exploit_scores = []
    vectores_ataque = set() #lista que no añade los elementos duplicados

    # Buscar CVEs relacionados
    for cve in df_cve.itertuples():
        productos_afectados = set(cve.product.lower().split(","))
        vendors_afectados = set(cve.vendor.lower().split(","))

        if (
            so in productos_afectados or #el so del activo actual esta en la lista de productos de la cve?
            so in vendors_afectados or
            apps.intersection(productos_afectados) or #alguna app esta en la lista de productos de la cve?
            apps.intersection(vendors_afectados)
        ):
            cvss_scores.append(cve.cvss_score)
            exploit_scores.append(cve.exploitability_score)
            vectores_ataque.add(cve.attack_vector)

    if cvss_scores:
        asociaciones.append({
            "id": activo_id,
            "so": activo.so,
            "apps": ", ".join(activo.apps),
            "cvss_media": round(sum(cvss_scores) / len(cvss_scores), 2),
            "cvss_max": round(max(cvss_scores), 2),
            "cvss_min": round(min(cvss_scores), 2),
            "exploitabilidad_media": round(sum(exploit_scores) / len(exploit_scores), 2),
            "exploitabilidad_max": round(max(exploit_scores), 2),
            "exploitabilidad_min": round(min(exploit_scores), 2),
            "vectores_ataque": ", ".join(sorted(vectores_ataque))
        })

# Guardar archivo
df_asociado = pd.DataFrame(asociaciones)
df_asociado.to_csv("csv_generados/activos_vulnerabilidades.csv", index=False, encoding="utf-8")

print(f"Archivo 'activos_vulnerabilidades.csv' generado con éxito ({len(df_asociado)} activos procesados).")


