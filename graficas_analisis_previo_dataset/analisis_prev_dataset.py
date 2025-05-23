import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Cargar el dataset
df = pd.read_csv("../csv_generados/info_cve_cleaned.csv")

# Crear carpeta para guardar las gráficas (opcional)
import os
output_dir = "graficas_cve"
os.makedirs(output_dir, exist_ok=True)

# --------------------------
# Análisis estadístico global
# --------------------------
print("Estadísticas básicas del dataset:\n")
print(df.describe())

# --------------------------
# 1. Distribución de puntuaciones CVSS
# --------------------------
plt.figure(figsize=(8, 5))
sns.histplot(df["cvss_score"], bins=20, kde=True, color="steelblue")
plt.title("Distribución de Puntuaciones CVSS")
plt.xlabel("CVSS Score")
plt.ylabel("Frecuencia")
plt.grid(True)
plt.tight_layout()
plt.savefig(f"{output_dir}/cvss_distribution.png")
plt.close()

# Tabla: CVEs por rango de CVSS
bins = [0, 3, 6, 8, 10]
labels = ['Baja (0–3)', 'Media (3–6)', 'Alta (6–8)', 'Crítica (8–10)']
df['cvss_rango'] = pd.cut(df["cvss_score"], bins=bins, labels=labels)
cvss_rango_counts = df['cvss_rango'].value_counts().sort_index()
print("\n Cantidad de CVEs por rango CVSS:")
print(cvss_rango_counts)

# --------------------------
# 2. Distribución por attack_vector
# --------------------------
plt.figure(figsize=(7, 5))
sns.countplot(data=df, x="attack_vector", order=df["attack_vector"].value_counts().index, palette="pastel")
plt.title("Distribución por Vector de Ataque")
plt.xlabel("Vector de Ataque")
plt.ylabel("Cantidad de CVEs")
plt.tight_layout()
plt.savefig(f"{output_dir}/attack_vector_distribution.png")
plt.close()

# --------------------------
# 3. Top 10 productos con más CVEs
# --------------------------
top_products = df["product"].value_counts().head(10)

plt.figure(figsize=(9, 5))
sns.barplot(x=top_products.values, y=top_products.index, palette="mako")
plt.title("Top 10 Productos con más Vulnerabilidades")
plt.xlabel("Cantidad de CVEs")
plt.ylabel("Producto")
plt.tight_layout()
plt.savefig(f"{output_dir}/top_productos.png")
plt.close()

# --------------------------
# 4. Top 10 vendors con más CVEs
# --------------------------
top_vendors = df["vendor"].value_counts().head(10)

plt.figure(figsize=(9, 5))
sns.barplot(x=top_vendors.values, y=top_vendors.index, palette="flare")
plt.title("Top 10 Vendors con más Vulnerabilidades")
plt.xlabel("Cantidad de CVEs")
plt.ylabel("Vendor")
plt.tight_layout()
plt.savefig(f"{output_dir}/top_vendors.png")
plt.close()

# --------------------------
# 5. Relación entre CVSS y Exploitability
# --------------------------
plt.figure(figsize=(7, 5))
sns.scatterplot(data=df, x="cvss_score", y="exploitability_score", alpha=0.6)
plt.title("Relación entre CVSS y Exploitabilidad")
plt.xlabel("CVSS Score")
plt.ylabel("Exploitability Score")
plt.grid(True)
plt.tight_layout()
plt.savefig(f"{output_dir}/cvss_vs_exploitability.png")
plt.close()

# --------------------------
# Guardar tabla resumen por CVSS rango
# --------------------------
cvss_rango_counts.to_csv(f"{output_dir}/resumen_rangos_cvss.csv")

print(f"\n Gráficas guardadas en la carpeta '{output_dir}'")
