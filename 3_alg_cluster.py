import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.cluster import KMeans
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

#------------Cargar y limpiar datos------------
data = pd.read_csv('csv_generados/activos_vulnerabilidades.csv')  # Cargar datos
data_cleaned = data.drop(['id'], axis=1).dropna()   # Eliminar columnas irrelevantes y filas con valores nulos


#------------Definir las transformaciones para las columnas------------
numeric_features = ['cvss_media','exploitabilidad_media','cvss_max','cvss_min','exploitabilidad_max','exploitabilidad_min']

preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numeric_features)
    ]
)

data_processed = preprocessor.fit_transform(data_cleaned)  # Aplicar preprocesamiento

#------------MÉTODO DEL CODO (añadido)------------
inertias = []
ks = range(2, 10)

for k in ks:
    kmeans = KMeans(n_clusters=k, random_state=0)
    kmeans.fit(data_processed)
    inertias.append(kmeans.inertia_)

plt.figure(figsize=(8, 5))
plt.plot(ks, inertias, marker='o')
plt.xlabel('Número de Clústeres (k)')
plt.ylabel('Inercia')
plt.title('Método del Codo para estimar el número óptimo de clusters')
plt.grid(True)
plt.savefig("graficas_clustering/MetodoCodo.png", dpi=300)
plt.show()
#--------------------------------------------------

#------------Método robusto con silhouette_score para determinar el número óptimo de clusters------------
from sklearn.metrics import silhouette_score

best_k = 2
best_score = -1

for k in range(2, 10):  # Prueba de 2 a 9 clusters
    kmeans = KMeans(n_clusters=k, random_state=0)
    labels = kmeans.fit_predict(data_processed)
    score = silhouette_score(data_processed, labels)
    print(f"Clusters: {k}, Silhouette Score: {score:.3f}")
    
    if score > best_score:
        best_k = k
        best_score = score

print(f"Mejor número de clusters según Silhouette Score: {best_k}")

#------------Aplicar K-Means con el número óptimo de clusters (ajustar manualmente si es necesario)------------
kmeans = KMeans(n_clusters=best_k, random_state=0)
clusters = kmeans.fit_predict(data_processed)
data_cleaned['Cluster'] = clusters

data_cleaned.to_csv('csv_generados/activos_vulnerabilidades_con_clusters.csv', index=False)  # Guardar resultados

#------------medir que tan buenos son los cluster con Silhouette Score----------
from sklearn.metrics import silhouette_score

sil_score = silhouette_score(data_processed, clusters)
print(f"Silhouette Score: {sil_score:.3f}") # Valores cercanos a 1 indican buenos clusters

#------------Aplicar t-SNE para reducir a 2 dimensiones y visualizar------------
tsne = TSNE(n_components=2, perplexity=5, random_state=0)
data_tsne = tsne.fit_transform(data_processed)

# Crear DataFrame con componentes reducidas
tsne_df = pd.DataFrame(data_tsne, columns=['Componente_1', 'Componente_2'])
tsne_df['Cluster'] = clusters


import seaborn as sns  # Librería para paletas de colores

# Generar una lista de colores según la cantidad de clusters detectados
num_clusters = len(set(clusters))  # Número de clusters encontrados
palette = sns.color_palette("husl", num_clusters)  # Paleta de colores distintos

# Crear un diccionario dinámico para mapear cada cluster a un color
colors = {i: palette[i] for i in range(num_clusters)}

# Asignar colores a los clusters
tsne_df['Color'] = tsne_df['Cluster'].map(colors)

# Graficar
plt.figure(figsize=(8, 6))
plt.scatter(tsne_df['Componente_1'], tsne_df['Componente_2'], c=tsne_df['Color'], edgecolor='k', s=60)
plt.legend(handles=[Patch(facecolor=c, edgecolor='k', label=f'Cluster {i}') for i, c in colors.items()],
           title='Clusters')
plt.xlabel('Componente 1')
plt.ylabel('Componente 2')
plt.title('Clusters de Activos Vulnerables en el Espacio t-SNE')
plt.savefig("graficas_clustering/ClustersActivosEspacioT-SNE.png", dpi=300)
plt.show()

