import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.cluster import KMeans
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import seaborn as sns  # Paleta de colores

#------------Cargar y limpiar datos------------
data = pd.read_csv('csv_generados/activos_vulnerabilidades.csv')  # Cargar datos
data_cleaned = data.drop(['id'], axis=1).dropna()  # Eliminar columnas irrelevantes y valores nulos

#------------Definir transformaciones------------
numeric_features = ['cvss_media', 'exploitabilidad_media', 'cvss_max', 'cvss_min',
                    'exploitabilidad_max', 'exploitabilidad_min']

preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numeric_features)
    ]
)

data_processed = preprocessor.fit_transform(data_cleaned)  # Normalización

#------------MÉTODO DEL CODO------------
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

#------------Silhouette Score para determinar el mejor k------------
from sklearn.metrics import silhouette_score

best_k = 2
best_score = -1

for k in range(2, 10):
    kmeans = KMeans(n_clusters=k, random_state=0)
    labels = kmeans.fit_predict(data_processed)
    score = silhouette_score(data_processed, labels)
    print(f"Clusters: {k}, Silhouette Score: {score:.3f}")
    
    if score > best_score:
        best_k = k
        best_score = score

print(f"Mejor número de clusters según Silhouette Score: {best_k}")

#------------Aplicar K-Means definitivo------------
kmeans = KMeans(n_clusters=best_k, random_state=0)
clusters = kmeans.fit_predict(data_processed)
data_cleaned['Cluster'] = clusters

data_cleaned.to_csv('csv_generados/activos_vulnerabilidades_con_clusters.csv', index=False)

#------------Medir calidad final del clustering------------
sil_score = silhouette_score(data_processed, clusters)
print(f"Silhouette Score: {sil_score:.3f}")

#------------t-SNE y visualización------------
tsne = TSNE(n_components=2, perplexity=5, random_state=0)
data_tsne = tsne.fit_transform(data_processed)

# Crear DataFrame con resultados
tsne_df = pd.DataFrame(data_tsne, columns=['Componente_1', 'Componente_2'])
tsne_df['Cluster'] = clusters
tsne_df['Color'] = tsne_df['Cluster'].map({i: c for i, c in enumerate(sns.color_palette("husl", len(set(clusters))))})
tsne_df['id'] = data_cleaned.index + 1  # IDs empiezan desde 1

# Identificar activos del caso de uso
caso_uso_ids = [25, 26, 27, 28, 29, 30]
caso_uso_df = tsne_df[tsne_df['id'].isin(caso_uso_ids)]
resto_df = tsne_df[~tsne_df['id'].isin(caso_uso_ids)]

# Graficar
plt.figure(figsize=(8, 6))

# Resto de activos
plt.scatter(resto_df['Componente_1'], resto_df['Componente_2'],
            c=resto_df['Color'], edgecolor='k', s=60)

# Activos del caso de uso resaltados con estrella
plt.scatter(caso_uso_df['Componente_1'], caso_uso_df['Componente_2'],
            c=caso_uso_df['Color'], edgecolor='black', marker='*', s=200, label='Caso de uso')

# Leyenda de clusters
unique_clusters = sorted(tsne_df['Cluster'].unique())
palette = sns.color_palette("husl", len(unique_clusters))
legend_clusters = [Patch(facecolor=palette[i], edgecolor='k', label=f'Cluster {i}') for i in unique_clusters]

# Añadir leyenda y título
from matplotlib.lines import Line2D

# Elemento personalizado para caso de uso (estrella negra con borde)
caso_uso_legend = Line2D([0], [0], marker='*', color='black', label='Caso de uso',
                         markerfacecolor='black', markersize=15, linestyle='None')

# Mostrar leyenda
plt.legend(handles=legend_clusters + [caso_uso_legend],
           title='Leyenda', loc='upper right')


plt.xlabel('Componente 1')
plt.ylabel('Componente 2')
plt.title('Clusters de Activos Vulnerables en el Espacio t-SNE')
plt.tight_layout()
plt.savefig("graficas_clustering/ClustersActivosEspacioT-SNE.png", dpi=300)
plt.show()

