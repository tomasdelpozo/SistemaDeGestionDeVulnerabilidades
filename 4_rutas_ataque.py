import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from collections import Counter
from operator import itemgetter

# ------------------------------
ARCHIVO = "csv_generados/activos_vulnerabilidades_con_clusters.csv"
OBJETIVO = 29
UMBRAL_SEVERIDAD = 6.3
# ------------------------------

df = pd.read_csv(ARCHIVO)

if "id" not in df.columns:
    df.insert(0, "id", [i+1 for i in range(len(df))])

# Crear grafo G (con clusters)
G = nx.Graph()
for _, row in df.iterrows():
    G.add_node(
        row["id"],
        apps=set(app.strip().lower() for app in row["apps"].split(",")),
        so=row["so"].lower(),
        severidad=row["cvss_media"],
        cluster=row["Cluster"]
    )

nodos = list(G.nodes(data=True))
for i in range(len(nodos)):
    id1, d1 = nodos[i]
    for j in range(i + 1, len(nodos)):
        id2, d2 = nodos[j]
        if d1["cluster"] == d2["cluster"]:
            comunes = d1["apps"] & d2["apps"]
            if comunes:
                condicion_umbral = (
                    (id1 == OBJETIVO and d2["severidad"] >= UMBRAL_SEVERIDAD) or
                    (id2 == OBJETIVO and d1["severidad"] >= UMBRAL_SEVERIDAD) or
                    (id1 != OBJETIVO and id2 != OBJETIVO and d1["severidad"] >= UMBRAL_SEVERIDAD and d2["severidad"] >= UMBRAL_SEVERIDAD)
                )
                if condicion_umbral:
                    G.add_edge(id1, id2, weight=1.0)

# Layout con separación mejorada
pos = nx.spring_layout(G, seed=30, k=0.8)

# Colores por cluster
clusters = nx.get_node_attributes(G, "cluster")
unique_clusters = sorted(set(clusters.values()))
color_map = plt.cm.Set2
cluster_color_dict = {
    c: color_map(i / max(len(unique_clusters) - 1, 1)) for i, c in enumerate(unique_clusters)
}
node_colors = ['red' if n == OBJETIVO else cluster_color_dict[clusters[n]] for n in G.nodes()]
node_sizes = [600 if n == OBJETIVO else 300 for n in G.nodes()]

# Rutas hacia el objetivo (con clusters)
rutas = []
apps_en_rutas = []

for origen in G.nodes():
    if origen == OBJETIVO:
        continue
    try:
        path = nx.shortest_path(G, source=origen, target=OBJETIVO, weight="weight")
        peso = nx.path_weight(G, path, weight="weight")
        rutas.append((origen, path, peso))
        for i in range(len(path) - 1):
            apps_en_rutas.extend(G.nodes[path[i]]["apps"] & G.nodes[path[i + 1]]["apps"])
    except nx.NetworkXNoPath:
        continue  # No mostrar nada

# Top 10 rutas con clusters
print("\n Top 10 rutas más cortas CON clusters:")
for origen, path, peso in sorted(rutas, key=itemgetter(2))[:10]:
    print(f"{origen} → {OBJETIVO} | Ruta: {path} | Saltos: {int(peso)}")

print("\n Aplicaciones más comunes en las rutas de ataque CON clusters:")
for app, count in Counter(apps_en_rutas).most_common(10):
    print(f"{app}: {count} veces")

# Leyenda de clusters
legend_elements = [
    Patch(facecolor=color, edgecolor='gray', label=f"Cluster {c}")
    for c, color in cluster_color_dict.items()
]

# GRAFO 1: CON CLUSTERS
plt.figure(figsize=(13, 9))
nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes)
nx.draw_networkx_edges(G, pos, alpha=0.5)
nx.draw_networkx_labels(G, pos, font_size=9)
plt.legend(handles=legend_elements, title="Clusters", loc="upper left", frameon=True)
plt.title(f"Grafo 1: Con clusters y umbral ≥ {UMBRAL_SEVERIDAD}")
plt.axis("off")
plt.tight_layout()
plt.savefig("graficas_rutas_ataque/grafo_con_clusters.png", dpi=300)
plt.show()

# GRAFO 2: SPG CON CLUSTERS
G_spg = nx.DiGraph()
G_spg.add_nodes_from(G.nodes(data=True))
for origen, path, _ in rutas:
    for i in range(len(path) - 1):
        G_spg.add_edge(path[i], path[i + 1], weight=1.0)

plt.figure(figsize=(13, 9))
nx.draw_networkx_nodes(G_spg, pos, node_color=node_colors, node_size=node_sizes)
nx.draw_networkx_edges(G_spg, pos, edge_color='blue', arrows=True, arrowstyle='->', arrowsize=15, width=2)
nx.draw_networkx_labels(G_spg, pos, font_size=9)
plt.legend(handles=legend_elements, title="Clusters", loc="upper left", frameon=True)
plt.title(f"Grafo 2: SPG (Subgrafo de rutas mínimas) CON clusters hacia {OBJETIVO}")
plt.axis("off")
plt.tight_layout()
plt.savefig("graficas_rutas_ataque/grafo_spg_con_clusters.png", dpi=300)
plt.show()

# GRAFO 3: SIN CLUSTERS
G2 = nx.Graph()
for n, d in G.nodes(data=True):
    G2.add_node(n, **d)

for i in range(len(nodos)):
    id1, d1 = nodos[i]
    for j in range(i + 1, len(nodos)):
        id2, d2 = nodos[j]
        comunes = d1["apps"] & d2["apps"]
        if comunes:
            condicion_umbral = (
                (id1 == OBJETIVO and d2["severidad"] >= UMBRAL_SEVERIDAD) or
                (id2 == OBJETIVO and d1["severidad"] >= UMBRAL_SEVERIDAD) or
                (id1 != OBJETIVO and id2 != OBJETIVO and d1["severidad"] >= UMBRAL_SEVERIDAD and d2["severidad"] >= UMBRAL_SEVERIDAD)
            )
            if condicion_umbral:
                G2.add_edge(id1, id2, weight=1.0)

rutas2 = []
apps_en_rutas2 = []

for origen in G2.nodes():
    if origen == OBJETIVO:
        continue
    try:
        path = nx.shortest_path(G2, source=origen, target=OBJETIVO, weight="weight")
        peso = nx.path_weight(G2, path, weight="weight")
        rutas2.append((origen, path, peso))
        for i in range(len(path) - 1):
            apps_en_rutas2.extend(G2.nodes[path[i]]["apps"] & G2.nodes[path[i + 1]]["apps"])
    except nx.NetworkXNoPath:
        continue

# Top 10 rutas sin clusters
print("\n Top 10 rutas más cortas SIN clusters:")
for origen, path, peso in sorted(rutas2, key=itemgetter(2))[:10]:
    print(f"{origen} → {OBJETIVO} | Ruta: {path} | Saltos: {int(peso)}")

print("\n Aplicaciones más comunes en las rutas de ataque SIN clusters:")
for app, count in Counter(apps_en_rutas2).most_common(10):
    print(f"{app}: {count} veces")

# Colores de nodos para G2 según cluster original
node_colors2 = ['red' if n == OBJETIVO else cluster_color_dict[clusters[n]] for n in G2.nodes()]

plt.figure(figsize=(13, 9))
nx.draw_networkx_nodes(G2, pos, node_color=node_colors2, node_size=node_sizes)
nx.draw_networkx_edges(G2, pos, alpha=0.5)
nx.draw_networkx_labels(G2, pos, font_size=9)
plt.legend(handles=legend_elements, title="Clusters", loc="upper left", frameon=True)
plt.title(f"Grafo 3: Sin clusters + umbral ≥ {UMBRAL_SEVERIDAD}")
plt.axis("off")
plt.tight_layout()
plt.savefig("graficas_rutas_ataque/grafo_sin_clusters.png", dpi=300)
plt.show()

# GRAFO 4: SPG SIN CLUSTERS
G2_spg = nx.DiGraph()
G2_spg.add_nodes_from(G2.nodes(data=True))
for origen, path, _ in rutas2:
    for i in range(len(path) - 1):
        G2_spg.add_edge(path[i], path[i + 1], weight=1.0)

plt.figure(figsize=(13, 9))
nx.draw_networkx_nodes(G2_spg, pos, node_color=node_colors2, node_size=node_sizes)
nx.draw_networkx_edges(G2_spg, pos, edge_color='green', arrows=True, arrowstyle='->', arrowsize=15, width=2)
nx.draw_networkx_labels(G2_spg, pos, font_size=9)
plt.legend(handles=legend_elements, title="Clusters", loc="upper left", frameon=True)
plt.title(f"Grafo 4: SPG (Subgrafo de rutas mínimas) SIN clusters hacia {OBJETIVO}")
plt.axis("off")
plt.tight_layout()
plt.savefig("graficas_rutas_ataque/grafo_spg_sin_clusters.png", dpi=300)
plt.show()

