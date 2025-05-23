
# DESARROLLO DE UN MODELO PARA LA OPTIMIZACIÓN DE LA GESTIÓN DE VULNERABILIDADES MEDIANTE APRENDIZAJE AUTOMÁTICO NO SUPERVISADO  
**Tomás del Pozo Merino**  
**GITST - ETSIT UPM**

---

## Requisitos

Para ejecutar el proyecto correctamente es necesario:

1. **Descargar el proyecto completo** desde el repositorio, incluyendo todas las carpetas, incluso si están vacías (como `graficas_...`).  
2. **Descargar la base de datos de vulnerabilidades** desde la página oficial del NIST:  
   https://nvd.nist.gov/vuln/data-feeds  
   El archivo debe estar en formato JSON (2.0) y debe guardarse en el directorio del proyecto con el nombre exacto:  
   **`nvd_data.json`**

3. Instalar las dependencias ejecutando el siguiente comando en una terminal:

   ```bash
   pip install -r requirements.txt
   ```

   OJO! En sistemas macOS o Linux puede ser necesario usar `python3` en lugar de `python`.

---

## Estructura del Proyecto

El repositorio incluye cuatro archivos Python principales, numerados para ejecutarse en orden. Cada uno representa una fase del proceso completo de análisis y clustering de activos vulnerables. También se incluyen varias carpetas donde se van guardando los resultados intermedios y gráficos.

---

## Archivos del Proyecto

### `1º_cve_json_to_csv.py`

Este fichero toma el archivo `nvd_data.json` descargado del NIST y genera un CSV limpio (`info_cve_cleaned.csv`) con las vulnerabilidades relevantes, extrayendo campos como `cvss_score`, `exploitability_score`, `attack_vector`, `vendor`, `product`, etc.

---

### `2º_asociar_activos_cve.py`

Este script une la información de los activos (del fichero `activos.csv`) con las vulnerabilidades extraídas en el paso anterior. Asocia las vulnerabilidades a cada activo en función de su sistema operativo y aplicaciones instaladas. El resultado es el archivo `activos_vulnerabilidades.csv`, que se guarda en la carpeta `csv_generados/`.

---

### `3º_alg_cluster.py`

Recoge el CSV generado en el paso anterior, lo limpia y lo normaliza, y aplica clustering con el algoritmo **K-Means**. Para decidir el número óptimo de clusters se utilizan dos métodos:
- El método del codo
- La métrica Silhouette Score

Además, se reduce la dimensionalidad con **t-SNE** para visualizar gráficamente los clústeres y se guarda el resultado en `graficas_clustering/ClustersActivosEspacioT-SNE.png`.

También se genera un CSV final con los activos ya clasificados por clúster: `activos_vulnerabilidades_con_clusters.csv`.

---

### `3º_alg_cluster_caso_de_uso.py` _(opcional)_

Este archivo es una versión adaptada para mostrar un **caso de uso real**. Resalta ciertos activos añadidos al final (IDs 25 al 30), que representan activos nuevos. Se identifican en la visualización con un símbolo especial. No es obligatorio ejecutarlo, pero es útil si se quiere ver cómo se incorporan nuevos activos al sistema.

---

### `4º_rutas_ataque.py`

Este fichero toma los activos con clúster asignado y genera una serie de **grafos de rutas de ataque**:
- **Grafo 1**: conexiones entre activos del mismo clúster.
- **Grafo 2**: rutas mínimas hacia un activo crítico dentro del clúster.
- **Grafo 3 y 4**: repiten los anteriores pero **sin restricción de clúster**, mostrando la red completa.

Todos los gráficos se guardan automáticamente en la carpeta `graficas_rutas_ataque/`.

---

### `analisis_prev_dataset.py` _(opcional)_

Este archivo realiza un **análisis exploratorio del dataset de vulnerabilidades**. Genera gráficas como:
- Distribución de puntuaciones CVSS
- Vectores de ataque
- Productos y vendors más vulnerables
- Relación entre severidad y explotabilidad

Los resultados se guardan en `graficas_analisis_previo_dataset/`. Es útil para entender mejor los datos antes de procesarlos, pero no es obligatorio ejecutarlo.

---

## Ejecución del Proyecto

1. Clonar o descargar el repositorio completo en un directorio local.
2. Descargar el dataset de vulnerabilidades del NVD y colocarlo como `nvd_data.json`.
3. Instalar dependencias:

   ```bash
   pip install -r requirements.txt
   ```

4. Ejecutar los ficheros en orden:

   ```bash
   python 1º_cve_json_to_csv.py
   python 2º_asociar_activos_cve.py
   python 3º_alg_cluster.py
   python 4º_rutas_ataque.py
   ```

5. (Opcional) Para el caso de uso:

   ```bash
   python 3º_alg_cluster_caso_de_uso.py
   ```

6. (Opcional) Para visualizar el análisis previo:

   ```bash
   python analisis_prev_dataset.py
   ```

---

## Carpetas generadas

- `csv_generados/`: contiene archivos CSV intermedios con los datos procesados.
- `graficas_analisis_previo_dataset/`: gráficas del análisis exploratorio (si se ejecuta el script correspondiente).
- `graficas_clustering/`: visualizaciones del proceso de clustering.
- `graficas_rutas_ataque/`: visualizaciones de las rutas de ataque.
