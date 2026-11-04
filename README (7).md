# training/

🇪🇸 **`entrenar_modelo.py`** entrena el modelo `modelo_rf_ids.joblib` que usa FlowEngine para etiquetar con IA (opción 2 del menú y capturas remotas).
🇬🇧 **`entrenar_modelo.py`** trains the `modelo_rf_ids.joblib` model FlowEngine uses for AI labelling (menu option 2 and remote captures).

```bash
python entrenar_modelo.py --datos ../datasets --salida modelo_salida
```

| Paso / Step | Qué hace / What it does |
|---|---|
| 0 | Revisa e instala dependencias (pandas, numpy, scikit-learn, joblib, matplotlib) / Checks and installs dependencies |
| 1 | Une todos los CSV de la carpeta y normaliza etiquetas (`MAPA_ETIQUETAS`) / Merges every CSV and normalises labels |
| 2 | Limpia duplicados, infinitos, nulos y columnas no numéricas (IPs, etc.) / Cleans duplicates, infinities, nulls, non-numeric columns |
| 3 | División estratificada 80/20 / Stratified 80/20 split |
| 4 | `RandomizedSearchCV` (15 combinaciones, CV estratificada de 3 particiones) sobre `RandomForestClassifier` / over a Random Forest |
| 5 | Métricas por clase, matriz de confusión e importancia de variables / Per-class metrics, confusion matrix, feature importance |
| 6 | Guarda `modelo_rf_ids.joblib` y `columnas_features.json` / Saves the model and its feature list |

Copia `modelo_salida/modelo_rf_ids.joblib` junto a `FlowEngine.exe` (Director y agentes). Usa la **misma versión de scikit-learn** al entrenar y al compilar FlowEngine.
Copy `modelo_salida/modelo_rf_ids.joblib` next to `FlowEngine.exe` (Director and agents). Use the **same scikit-learn version** for training and for building FlowEngine.

> 🇪🇸 `MAPA_ETIQUETAS` unifica nombres habituales (`dos`→`DoS`, `portscan`→`PortScan`, `bruteforce`→`BruteForce`, `normal`→`Normal`…). Las etiquetas `fuzzer`, `beaconing` e `injection` de estos datasets no están en el mapa y se conservan tal cual; añádelas si quieres agruparlas (p. ej. `'injection': 'WebAttack'`).
> 🇬🇧 `MAPA_ETIQUETAS` unifies common names. The `fuzzer`, `beaconing` and `injection` labels from these datasets are not in the map and are kept as-is; add them if you want them grouped (e.g. `'injection': 'WebAttack'`).
