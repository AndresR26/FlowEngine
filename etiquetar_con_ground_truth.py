"""Etiqueta un CSV de FlowEngine cruzándolo con un archivo de ground truth
(formato NUSW-NB15_GT.csv del dataset UNSW-NB15) por la 4-tupla
(IP origen, IP destino, puerto origen, puerto destino).

Uso:
    python etiquetar_con_ground_truth.py --csv pcap_resultado.csv --gt NUSW-NB15_GT.csv --salida etiquetado.csv
"""
import argparse
import pandas as pd
from tqdm.auto import tqdm

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--csv", required=True, help="CSV generado por FlowEngine")
parser.add_argument("--gt", required=True, help="Ground truth (NUSW-NB15_GT.csv)")
parser.add_argument("--salida", default="etiquetado.csv", help="CSV de salida")
args = parser.parse_args()

tqdm.pandas()

# ============================================================
# CARGAR ARCHIVOS
# ============================================================
print("📂 Cargando archivos...")

mi_csv = pd.read_csv(args.csv, low_memory=False)
gt     = pd.read_csv(args.gt, low_memory=False)

print(f"   Tu CSV    : {len(mi_csv):,} filas")
print(f"   GT        : {len(gt):,} filas")

# ============================================================
# PREPARAR GT
# ============================================================
print("\n🔧 Preparando GT...")

gt = gt.rename(columns={
    "Source IP":        "Source IP",
    "Destination IP":   "Destination IP",
    "Source Port":      "Source Port",
    "Destination Port": "Destination Port",
    "Attack category":  "attack_cat",
    "Start time":       "gt_start",
    "Last time":        "gt_end"
})

gt["label"] = gt["attack_cat"].apply(lambda x: 0 if pd.isna(x) or x == "" else 1)

# Forzar tipos para que el merge sea exacto
for col in ["Source Port", "Destination Port"]:
    mi_csv[col] = pd.to_numeric(mi_csv[col], errors="coerce").fillna(0).astype(int)
    gt[col]     = pd.to_numeric(gt[col],     errors="coerce").fillna(0).astype(int)

mi_csv["Source IP"]      = mi_csv["Source IP"].astype(str).str.strip()
mi_csv["Destination IP"] = mi_csv["Destination IP"].astype(str).str.strip()
gt["Source IP"]          = gt["Source IP"].astype(str).str.strip()
gt["Destination IP"]     = gt["Destination IP"].astype(str).str.strip()

# ============================================================
# JOIN VECTORIZADO CON BARRA DE PROGRESO
# ============================================================
print("\n🔗 Ejecutando join...")

KEYS = ["Source IP", "Destination IP", "Source Port", "Destination Port"]

# Quedarse solo con las columnas necesarias del GT
gt_slim = gt[KEYS + ["attack_cat", "label"]].copy()

# Eliminar duplicados en el GT (mismo flujo puede aparecer varias veces)
gt_slim = gt_slim.drop_duplicates(subset=KEYS)

# Split en chunks para mostrar progreso sin sacrificar velocidad
CHUNK = 10_000
total  = len(mi_csv)
chunks = [mi_csv.iloc[i:i+CHUNK] for i in range(0, total, CHUNK)]

resultados = []

with tqdm(total=total, desc="Etiquetando flujos", unit="flujos",
          bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") as pbar:

    for chunk in chunks:
        merged = pd.merge(chunk, gt_slim, on=KEYS, how="left")
        merged["attack_cat"] = merged["attack_cat"].fillna("Normal")
        merged["label"]      = merged["label"].fillna(0).astype(int)
        resultados.append(merged)
        pbar.update(len(chunk))

# ============================================================
# CONSOLIDAR Y GUARDAR
# ============================================================
print("\n💾 Guardando resultado...")

df_final = pd.concat(resultados, ignore_index=True)
df_final.to_csv(args.salida, index=False)

# ============================================================
# RESUMEN
# ============================================================
total_flujos   = len(df_final)
matcheados     = (df_final["label"] == 1).sum()
no_matcheados  = (df_final["attack_cat"] == "Normal").sum()
cobertura      = matcheados / total_flujos * 100

print(f"\n{'='*45}")
print(f"  Total flujos     : {total_flujos:,}")
print(f"  Ataques          : {matcheados:,}  ({cobertura:.1f}%)")
print(f"  Normales         : {no_matcheados:,}")
print(f"{'='*45}")
print(f"\n  Distribución attack_cat:")
print(df_final["attack_cat"].value_counts().to_string())
print(f"\n✅ Guardado en {args.salida}")
