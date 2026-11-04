#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 ENTRENAMIENTO DE MODELO IDS (Intrusion Detection System) CON RANDOM FOREST
================================================================================
Qué hace este script, paso a paso:

  1. Lee TODOS los archivos .csv de una carpeta.
  2. "Conmuta" (normaliza) los nombres de los ataques: cada CSV puede llamar
     al mismo ataque de forma distinta (ej. "dos" vs "DoS" vs "DOS") y aquí
     se unifican todos bajo un único nombre estándar (ver MAPA_ETIQUETAS).
  3. Une todos los CSV en un solo dataset, limpia duplicados, valores
     infinitos/nulos y columnas que no sirven como variables predictoras.
  4. Divide los datos en entrenamiento (80%) y prueba (20%), de forma
     estratificada (respetando la proporción de cada clase de ataque).
  5. Optimiza los hiperparámetros de un RandomForestClassifier mediante
     búsqueda aleatoria con validación cruzada estratificada.
  6. Evalúa el modelo con métricas por clase y genera una matriz de
     confusión + importancia de características: esto muestra justamente
     los PATRONES y confusiones entre los distintos tipos de ataque.
  7. Guarda el modelo final y todos los resultados en disco.

Requisitos: NINGUNO que tengas que instalar a mano — el propio script revisa,
instala y repara automáticamente pandas, numpy, scikit-learn, joblib y
matplotlib la primera vez que lo corras (ver PASO 0 más abajo).

================================================================================
"""

import os
import sys
import subprocess
import importlib

# ==============================================================================
# 0. VERIFICACIÓN E INSTALACIÓN AUTOMÁTICA DE DEPENDENCIAS
# ==============================================================================
PRUEBAS_FUNCIONALES = {
    'numpy': 'import numpy as np; assert np.array([1, 2, 3]).sum() == 6',
    'pandas': 'import pandas as pd; assert len(pd.DataFrame({"a": [1, 2]})) == 2',
    'joblib': (
        'import joblib, io; b = io.BytesIO(); joblib.dump({"x": 1}, b); '
        'b.seek(0); assert joblib.load(b) == {"x": 1}'
    ),
    'matplotlib': (
        'import matplotlib; matplotlib.use("Agg"); '
        'import matplotlib.pyplot as plt; f = plt.figure(); plt.close(f)'
    ),
    'sklearn': (
        'from sklearn.ensemble import RandomForestClassifier as RFC; '
        'm = RFC(n_estimators=2, random_state=0); '
        'm.fit([[0, 0], [1, 1], [2, 2]], [0, 1, 0]); '
        'm.predict([[0.5, 0.5]])'
    ),
}

PAQUETES_PIP = {
    'numpy': ['numpy'],
    'pandas': ['pandas'],
    'joblib': ['joblib'],
    'matplotlib': ['matplotlib'],
    'sklearn': ['numpy', 'scipy', 'scikit-learn'],
}


def _funciona(modulo):
    resultado = subprocess.run(
        [sys.executable, '-c', PRUEBAS_FUNCIONALES[modulo]],
        capture_output=True, text=True
    )
    return resultado.returncode == 0, resultado.stderr


def _pip_install(paquetes, forzar=False):
    comando_base = [sys.executable, '-m', 'pip', 'install']
    if forzar:
        comando_base += ['--upgrade', '--force-reinstall']
    metodos = [
        comando_base + paquetes,
        comando_base + ['--user'] + paquetes,
        comando_base + ['--break-system-packages'] + paquetes,
    ]
    for metodo in metodos:
        resultado = subprocess.run(metodo)
        if resultado.returncode == 0:
            importlib.invalidate_caches()
            return True
        print('    (ese método de instalación falló, probando otra alternativa...)')
    return False


def asegurar_dependencias():
    print('Verificando que las dependencias estén instaladas y FUNCIONANDO (no solo importadas)...\n')
    problemas = []

    for modulo in PRUEBAS_FUNCIONALES:
        ok, _ = _funciona(modulo)
        if ok:
            print(f'  OK     {modulo}')
            continue

        print(f'  Instalando/reparando {modulo} ({", ".join(PAQUETES_PIP[modulo])})...')
        _pip_install(PAQUETES_PIP[modulo])
        ok, _ = _funciona(modulo)

        if not ok:
            print(f'  {modulo} sigue sin funcionar bien; reinstalando a la fuerza junto con sus '
                  f'dependencias (esto resuelve la mayoría de incompatibilidades de versión)...')
            _pip_install(PAQUETES_PIP[modulo], forzar=True)
            ok, error = _funciona(modulo)

        if ok:
            print(f'  OK     {modulo} (quedó funcionando tras repararlo)')
        else:
            problemas.append((modulo, error))
            print(f'  FALLA  {modulo}: no se pudo dejar funcionando automáticamente.')

    if problemas:
        print('\n' + '=' * 70)
        print('[ERROR] Estas dependencias no quedaron funcionando pese a reinstalarlas:')
        for modulo, error in problemas:
            ultima_linea = next((l for l in reversed(error.strip().splitlines()) if l.strip()), '(sin detalle)')
            print(f'  - {modulo}: {ultima_linea}')
        print('\nProbablemente ayude, en este orden:')
        print('  1) Actualizar pip:     python -m pip install --upgrade pip')
        print('  2) Reinstalar a mano:  pip install --upgrade --force-reinstall numpy scipy scikit-learn pandas joblib matplotlib')
        print('  3) En Windows: instala el "Microsoft Visual C++ Redistributable" '
              '(numpy/scikit-learn lo necesitan para sus componentes compilados).')
        sys.exit(1)

    print('\nTodas las dependencias están instaladas y funcionando correctamente.\n')


asegurar_dependencias()

# --- A partir de aquí, todas las librerías necesarias ya están garantizadas ---
import glob
import json
import time
import warnings
import gc  # <--- Agregado para forzar limpieza de memoria
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    balanced_accuracy_score, f1_score
)

warnings.filterwarnings('ignore')


# ==============================================================================
# 1. CONFIGURACIÓN — AJUSTA ESTOS VALORES SEGÚN TU CASO
# ==============================================================================

# Se pueden cambiar aquí o por línea de comandos:
#   python entrenar_modelo.py --datos ../datasets --salida ./modelo
CARPETA_DATOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "datasets")
CARPETA_SALIDA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo_salida")
TAMANO_PRUEBA = 0.20
SEMILLA = 42
UMBRAL_COLUMNA_VACIA = 0.5
MIN_MUESTRAS_POR_CLASE = 10
MAX_FILAS_PARA_BUSQUEDA = 150_000

POSIBLES_COLUMNAS_ETIQUETA = ['label', 'class', 'attack_cat', 'attack', 'tipo_ataque', 'category']

COLUMNAS_NO_FEATURES = [
    'Flow ID', 'Source IP', 'Src IP', 'Destination IP', 'Dst IP',
    'Timestamp', 'SimillarHTTP', 'Unnamed: 0', 'id', 'ID',
]


# ==============================================================================
# 2. MAPA DE CONMUTACIÓN / NORMALIZACIÓN DE ETIQUETAS DE ATAQUE
# ==============================================================================

MAPA_ETIQUETAS = {
    'benign': 'Normal',
    'normal': 'Normal',
    'background': 'Normal',
    'none': 'Normal',
    'dos': 'DoS',
    'dos hulk': 'DoS',
    'dos goldeneye': 'DoS',
    'dos slowloris': 'DoS',
    'dos slowhttptest': 'DoS',
    'dos attacks-hulk': 'DoS',
    'dos attacks-goldeneye': 'DoS',
    'dos attacks-slowloris': 'DoS',
    'dos attacks-slowhttptest': 'DoS',
    'slowloris': 'DoS',
    'slowhttptest': 'DoS',
    'hulk': 'DoS',
    'goldeneye': 'DoS',
    'ddos': 'DDoS',
    'ddos attack-hoic': 'DDoS',
    'ddos attack-loic-udp': 'DDoS',
    'ddos attacks-loic-http': 'DDoS',
    'ddos attack-loic-http': 'DDoS',
    'portscan': 'PortScan',
    'port scan': 'PortScan',
    'scanning': 'PortScan',
    'scan': 'PortScan',
    'ftp-patator': 'BruteForce',
    'ssh-patator': 'BruteForce',
    'brute force': 'BruteForce',
    'bruteforce': 'BruteForce',
    'web attack - brute force': 'BruteForce',
    'web attack-brute force': 'BruteForce',
    'web attack - sql injection': 'WebAttack',
    'web attack-sql injection': 'WebAttack',
    'web attack - xss': 'WebAttack',
    'web attack-xss': 'WebAttack',
    'sql injection': 'WebAttack',
    'xss': 'WebAttack',
    'web attack': 'WebAttack',
    'bot': 'Botnet',
    'botnet': 'Botnet',
    'infiltration': 'Infiltration',
    'infiltracion': 'Infiltration',
    'infiltración': 'Infiltration',
    'heartbleed': 'Heartbleed',
}


def normalizar_etiqueta(valor):
    if pd.isna(valor):
        return 'Desconocido'
    texto = str(valor).strip()
    return MAPA_ETIQUETAS.get(texto.lower(), texto)


def encontrar_columna_etiqueta(columnas):
    normalizadas = {c.strip().lower(): c for c in columnas}
    for candidato in POSIBLES_COLUMNAS_ETIQUETA:
        if candidato in normalizadas:
            return normalizadas[candidato]
    return None


def optimizar_memoria(df):
    for col in df.select_dtypes(include=['float64']).columns:
        df[col] = pd.to_numeric(df[col], downcast='float')
    for col in df.select_dtypes(include=['int64']).columns:
        df[col] = pd.to_numeric(df[col], downcast='integer')
    return df


# ==============================================================================
# 3. CARGA Y UNIFICACIÓN DE TODOS LOS CSV DE LA CARPETA
# ==============================================================================

def cargar_y_unificar_csvs(carpeta):
    rutas = glob.glob(os.path.join(carpeta, '*.csv'))
    if not rutas:
        raise FileNotFoundError(f'No se encontraron archivos .csv en: {carpeta}')

    print(f'Se encontraron {len(rutas)} archivo(s) CSV. Cargando...\n')

    dataframes = []
    etiquetas_originales_vistas = set()

    for ruta in sorted(rutas):
        nombre = os.path.basename(ruta)
        try:
            try:
                df = pd.read_csv(ruta, low_memory=False, encoding='utf-8')
            except UnicodeDecodeError:
                df = pd.read_csv(ruta, low_memory=False, encoding='latin1')
        except Exception as error:
            print(f'  [AVISO] No se pudo leer {nombre}: {error}')
            continue

        df.columns = [c.strip() for c in df.columns]

        columna_etiqueta = encontrar_columna_etiqueta(df.columns)
        if columna_etiqueta is None:
            print(f'  [AVISO] {nombre}: no se encontró columna de etiqueta/clase, se omite este archivo.')
            continue

        etiquetas_originales_vistas.update(
            df[columna_etiqueta].dropna().astype(str).str.strip().unique()
        )

        df['Label'] = df[columna_etiqueta].apply(normalizar_etiqueta)
        if columna_etiqueta != 'Label':
            df = df.drop(columns=[columna_etiqueta])

        df['__archivo_origen__'] = nombre
        df = optimizar_memoria(df)
        dataframes.append(df)
        print(f'  OK   {nombre}: {len(df):,} filas, {df["Label"].nunique()} clases detectadas')

    if not dataframes:
        raise RuntimeError('Ningún CSV pudo cargarse correctamente. Revisa la carpeta y los archivos.')

    print('\nResumen de conmutación de etiquetas (original -> unificada):')
    for etiqueta in sorted(etiquetas_originales_vistas):
        estaba_en_mapa = etiqueta.strip().lower() in MAPA_ETIQUETAS
        destino = normalizar_etiqueta(etiqueta)
        aviso = '' if estaba_en_mapa else '   <-- no estaba en MAPA_ETIQUETAS, se dejó tal cual; agrégala si corresponde'
        print(f'   "{etiqueta}"  ->  "{destino}"{aviso}')

    columnas_comunes = set(dataframes[0].columns)
    for df in dataframes[1:]:
        columnas_comunes &= set(df.columns)
    columnas_comunes = sorted(columnas_comunes)

    columnas_descartadas = set()
    for df in dataframes:
        columnas_descartadas |= (set(df.columns) - set(columnas_comunes))
    if columnas_descartadas:
        print(f'\n[AVISO] Estas columnas no estaban en todos los archivos y se ignoraron: '
              f'{sorted(columnas_descartadas)}')

    df_final = pd.concat([d[columnas_comunes] for d in dataframes], ignore_index=True)

    columnas_para_dedup = [c for c in df_final.columns if c != '__archivo_origen__']
    antes = len(df_final)
    df_final = df_final.drop_duplicates(subset=columnas_para_dedup)
    if antes != len(df_final):
        print(f'\nSe eliminaron {antes - len(df_final):,} filas duplicadas.')

    print(f'\nDataset combinado final: {len(df_final):,} filas, {len(columnas_comunes)} columnas comunes.')
    return df_final


# ==============================================================================
# 4. PREPARACIÓN DE FEATURES (X) Y ETIQUETA (y)
# ==============================================================================

def preparar_features(df):
    y = df['Label']

    columnas_a_eliminar = [c for c in (COLUMNAS_NO_FEATURES + ['Label', '__archivo_origen__']) if c in df.columns]
    X = df.drop(columns=columnas_a_eliminar)

    columnas_no_numericas = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if columnas_no_numericas:
        print(f'[AVISO] Se ignoraron columnas no numéricas (no usadas como feature): {columnas_no_numericas}')
    X = X.select_dtypes(include=[np.number])

    if X.shape[1] == 0:
        print('\n[ERROR FATAL] Ninguna columna numérica quedó disponible como feature.')
        sys.exit(1)

    X = X.replace([np.inf, -np.inf], np.nan)

    porcentaje_nulos = X.isna().mean().sort_values(ascending=False)
    columnas_muy_vacias = porcentaje_nulos[porcentaje_nulos > UMBRAL_COLUMNA_VACIA].index.tolist()
    if columnas_muy_vacias:
        print(f'\n[AVISO] Estas columnas tienen más del {UMBRAL_COLUMNA_VACIA * 100:.0f}% de valores '
              f'nulos/infinitos y se descartan:')
        for col in columnas_muy_vacias:
            print(f'   - {col}: {porcentaje_nulos[col] * 100:.1f}% vacío')
        X = X.drop(columns=columnas_muy_vacias)

    if X.shape[1] == 0:
        print(f'\n[ERROR FATAL] Todas las columnas numéricas quedaron por encima del umbral.')
        sys.exit(1)

    filas_validas = X.notna().all(axis=1)
    filas_eliminadas = (~filas_validas).sum()
    if filas_eliminadas > 0:
        print(f'\nSe eliminaron {filas_eliminadas:,} filas ({filas_eliminadas / len(X) * 100:.1f}%) '
              f'con algún valor infinito o nulo restante.')

    X = X[filas_validas].reset_index(drop=True)
    y = y[filas_validas].reset_index(drop=True)

    if len(X) == 0:
        print('\n[ERROR FATAL] Después de limpiar infinitos/nulos no quedó ninguna fila utilizable.')
        sys.exit(1)

    return X, y


# ==============================================================================
# 5. OPTIMIZACIÓN DE HIPERPARÁMETROS DE RANDOM FOREST (OPTIMIZADO PARA 16GB RAM)
# ==============================================================================

# ==============================================================================
# 5. OPTIMIZACIÓN DE HIPERPARÁMETROS DE RANDOM FOREST (MÁXIMA PROTECCIÓN RAM)
# ==============================================================================

def optimizar_hiperparametros(X_train, y_train):
    # Reducimos un poco más el límite por seguridad en equipos de 16GB
    LIMITE_SEGURO = 100_000 
    
    if len(X_train) > LIMITE_SEGURO:
        fraccion = LIMITE_SEGURO / len(X_train)
        X_busqueda, _, y_busqueda, _ = train_test_split(
            X_train, y_train, train_size=fraccion, stratify=y_train, random_state=SEMILLA
        )
        print(f'Dataset inmenso: la búsqueda usará una muestra de {len(X_busqueda):,} filas.')
    else:
        X_busqueda, y_busqueda = X_train, y_train

    # Reducimos ligeramente el peso máximo de los árboles para evitar 
    # que crezcan infinitamente y consuman toda la memoria
    espacio_parametros = {
        'n_estimators': [100, 150, 200],
        'max_depth': [15, 20, 25],
        'min_samples_split': [5, 10],
        'min_samples_leaf': [2, 4],
        'max_features': ['sqrt', 'log2'],
        'class_weight': ['balanced'],
        'criterion': ['gini', 'entropy'],
    }

    cv_estratificado = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEMILLA)

    gc.collect()

    # EL CAMBIO MAESTRO:
    # 1. El RandomForestClassifier usa 4 núcleos (n_jobs=4). Como usa hilos, comparte RAM.
    # 2. RandomizedSearchCV usa 1 núcleo (n_jobs=1). No duplica el dataset.
    busqueda = RandomizedSearchCV(
        estimator=RandomForestClassifier(random_state=SEMILLA, n_jobs=4),
        param_distributions=espacio_parametros,
        n_iter=15,                 # Bajamos un poco las iteraciones para compensar tiempo
        scoring='f1_weighted',
        cv=cv_estratificado,
        random_state=SEMILLA,
        n_jobs=1,                  # <-- CLAVE: Cero duplicación de memoria
        verbose=2,                 # verbose=2 muestra barra de progreso por cada intento
    )

    print('\nBuscando los mejores hiperparámetros de forma segura (sin saturar RAM)...')
    inicio = time.time()
    busqueda.fit(X_busqueda, y_busqueda)
    print(f'Búsqueda completada en {(time.time() - inicio) / 60:.1f} min.')
    print(f'Mejores hiperparámetros encontrados: {busqueda.best_params_}')

    # Liberar memoria pesada de los resultados
    del busqueda.cv_results_
    gc.collect()

    print('\nEntrenando el modelo FINAL con todos los datos de entrenamiento...')
    # Usamos los 4 núcleos directamente en el modelo final, igual que antes
    modelo_final = RandomForestClassifier(**busqueda.best_params_, random_state=SEMILLA, n_jobs=4)
    inicio = time.time()
    modelo_final.fit(X_train, y_train)
    print(f'Entrenamiento final completado en {(time.time() - inicio) / 60:.1f} min.')

    return modelo_final, busqueda.best_params_


# ==============================================================================
# 6. EVALUACIÓN
# ==============================================================================

def evaluar_modelo(modelo, X_test, y_test, carpeta_salida):
    y_pred = modelo.predict(X_test)

    exactitud = accuracy_score(y_test, y_pred)
    exactitud_balanceada = balanced_accuracy_score(y_test, y_pred)
    f1_ponderado = f1_score(y_test, y_pred, average='weighted')

    print(f'\n{"=" * 70}\nRESULTADOS DE EVALUACIÓN (conjunto de prueba)\n{"=" * 70}')
    print(f'Exactitud (accuracy):        {exactitud:.4f}')
    print(f'Exactitud balanceada:        {exactitud_balanceada:.4f}')
    print(f'F1 ponderado:                {f1_ponderado:.4f}')

    reporte = classification_report(y_test, y_pred, zero_division=0)
    print('\nReporte por clase (precision / recall / f1-score):')
    print(reporte)

    with open(os.path.join(carpeta_salida, 'reporte_clasificacion.txt'), 'w', encoding='utf-8') as f:
        f.write(f'Exactitud: {exactitud:.4f}\n')
        f.write(f'Exactitud balanceada: {exactitud_balanceada:.4f}\n')
        f.write(f'F1 ponderado: {f1_ponderado:.4f}\n\n')
        f.write(reporte)

    clases = sorted(y_test.unique())
    matriz = confusion_matrix(y_test, y_pred, labels=clases)

    plt.figure(figsize=(max(8, len(clases) * 1.1), max(6, len(clases) * 0.9)))
    plt.imshow(matriz, cmap='Blues')
    plt.colorbar(label='Cantidad de flujos')
    plt.xticks(range(len(clases)), clases, rotation=45, ha='right')
    plt.yticks(range(len(clases)), clases)
    plt.xlabel('Predicción del modelo')
    plt.ylabel('Etiqueta real')
    plt.title('Matriz de confusión')
    valor_medio = matriz.max() / 2
    for i in range(len(clases)):
        for j in range(len(clases)):
            color = 'white' if matriz[i, j] > valor_medio else 'black'
            plt.text(j, i, str(matriz[i, j]), ha='center', va='center', color=color, fontsize=8)
    plt.tight_layout()
    ruta_matriz = os.path.join(carpeta_salida, 'matriz_confusion.png')
    plt.savefig(ruta_matriz, dpi=150)
    plt.close()
    print(f'Matriz de confusión guardada en: {ruta_matriz}')

    importancias = pd.Series(modelo.feature_importances_, index=X_test.columns).sort_values(ascending=False)
    plt.figure(figsize=(10, max(6, min(20, len(importancias)) * 0.35)))
    importancias.head(20).sort_values().plot(kind='barh', color='#2b6cb0')
    plt.xlabel('Importancia relativa')
    plt.title('Características más relevantes para distinguir los ataques')
    plt.tight_layout()
    ruta_importancia = os.path.join(carpeta_salida, 'importancia_caracteristicas.png')
    plt.savefig(ruta_importancia, dpi=150)
    plt.close()
    importancias.to_csv(os.path.join(carpeta_salida, 'importancia_caracteristicas.csv'), header=['importancia'])
    print(f'Importancia de características guardada en: {ruta_importancia}')

    return {
        'exactitud': float(exactitud),
        'exactitud_balanceada': float(exactitud_balanceada),
        'f1_ponderado': float(f1_ponderado),
    }


# ==============================================================================
# 7. FUNCIÓN PRINCIPAL
# ==============================================================================

def leer_argumentos():
    import argparse
    global CARPETA_DATOS, CARPETA_SALIDA
    parser = argparse.ArgumentParser(description="Entrena modelo_rf_ids.joblib a partir de CSV generados por FlowEngine.")
    parser.add_argument("--datos", default=CARPETA_DATOS, help="Carpeta con los CSV etiquetados")
    parser.add_argument("--salida", default=CARPETA_SALIDA, help="Carpeta donde guardar el modelo y los reportes")
    args = parser.parse_args()
    CARPETA_DATOS, CARPETA_SALIDA = os.path.abspath(args.datos), os.path.abspath(args.salida)
    print(f"Datos : {CARPETA_DATOS}\nSalida: {CARPETA_SALIDA}\n")


def main():
    leer_argumentos()
    os.makedirs(CARPETA_SALIDA, exist_ok=True)

    print('PASO 1/6 — Cargando y unificando los CSV de la carpeta...')
    df = cargar_y_unificar_csvs(CARPETA_DATOS)

    if len(df) == 0:
        print('\n[ERROR FATAL] Se cargaron archivos CSV pero el resultado combinado tiene 0 filas.')
        sys.exit(1)

    print('\nDistribución final de clases:')
    print(df['Label'].value_counts().to_string())

    print('\nPASO 2/6 — Preparando variables (features)...')
    X, y = preparar_features(df)
    print(f'Features finales: {X.shape[1]} columnas numéricas, {len(X):,} filas utilizables.')

    with open(os.path.join(CARPETA_SALIDA, 'columnas_features.json'), 'w', encoding='utf-8') as f:
        json.dump(list(X.columns), f, ensure_ascii=False, indent=2)

    conteo_clases = y.value_counts()
    clases_insuficientes = conteo_clases[conteo_clases < MIN_MUESTRAS_POR_CLASE].index.tolist()
    if clases_insuficientes:
        print(f'\n[AVISO] Estas clases tienen menos de {MIN_MUESTRAS_POR_CLASE} muestras y se excluyen:')
        print(clases_insuficientes)
        mascara = ~y.isin(clases_insuficientes)
        X = X[mascara].reset_index(drop=True)
        y = y[mascara].reset_index(drop=True)

    if len(X) == 0:
        print(f'\n[ERROR FATAL] Después de excluir clases con pocas muestras no quedó ninguna fila.')
        sys.exit(1)

    # --- INICIO DEL BLOQUE COMPLETADO ---
    print(f'\nPASO 3/6 — Dividiendo en conjunto de entrenamiento y prueba ({(1-TAMANO_PRUEBA)*100:.0f}/{TAMANO_PRUEBA*100:.0f})...')
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TAMANO_PRUEBA, stratify=y, random_state=SEMILLA
    )
    
    # Limpiamos variables masivas que ya no necesitamos para ahorrar RAM
    del X, y, df
    gc.collect()

    print('\nPASO 4/6 — Optimizando hiperparámetros y entrenando...')
    modelo, mejores_parametros = optimizar_hiperparametros(X_train, y_train)

    print('\nPASO 5/6 — Evaluando modelo final...')
    evaluar_modelo(modelo, X_test, y_test, CARPETA_SALIDA)

    print('\nPASO 6/6 — Guardando modelo...')
    ruta_modelo = os.path.join(CARPETA_SALIDA, 'modelo_rf_ids.joblib')
    joblib.dump(modelo, ruta_modelo)
    print(f'Modelo guardado exitosamente en: {ruta_modelo}')

    print('\n¡PROCESO COMPLETADO EXITOSAMENTE!')


if __name__ == '__main__':
    main()
