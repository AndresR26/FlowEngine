import pandas as pd
import tkinter as tk
from tkinter import filedialog
import re
import os


def seleccionar_dataset():

    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)

    archivo = filedialog.askopenfilename(
        title="Seleccionar dataset CSV",
        filetypes=[("CSV files", "*.csv")]
    )

    root.destroy()
    return archivo


def convertir_columnas_numericas(df):
    """CORREGIDO: antes se forzaba a número toda columna salvo 4 fijas, y las columnas
    de texto (State, Service, SNI, JA3, DNS Qname, HTTP ...) quedaban vacías (NaN).
    Ahora una columna solo se convierte si TODOS sus valores no vacíos son numéricos."""

    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            continue
        convertida = pd.to_numeric(df[col], errors="coerce")
        if convertida.notna().sum() == df[col].notna().sum():
            df[col] = convertida

    return df


def traducir_filtro(filtro):
    """Traduce una sintaxis tipo Wireshark a pandas.query().
    CORREGIDO: antes 'tcp' se reemplazaba también dentro de 'tcp.port', dejando un
    filtro inválido ("Protocol == 'TCP'.port == 80"). Ahora los campos con punto se
    traducen primero y 'tcp'/'udp' solo se reemplazan como palabra suelta.
    'tcp.port == 80' coincide con el puerto de origen O de destino, como en Wireshark."""

    operadores = {
        "&&": " and ",
        "||": " or ",
    }
    for k, v in operadores.items():
        filtro = filtro.replace(k, v)

    # tcp.port / udp.port <op> <número>  ->  protocolo + (puerto origen o destino)
    def _puerto(m):
        proto, op, valor = m.group(1).upper(), m.group(2), m.group(3)
        return (f"(Protocol == '{proto}' and "
                f"(`Source Port` {op} {valor} or `Destination Port` {op} {valor}))")
    filtro = re.sub(r"\b(tcp|udp)\.port\s*(==|!=|>=|<=|>|<)\s*(\d+)", _puerto, filtro)

    filtro = filtro.replace("ip.src", "`Source IP`")
    filtro = filtro.replace("ip.dst", "`Destination IP`")

    # 'tcp' / 'udp' sueltos (no dentro de comillas, backticks ni nombres con punto)
    for k, v in {"tcp": "Protocol == 'TCP'", "udp": "Protocol == 'UDP'"}.items():
        filtro = re.sub(rf"(?<![\w.'`\"]){k}(?![\w.'`\"])", v, filtro)

    return " ".join(filtro.split())


def crear_variable(df):

    print("\nCrear variable derivada")

    nombre = input("Nombre de la variable: ")

    print("\nPuedes usar columnas del dataset.")
    print("Ejemplo:")
    print("`Fwd Pkt Len Max` / `Pkt Size Mean`")

    expresion = input("\nExpresión: ")

    try:

        df[nombre] = df.eval(expresion)

        print(f"Variable '{nombre}' creada correctamente")

    except Exception as e:

        print("Error:", e)

    return df


def aplicar_filtro(df):

    print("\nEscribe filtro")

    print("\nEjemplos:")
    print("tcp")
    print("udp")
    print("tcp.port == 80")
    print("ip.src == '192.168.1.10'")
    print("tcp && `Pkt Size Mean` > 500")

    filtro = input("\nFiltro: ")

    try:

        filtro_pandas = traducir_filtro(filtro)

        df_filtrado = df.query(filtro_pandas)

        print("\nFiltrado aplicado")
        print(f"Filas restantes: {len(df_filtrado)}")

        return df_filtrado

    except Exception as e:

        print("Error en filtro:", e)

        return df


def guardar_dataset(df, original):

    carpeta = os.path.dirname(original)

    salida = os.path.join(carpeta, "dataset_filtrado_avanzado.csv")

    df.to_csv(salida, index=False)

    print("\nDataset guardado en:")
    print(salida)


def mostrar_columnas(df):

    print("\nColumnas disponibles:\n")

    for c in df.columns:
        print(c)


def run():

    print("\nSelecciona dataset")

    path = seleccionar_dataset()

    if not path:
        print("No se seleccionó archivo")
        return

    df = pd.read_csv(path)

    # Conversión automática a numérico
    df = convertir_columnas_numericas(df)

    print(f"\nDataset cargado: {len(df)} filas")

    while True:

        print("\n==========================")
        print("1 Ver columnas")
        print("2 Crear variable")
        print("3 Aplicar filtro")
        print("4 Guardar dataset")
        print("5 Salir")
        print("==========================")

        opcion = input("Opción: ")

        if opcion == "1":

            mostrar_columnas(df)

        elif opcion == "2":

            df = crear_variable(df)

        elif opcion == "3":

            df = aplicar_filtro(df)

        elif opcion == "4":

            guardar_dataset(df, path)

        elif opcion == "5":

            break

        else:

            print("Opción inválida")
