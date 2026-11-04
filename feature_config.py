ALL_FEATURES = [
    # ===== BASICAS =====
    "Destination Port","Protocol","Flow Duration",

    # ===== PACKETS =====
    "Total Fwd Packets","Total Backward Packets",
    "Total Length Fwd Packets","Total Length Bwd Packets",

    "Source IP","Destination IP",
    "Source Port",
    "State",

    "Src Packets","Dst Packets",
    "Src Bytes","Dst Bytes",

    # ===== LONGITUD =====
    "Packet Length Mean","Packet Length Std",
    "Packet Length Max","Packet Length Min",

    "Fwd Packet Length Mean","Bwd Packet Length Mean",

    # ===== IAT =====
    "Flow IAT Mean","Flow IAT Std",
    "Fwd IAT Mean","Fwd IAT Std",
    "Bwd IAT Mean","Bwd IAT Std",

    # ===== ACTIVIDAD =====
    "Active Mean","Active Std",
    "Idle Mean","Idle Std",

    # ===== BULK =====
    "Fwd Bulk Packets","Bwd Bulk Packets",
    "Fwd Bulk Bytes","Bwd Bulk Bytes",

    # ===== VELOCIDAD =====
    "Flow Bytes/s","Flow Packets/s",

    # ===== NUEVAS NB-15 (RATE / LOAD) =====
    "Src Rate","Dst Rate",
    "Src Load","Dst Load",

    # ===== TTL =====
    "Src TTL","Dst TTL",

    # ===== FLAGS =====
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",

    # ===== RATIO =====
    "Down/Up Ratio",

    # ===== LABEL =====
    "Label"
]

DEFAULT_FEATURES = ALL_FEATURES.copy()


def seleccionar_features():

    print("\nCONFIGURACIÓN DE VARIABLES")

    print("1️⃣ Usar Configuracion predeterminada")
    print("2️⃣ Personalizar")
    opcion = input("\nSelecciona: ")

    if opcion == "1":
        return DEFAULT_FEATURES, {}

    print("\nVariables disponibles:\n")
    for i, f in enumerate(ALL_FEATURES):
        print(f"{i+1}. {f}")

    seleccion = input("\nSelecciona variables (ej: 1,2,5): ")
    indices = [int(x.strip()) - 1 for x in seleccion.split(",")]

    selected = [ALL_FEATURES[i] for i in indices]

    
    custom = {}

    print("\n¿Deseas agregar variables nuevas? (s/n)")
    if input().lower() == "s":

        while True:

            name = input("\nNombre de la nueva variable: ")

            print("Ejemplo de uso: Flow_Duration, Total_Fwd_Packets")
            expr = input("Expresión: ")

            custom[name] = expr

            if input("¿Agregar otra? (s/n): ").lower() != "s":
                break

    return selected, custom
