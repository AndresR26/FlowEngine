# src/

🇪🇸 Código del programa principal. Todos los archivos deben estar juntos en esta carpeta (los módulos se importan entre sí y `compilar.py` los busca en el directorio actual).
🇬🇧 Main program source. All files must stay together in this folder (modules import each other and `compilar.py` looks for them in the current directory).

| Archivo / File | Descripción / Description |
|---|---|
| `flow_engine.py` | Punto de entrada y menú / Entry point and menu |
| `live_conf.py` | Captura en vivo + motor de flujos / Live capture + flow engine |
| `pcap_conf.py` | Procesamiento de PCAP / PCAP processing |
| `advanced_dataset_filters.py` | Filtros sobre CSV / CSV filters |
| `red_distribuida.py` | Lado Director / Director side |
| `agente_persistente.py` | Servicio del agente / Agent service |
| `compilar.py` | Compilación con PyInstaller / PyInstaller build |

```bash
python flow_engine.py   # ejecutar / run   (Windows: Administrador · Linux: sudo)
python compilar.py      # compilar / build -> dist/FlowEngine(.exe), dist/SensorAgente(.exe)
```
