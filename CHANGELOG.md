# Changelog

## [1.1.0] — 2026-11-03

### Corregido / Fixed
- Captura programada: el agente leía `delay_segundos` y el Director envía `retraso_segundos`; ahora arranca a la hora elegida. / Scheduled capture now starts at the chosen time (key mismatch fixed).
- El agente lanza `FlowEngine` (sin `.exe`) en Linux. / Agent launches `FlowEngine` (no `.exe`) on Linux.
- Filtros: `tcp.port` / `udp.port` ya no generan un filtro inválido y comparan puerto origen o destino. / Port filters no longer break and match either port.
- Filtros: las columnas de texto (`State`, `Service`, `DNS Qname`, `HTTP *`…) ya no se vacían al cargar el CSV. / Text columns are no longer emptied.
- Recepción en el Director: valida el token, sanea el nombre del archivo y lee los metadatos completos. / Director validates the token, sanitises file names and reads metadata fully.
- Rutas fijas `D:\...` sustituidas por parámetros en el entrenamiento y en el etiquetado con ground truth. / Hard-coded paths replaced with CLI arguments.

### Añadido / Added
- Token configurable con `token_red.txt` o `FLOWENGINE_TOKEN`. / Configurable token.
- `training/entrenar_modelo.py`, `tools/etiquetar_con_ground_truth.py`, `lab/lab_attacks.sh`.
- Documentación de los datasets publicados en Zenodo. / Documentation of the datasets published on Zenodo.

## [1.0.0] — 2026-11

- Captura en vivo manual/IA, procesamiento PCAP, filtros avanzados, captura distribuida Director–Agentes. / Live manual/AI capture, PCAP processing, advanced filters, distributed capture.
- Manuales técnico y de usuario (ES/EN) y diagramas de arquitectura. / Technical and user manuals (ES/EN) and architecture diagrams.
