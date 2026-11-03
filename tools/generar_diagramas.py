"""Genera los diagramas de arquitectura de red (ES/EN) para la documentación."""
import os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = sys.argv[1] if len(sys.argv) > 1 else "img"
os.makedirs(OUT, exist_ok=True)

NAVY, BLUE, GREEN, ORANGE = "#1B2A4A", "#2E5DA6", "#2F8F5B", "#B5541B"
GRAY, DARK, RED = "#6B7280", "#111827", "#8A2E2E"

T = {
 "es": {
  "topo_title": "Arquitectura de red – FlowEngine (Laboratorio IDS)",
  "topo_sub": "Topología Director – Agentes sobre una red local (LAN / misma subred)",
  "director": "PC DIRECTOR\nFlowEngine.exe\n(menú principal)",
  "dir_ports": "Escucha:\nTCP 51502 (recepción de CSV)\nEnvía:\nUDP 51500 broadcast\nTCP → 50050",
  "dir_store": "Carpeta: capturas_remotas/",
  "switch": "Switch / Router\nLAN 192.168.x.0/24",
  "agent": "PC AGENTE {n}\nSensorAgente.exe\n+ FlowEngine.exe\n+ modelo_rf_ids.joblib",
  "ag_ports": "Escucha: UDP 51500 · TCP 50050",
  "legend": ["UDP 51500 · descubrimiento (broadcast)", "TCP 50050 · orden de captura",
             "TCP 51502 · envío del CSV al Director"],
  "note": "Todos los equipos deben estar en la misma subred (el broadcast 255.255.255.255 no atraviesa routers).\n"
          "El firewall de cada equipo debe permitir los puertos indicados. Npcap (Windows) o root (Linux) es obligatorio para capturar.",
  "seq_title": "Secuencia de una captura remota",
  "seq_sub": "El mismo ciclo se repite con cada agente descubierto",
  "s_dir": "PC DIRECTOR\nFlowEngine.exe",
  "s_ag": "PC AGENTE\nSensorAgente.exe",
  "s_eng": "FlowEngine.exe\n(modo --captura-remota)",
  "s1": "1. Broadcast UDP 51500  {accion: ping, token}",
  "s2": "2. Respuesta UDP  {estado: activo, hostname, puerto_tcp}",
  "s3": "3. TCP 50050  {accion: capturar | capturar_programada, token, duracion, id_captura, director_ip}",
  "s3b": "4. Respuesta TCP  {estado: ok}",
  "s4": "5. Lanza subproceso",
  "s5": "6. Captura N segundos\ny etiqueta con IA",
  "s6": "7. TCP 51502  [4 bytes longitud][JSON metadatos][contenido CSV]",
  "s7": "Guarda capturas_remotas/<ip>_<archivo>.csv",
 },
 "en": {
  "topo_title": "Network architecture – FlowEngine (IDS Lab)",
  "topo_sub": "Director – Agents topology over a local network (LAN / same subnet)",
  "director": "DIRECTOR PC\nFlowEngine.exe\n(main menu)",
  "dir_ports": "Listens:\nTCP 51502 (CSV reception)\nSends:\nUDP 51500 broadcast\nTCP → 50050",
  "dir_store": "Folder: capturas_remotas/",
  "switch": "Switch / Router\nLAN 192.168.x.0/24",
  "agent": "AGENT PC {n}\nSensorAgente.exe\n+ FlowEngine.exe\n+ modelo_rf_ids.joblib",
  "ag_ports": "Listens: UDP 51500 · TCP 50050",
  "legend": ["UDP 51500 · discovery (broadcast)", "TCP 50050 · capture order",
             "TCP 51502 · CSV upload to Director"],
  "note": "All machines must be on the same subnet (255.255.255.255 broadcast does not cross routers).\n"
          "Each machine's firewall must allow the listed ports. Npcap (Windows) or root (Linux) is required to capture.",
  "seq_title": "Remote capture sequence",
  "seq_sub": "The same cycle repeats for every discovered agent",
  "s_dir": "DIRECTOR PC\nFlowEngine.exe",
  "s_ag": "AGENT PC\nSensorAgente.exe",
  "s_eng": "FlowEngine.exe\n(--captura-remota mode)",
  "s1": "1. UDP broadcast 51500  {accion: ping, token}",
  "s2": "2. UDP reply  {estado: activo, hostname, puerto_tcp}",
  "s3": "3. TCP 50050  {accion: capturar | capturar_programada, token, duracion, id_captura, director_ip}",
  "s3b": "4. TCP reply  {estado: ok}",
  "s4": "5. Spawns subprocess",
  "s5": "6. Captures N seconds\nwith AI labelling",
  "s6": "7. TCP 51502  [4-byte length][JSON metadata][CSV content]",
  "s7": "Saves capturas_remotas/<ip>_<file>.csv",
 },
}

def box(ax, x, y, w, h, text, fc, ec, fs=9, bold=True, color=DARK):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1",
                                lw=1.8, ec=ec, fc=fc, zorder=3))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", color=color, zorder=4, linespacing=1.35)

def arrow(ax, p1, p2, color, lw=2, ls="-", rad=0.0, both=False):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="<|-|>" if both else "-|>", mutation_scale=13,
                                 color=color, lw=lw, ls=ls, connectionstyle=f"arc3,rad={rad}", zorder=2))

def topology(lang):
    t = T[lang]
    fig, ax = plt.subplots(figsize=(12, 7.6), dpi=180)
    ax.set_xlim(0, 120); ax.set_ylim(0, 76); ax.axis("off")
    ax.text(60, 73, t["topo_title"], ha="center", fontsize=14, fontweight="bold", color=NAVY)
    ax.text(60, 70, t["topo_sub"], ha="center", fontsize=9.5, color=GRAY, style="italic")

    # Director
    box(ax, 3, 34, 24, 15, t["director"], "#DCE7FA", NAVY, fs=10)
    box(ax, 3, 15, 24, 15, t["dir_ports"], "white", NAVY, fs=7.8, bold=False)
    box(ax, 3, 8, 24, 4, t["dir_store"], "#F3F4F6", GRAY, fs=7.8, bold=False)

    # Switch
    box(ax, 46, 36, 22, 10, t["switch"], "#F3F4F6", GRAY, fs=9)

    # Agents
    ys = [52, 30, 8]
    for i, y in enumerate(ys, 1):
        box(ax, 88, y, 28, 13, t["agent"].format(n=i), "#E8F3EC", GREEN, fs=8.4)
        ax.text(102, y - 1.6, t["ag_ports"], ha="center", fontsize=7.2, color=GREEN)

    # Flujos lógicos: tres flechas paralelas por enlace (descubrimiento, orden, reporte)
    def triple(x1, y1, x2, y2):
        import math
        dx, dy = x2 - x1, y2 - y1
        L = math.hypot(dx, dy); nx, ny = -dy / L, dx / L
        for off, c, rev in ((1.6, BLUE, False), (0, NAVY, False), (-1.6, ORANGE, True)):
            p1 = (x1 + nx * off, y1 + ny * off); p2 = (x2 + nx * off, y2 + ny * off)
            arrow(ax, p2 if rev else p1, p1 if rev else p2, c, lw=1.8)
    triple(27.6, 41.5, 45.6, 41.5)
    for y, sy in zip(ys, (44.5, 41, 37.5)):
        triple(68.4, sy, 87.6, y + 6.5)
    # legend
    lx = 14
    for c, txt in zip([BLUE, NAVY, ORANGE], t["legend"]):
        ax.add_patch(FancyArrowPatch((lx, 3.2), (lx + 4, 3.2), arrowstyle="-|>", mutation_scale=12, color=c, lw=2))
        ax.text(lx + 5, 3.2, txt, va="center", fontsize=8, color=DARK)
        lx += 31
    ax.text(60, -1.5, t["note"], ha="center", va="top", fontsize=7.8, color=RED, linespacing=1.4)
    fig.savefig(f"{OUT}/topologia_red_{lang}.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)

def sequence(lang):
    t = T[lang]
    fig, ax = plt.subplots(figsize=(12, 8.2), dpi=180)
    ax.set_xlim(0, 120); ax.set_ylim(0, 82); ax.axis("off")
    ax.text(60, 80, t["seq_title"], ha="center", fontsize=14, fontweight="bold", color=NAVY)
    ax.text(60, 77, t["seq_sub"], ha="center", fontsize=9.5, color=GRAY, style="italic")
    xd, xa, xe = 14, 70, 104
    box(ax, xd - 11, 68, 22, 6, t["s_dir"], "#DCE7FA", NAVY, fs=9)
    box(ax, xa - 11, 68, 22, 6, t["s_ag"], "#E8F3EC", GREEN, fs=9)
    box(ax, xe - 13, 68, 26, 6, t["s_eng"], "#FFF4E5", ORANGE, fs=8.5)
    for x in (xd, xa, xe):
        ax.plot([x, x], [3, 67.6], color="#C3C9D5", lw=1.3, ls=(0, (4, 3)), zorder=1)

    def msg(y, x1, x2, color, text, ls="-"):
        arrow(ax, (x1, y), (x2, y), color, lw=1.9, ls=ls)
        ax.text((x1 + x2) / 2, y + 1.1, text, ha="center", va="bottom", fontsize=7.9, color=color,
                fontweight="bold", zorder=5, bbox=dict(fc="white", ec="none", pad=0.6))

    msg(62, xd, xa, BLUE, t["s1"])
    msg(55, xa, xd, GREEN, t["s2"], ls=(0, (4, 2)))
    msg(47, xd, xa, NAVY, "")
    ax.text((xd + xe) / 2 - 6, 48.2, t["s3"], ha="center", va="bottom", fontsize=7.6, color=NAVY,
            fontweight="bold", bbox=dict(fc="white", ec="none", pad=0.6))
    msg(40, xa, xd, GREEN, t["s3b"], ls=(0, (4, 2)))
    msg(33, xa, xe, ORANGE, t["s4"])
    box(ax, xe - 13, 20, 26, 8, t["s5"], "#FFF4E5", ORANGE, fs=8, bold=False)
    msg(13, xe, xd, ORANGE, t["s6"])
    box(ax, xd - 12, 3, 34, 5.5, t["s7"], "white", NAVY, fs=7.8, bold=False)
    fig.savefig(f"{OUT}/secuencia_captura_{lang}.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)

for lang in ("es", "en"):
    topology(lang)
    sequence(lang)
print("ok")


# ---------------------------------------------------------------- módulos
M = {
 "es": {"title": "Arquitectura del software – módulos de FlowEngine",
        "menu": "flow_engine.py\nMenú principal", "o1": "1. Manual", "o2": "2. IA", "o3": "3. PCAP",
        "o4": "4. Filtros", "o5": "5 / 6. Remota",
        "live": "live_conf.py\nrun() · run_ia()", "pcap": "pcap_conf.py\nrun()", "filt": "advanced_dataset_\nfilters.py",
        "red": "red_distribuida.py\nDirectorRed", "eng": "Motor de flujos\nAnalyzer + Flow",
        "out": "CSV · PCAP\nlabels_log.csv", "model": "modelo_rf_ids\n.joblib", "agent": "agente_persistente.py\n(SensorAgente)",
        "remote": "FlowEngine\n--captura-remota", "net": "UDP 51500 · TCP 50050 · TCP 51502", "fcsv": "dataset_filtrado_\navanzado.csv"},
 "en": {"title": "Software architecture – FlowEngine modules",
        "menu": "flow_engine.py\nMain menu", "o1": "1. Manual", "o2": "2. AI", "o3": "3. PCAP",
        "o4": "4. Filters", "o5": "5 / 6. Remote",
        "live": "live_conf.py\nrun() · run_ia()", "pcap": "pcap_conf.py\nrun()", "filt": "advanced_dataset_\nfilters.py",
        "red": "red_distribuida.py\nDirectorRed", "eng": "Flow engine\nAnalyzer + Flow",
        "out": "CSV · PCAP\nlabels_log.csv", "model": "modelo_rf_ids\n.joblib", "agent": "agente_persistente.py\n(SensorAgente)",
        "remote": "FlowEngine\n--captura-remota", "net": "UDP 51500 · TCP 50050 · TCP 51502", "fcsv": "dataset_filtrado_\navanzado.csv"},
}

def modules(lang):
    t = M[lang]
    fig, ax = plt.subplots(figsize=(12, 7), dpi=180)
    ax.set_xlim(0, 120); ax.set_ylim(0, 70); ax.axis("off")
    ax.text(60, 67, t["title"], ha="center", fontsize=14, fontweight="bold", color=NAVY)
    box(ax, 48, 54, 24, 8, t["menu"], "#DCE7FA", NAVY, fs=10)
    cols = [(8, "live", t["o1"] + " / " + t["o2"]), (40, "pcap", t["o3"]), (68, "filt", t["o4"]), (96, "red", t["o5"])]
    for x, key, lab in cols:
        box(ax, x, 36, 20, 8, t[key], "white", BLUE, fs=8.6)
        arrow(ax, (60, 53.6), (x + 10, 44.4), BLUE, lw=1.5)
        ax.text((60 + x + 10) / 2 + (2 if x > 50 else -2), 49.5, lab, ha="center", fontsize=7.8, color=BLUE,
                bbox=dict(fc="white", ec="none", pad=0.5))
    box(ax, 18, 20, 30, 8, t["eng"], "#FFF4E5", ORANGE, fs=9)
    arrow(ax, (18, 35.6), (28, 28.4), ORANGE); arrow(ax, (50, 35.6), (40, 28.4), ORANGE)
    box(ax, 4, 5, 20, 7, t["out"], "#F3F4F6", GRAY, fs=8, bold=False)
    box(ax, 30, 5, 18, 7, t["model"], "#F3F4F6", GRAY, fs=8, bold=False)
    arrow(ax, (26, 19.6), (14, 12.4), GRAY); arrow(ax, (39, 12.4), (36, 19.6), GRAY, ls=(0, (3, 2)))
    box(ax, 66, 22, 20, 6, t["fcsv"], "#F3F4F6", GRAY, fs=7.8, bold=False)
    arrow(ax, (78, 35.6), (76, 28.4), GRAY)
    box(ax, 94, 18, 24, 8, t["agent"], "#E8F3EC", GREEN, fs=8.4)
    arrow(ax, (106, 35.6), (106, 26.4), GREEN, both=True)
    ax.text(107.5, 31, t["net"], fontsize=7, color=GREEN, ha="left", rotation=0)
    box(ax, 94, 4, 24, 8, t["remote"], "#FFF4E5", ORANGE, fs=8.4)
    arrow(ax, (106, 17.6), (106, 12.4), GREEN)
    arrow(ax, (93.6, 8), (48.4, 8), GRAY, ls=(0, (3, 2)))
    fig.savefig(f"{OUT}/modulos_software_{lang}.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)

for lang in ("es", "en"):
    modules(lang)
