# lab/

> ⚠️ **Solo para un laboratorio aislado y propio.** Este script lanza ataques reales (escaneos, fuerza bruta, inundaciones DoS, inyección SQL, ARP spoofing). Usarlo contra equipos o redes sin autorización es ilegal.
> ⚠️ **Isolated, self-owned lab only.** This script launches real attacks (scans, brute force, DoS floods, SQL injection, ARP spoofing). Using it against machines or networks you are not authorised to test is illegal.

🇪🇸 **`lab_attacks.sh`** genera el tráfico de ataque con el que se construyeron los datasets. Se ejecuta en la máquina atacante (Kali/Debian) mientras FlowEngine captura en modo manual (opción 1) desde el sensor: antes de cada ataque el script se detiene y te indica la etiqueta que debes escribir en FlowEngine.
🇬🇧 **`lab_attacks.sh`** generates the attack traffic used to build the datasets. Run it on the attacker machine (Kali/Debian) while FlowEngine captures in manual mode (option 1) on the sensor: before each attack the script pauses and tells you which label to type in FlowEngine.

Topología por defecto / Default topology (editable al inicio del script / editable at the top of the script): atacante `192.168.1.30`, víctima `192.168.1.10` (DVWA), cliente `192.168.1.20`, sensor `192.168.1.40` en puerto espejo / on a mirror port.

```bash
sudo ./lab_attacks.sh setup            # instala herramientas / installs tools
sudo ./lab_attacks.sh portscan         # una categoría / one category
sudo ./lab_attacks.sh --sin-setup todo # todas, sin reinstalar / all, no reinstall
```

| Categoría / Category | Herramientas / Tools | Etiqueta / Label | Duración / Duration |
|---|---|---|---|
| `portscan` | nmap (SYN, FIN, XMAS, NULL, UDP, OS/versión) | `portscan` | ~18 min |
| `bruteforce` | hydra (FTP, SSH) | `bruteforce` | ~6 min |
| `dos` | hping3 (SYN/UDP/ICMP flood), slowloris, slowhttptest | `dos` | ~15 min + pausas |
| `fuzzer` | ffuf | `fuzzer` | ~3 min |
| `webattack` | sqlmap contra DVWA | `webattack` | ~3 min |
| `mitm` | bettercap (ARP spoofing) | `mitm` | ~3 min |
