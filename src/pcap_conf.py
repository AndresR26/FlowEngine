from scapy.all import *
import numpy as np
import os
import csv
import math
import hashlib
import tkinter as tk

from tkinter import filedialog
from collections import defaultdict, deque, Counter
from datetime import datetime


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "csv_file": "pcap_resultado1.csv",

    "min_packets": 5,
    "time_window": 60,

    "flow_timeout": 30,
    "active_gap": 1.0,

    "save_pcap": False,
}


# ============================================================
# IMPORTS SEGUROS
# ============================================================

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except Exception:
    HTTPRequest = HTTPResponse = None


try:
    from scapy.layers.dns import DNS
except Exception:
    DNS = None


try:
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Beacon,
        Dot11Auth,
        Dot11Deauth,
        Dot11ProbeReq
    )
except Exception:
    Dot11 = None
    Dot11Beacon = None
    Dot11Auth = None
    Dot11Deauth = None
    Dot11ProbeReq = None


# ============================================================
# GREASE TLS
# ============================================================

GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


# ============================================================
# ENTROPÍA
# ============================================================

def _entropia(data: bytes) -> float:

    if not data:
        return 0.0

    n = len(data)

    counts = Counter(data)

    return -sum(
        (c / n) * math.log2(c / n)
        for c in counts.values()
    )


# ============================================================
# TLS CLIENT HELLO
# ============================================================

def analizar_tls_clienthello(payload: bytes):

    try:

        if len(payload) < 43:
            return None

        idx = 0

        # TLS record type
        if payload[idx] != 0x16:
            return None

        idx += 5

        # Handshake type = ClientHello
        if payload[idx] != 0x01:
            return None

        idx += 4

        tls_version = int.from_bytes(
            payload[idx:idx + 2],
            "big"
        )

        idx += 2 + 32

        session_id_len = payload[idx]

        idx += 1 + session_id_len

        if idx + 2 > len(payload):
            return None

        cipher_len = int.from_bytes(
            payload[idx:idx + 2],
            "big"
        )

        idx += 2

        ciphers = [
            int.from_bytes(
                payload[idx + i:idx + i + 2],
                "big"
            )
            for i in range(0, cipher_len, 2)
            if idx + i + 2 <= len(payload)
        ]

        idx += cipher_len

        if idx >= len(payload):

            return {
                "sni": None,
                "tls_version": tls_version,
                "ciphers": ciphers,
                "extensions": [],
                "curves": [],
                "point_formats": []
            }

        comp_len = payload[idx]

        idx += 1 + comp_len

        if idx + 2 > len(payload):

            return {
                "sni": None,
                "tls_version": tls_version,
                "ciphers": ciphers,
                "extensions": [],
                "curves": [],
                "point_formats": []
            }

        ext_total = int.from_bytes(
            payload[idx:idx + 2],
            "big"
        )

        idx += 2

        end = min(
            idx + ext_total,
            len(payload)
        )

        sni = None

        extensions = []
        curves = []
        point_formats = []

        while idx + 4 <= end:

            ext_type = int.from_bytes(
                payload[idx:idx + 2],
                "big"
            )

            ext_len = int.from_bytes(
                payload[idx + 2:idx + 4],
                "big"
            )

            data0 = idx + 4

            if data0 + ext_len > len(payload):
                break

            extensions.append(ext_type)

            # ------------------------------------------------
            # SNI
            # ------------------------------------------------

            if ext_type == 0x0000:

                try:

                    if ext_len >= 5:

                        name_type = payload[data0 + 2]

                        name_len = int.from_bytes(
                            payload[data0 + 3:data0 + 5],
                            "big"
                        )

                        name_start = data0 + 5

                        if (
                            name_start + name_len
                            <= len(payload)
                        ):

                            sni = payload[
                                name_start:
                                name_start + name_len
                            ].decode(
                                "utf-8",
                                errors="ignore"
                            )

                except Exception:
                    pass

            # ------------------------------------------------
            # Supported Groups
            # ------------------------------------------------

            elif ext_type == 0x000a:

                try:

                    if ext_len >= 2:

                        l = int.from_bytes(
                            payload[data0:data0 + 2],
                            "big"
                        )

                        raw = payload[
                            data0 + 2:
                            data0 + 2 + l
                        ]

                        curves = [
                            int.from_bytes(
                                raw[i:i + 2],
                                "big"
                            )
                            for i in range(
                                0,
                                len(raw) - 1,
                                2
                            )
                        ]

                except Exception:
                    pass

            # ------------------------------------------------
            # EC Point Formats
            # ------------------------------------------------

            elif ext_type == 0x000b:

                try:

                    if ext_len >= 1:

                        l = payload[data0]

                        point_formats = list(
                            payload[
                                data0 + 1:
                                data0 + 1 + l
                            ]
                        )

                except Exception:
                    pass

            idx = data0 + ext_len

        return {
            "sni": sni,
            "tls_version": tls_version,
            "ciphers": ciphers,
            "extensions": extensions,
            "curves": curves,
            "point_formats": point_formats
        }

    except Exception:

        return None


# ============================================================
# JA3
# ============================================================

def calcular_ja3(tls_info: dict):

    if not tls_info:
        return None

    ciphers = [
        c
        for c in tls_info.get("ciphers", [])
        if c not in GREASE_VALUES
    ]

    exts = [
        e
        for e in tls_info.get("extensions", [])
        if e not in GREASE_VALUES
    ]

    curves = [
        c
        for c in tls_info.get("curves", [])
        if c not in GREASE_VALUES
    ]

    pfmts = tls_info.get(
        "point_formats",
        []
    )

    ja3_str = "{},{},{},{},{}".format(
        tls_info.get(
            "tls_version",
            0
        ),

        "-".join(
            str(c)
            for c in ciphers
        ),

        "-".join(
            str(e)
            for e in exts
        ),

        "-".join(
            str(c)
            for c in curves
        ),

        "-".join(
            str(p)
            for p in pfmts
        )
    )

    return hashlib.md5(
        ja3_str.encode()
    ).hexdigest()


# ============================================================
# DETECCIÓN DE PROTOCOLO
# ============================================================

def detectar_protocolo(pkt):

    # --------------------------------------------------------
    # 802.11
    # --------------------------------------------------------

    if Dot11 and pkt.haslayer(Dot11):

        if (
            Dot11Beacon
            and pkt.haslayer(Dot11Beacon)
        ):
            return "802.11_Beacon"

        if (
            Dot11Auth
            and pkt.haslayer(Dot11Auth)
        ):
            return "802.11_Auth"

        if (
            Dot11Deauth
            and pkt.haslayer(Dot11Deauth)
        ):
            return "802.11_Deauth"

        if (
            Dot11ProbeReq
            and pkt.haslayer(Dot11ProbeReq)
        ):
            return "802.11_ProbeReq"

        return "802.11_Other"

    # --------------------------------------------------------
    # ARP
    # --------------------------------------------------------

    if pkt.haslayer(ARP):
        return "ARP"

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    if pkt.haslayer(ICMP):
        return "ICMP"

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if pkt.haslayer(TCP):
        return "TCP"

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if pkt.haslayer(UDP):
        return "UDP"

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    if pkt.haslayer(IP):
        return "IP"

    return "OTHER"


# ============================================================
# SERVICE + PAYLOAD
# ============================================================

def detectar_service_y_payload(pkt):

    info = {

        "service": "unknown",

        "sni": None,
        "ja3": None,
        "tls_version": None,

        "dns_qname": None,
        "dns_qtype": None,
        "dns_rcode": None,
        "dns_ancount": None,

        "http_method": None,
        "http_host": None,
        "http_uri": None,
        "http_ua": None,
        "http_status": None,
        "http_len": None,

        "entropy": None,
    }

    # ========================================================
    # DNS
    # ========================================================

    if DNS and pkt.haslayer(DNS):

        info["service"] = "dns"

        dns = pkt[DNS]

        try:

            if dns.qd is not None:

                info["dns_qname"] = (
                    dns.qd.qname
                    .decode(
                        errors="ignore"
                    )
                    .rstrip(".")
                )

                info["dns_qtype"] = int(
                    dns.qd.qtype
                )

        except Exception:
            pass

        if dns.qr == 1:

            try:

                info["dns_rcode"] = int(
                    dns.rcode
                )

                info["dns_ancount"] = int(
                    dns.ancount
                )

            except Exception:
                pass

        return info

    # ========================================================
    # HTTP REQUEST
    # ========================================================

    if (
        HTTPRequest
        and pkt.haslayer(HTTPRequest)
    ):

        info["service"] = "http"

        req = pkt[HTTPRequest]

        try:

            info["http_method"] = (
                req.Method.decode(
                    errors="ignore"
                )
                if req.Method
                else None
            )

            info["http_host"] = (
                req.Host.decode(
                    errors="ignore"
                )
                if req.Host
                else None
            )

            info["http_uri"] = (
                req.Path.decode(
                    errors="ignore"
                )
                if req.Path
                else None
            )

            info["http_ua"] = (
                req.User_Agent.decode(
                    errors="ignore"
                )
                if req.User_Agent
                else None
            )

        except Exception:
            pass

        return info

    # ========================================================
    # HTTP RESPONSE
    # ========================================================

    if (
        HTTPResponse
        and pkt.haslayer(HTTPResponse)
    ):

        info["service"] = "http"

        resp = pkt[HTTPResponse]

        try:

            info["http_status"] = (
                int(resp.Status_Code)
                if resp.Status_Code
                else None
            )

        except Exception:
            pass

        try:

            info["http_len"] = (
                int(resp.Content_Length)
                if resp.Content_Length
                else None
            )

        except Exception:
            pass

        return info

    # ========================================================
    # PORT MAP
    # ========================================================

    port_map = {

        80: "http",
        443: "https",

        21: "ftp",
        22: "ssh",
        23: "telnet",

        25: "smtp",

        53: "dns",

        110: "pop3",
        143: "imap",

        123: "ntp",

        137: "netbios",
        138: "netbios",
        139: "smb",
        445: "smb",

        3389: "rdp",

        3306: "mysql",
        1433: "mssql",
        5432: "postgresql",

        1900: "ssdp",

        1883: "mqtt",
    }

    # ========================================================
    # TCP
    # ========================================================

    if pkt.haslayer(TCP):

        port = min(
            pkt[TCP].sport,
            pkt[TCP].dport
        )

        raw = (
            bytes(
                pkt[TCP].payload
            )
            if pkt[TCP].payload
            else b""
        )

        if raw:

            info["entropy"] = _entropia(
                raw
            )

            tls_info = (
                analizar_tls_clienthello(
                    raw
                )
            )

            if tls_info:

                info["sni"] = (
                    tls_info["sni"]
                )

                info["tls_version"] = (
                    tls_info["tls_version"]
                )

                info["ja3"] = (
                    calcular_ja3(
                        tls_info
                    )
                )

        is_tls = (
            port == 443
            or (
                len(raw) > 0
                and raw[0] == 0x16
            )
        )

        info["service"] = port_map.get(
            port,
            "https"
            if is_tls
            else "other"
        )

        return info

    # ========================================================
    # UDP
    # ========================================================

    if pkt.haslayer(UDP):

        port = min(
            pkt[UDP].sport,
            pkt[UDP].dport
        )

        raw = (
            bytes(
                pkt[UDP].payload
            )
            if pkt[UDP].payload
            else b""
        )

        if raw:

            info["entropy"] = _entropia(
                raw
            )

        info["service"] = port_map.get(
            port,
            "other"
        )

        return info

    return info


# ============================================================
# FLOW
# ============================================================

class Flow:

    def __init__(self, fid):

        self.fid = fid

        # ----------------------------------------------------
        # Packet sizes
        # ----------------------------------------------------

        self.fwd_sizes = []
        self.bwd_sizes = []

        # ----------------------------------------------------
        # Packet times
        # ----------------------------------------------------

        self.fwd_times = []
        self.bwd_times = []

        # ----------------------------------------------------
        # TTL
        # ----------------------------------------------------

        self.fwd_ttl = []
        self.bwd_ttl = []

        # ----------------------------------------------------
        # States / services
        # ----------------------------------------------------

        self.states = []
        self.services = []

        self.sni_list = []

        # ----------------------------------------------------
        # Time
        # ----------------------------------------------------

        self.start = None
        self.end = None
        self.last_seen = None

        # ----------------------------------------------------
        # TCP timing
        # ----------------------------------------------------

        self.syn_time = None
        self.synack_time = None
        self.ack_time = None

        # ----------------------------------------------------
        # TCP flags
        # ----------------------------------------------------

        self.syn_cnt = 0
        self.fin_cnt = 0
        self.rst_cnt = 0
        self.psh_cnt = 0
        self.ack_cnt = 0

        self.urg_cnt = 0
        self.ece_cnt = 0
        self.cwr_cnt = 0

        self.fwd_psh_cnt = 0
        self.bwd_psh_cnt = 0

        self.fwd_urg_cnt = 0
        self.bwd_urg_cnt = 0

        self.flag_signature = "none"

        self.fin_fwd = False
        self.fin_bwd = False

        # ----------------------------------------------------
        # TCP Window
        # ----------------------------------------------------

        self.fwd_win_init = None
        self.bwd_win_init = None

        self.zero_win_cnt = 0

        # ----------------------------------------------------
        # Retransmission
        # ----------------------------------------------------

        self.fwd_seen_seq = set()
        self.bwd_seen_seq = set()

        self.fwd_retrans = 0
        self.bwd_retrans = 0

        # ----------------------------------------------------
        # Fragmentation
        # ----------------------------------------------------

        self.frag_cnt = 0
        self.df_cnt = 0

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        self.ja3_list = []
        self.tls_version_list = []

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        self.dns_qname_list = []
        self.dns_qtype_list = []

        self.dns_rcode_list = []
        self.dns_ancount_list = []

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        self.http_method_list = []
        self.http_host_list = []
        self.http_uri_list = []

        self.http_ua_list = []
        self.http_status_list = []
        self.http_len_list = []

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        self.icmp_type_list = []
        self.icmp_code_list = []

        # ----------------------------------------------------
        # Entropy
        # ----------------------------------------------------

        self.entropy_list = []

    # ========================================================
    # ADD
    # ========================================================

    def add(
        self,
        pkt,
        direction
    ):

        t = float(
            pkt.time
        )

        size = len(pkt)

        if self.start is None:

            self.start = t

        self.end = t

        self.last_seen = t

        # ----------------------------------------------------
        # TTL
        # ----------------------------------------------------

        ttl = (
            pkt[IP].ttl
            if pkt.haslayer(IP)
            else 0
        )

        # ----------------------------------------------------
        # Direction
        # ----------------------------------------------------

        if direction == "FWD":

            self.fwd_sizes.append(
                size
            )

            self.fwd_times.append(
                t
            )

            self.fwd_ttl.append(
                ttl
            )

        else:

            self.bwd_sizes.append(
                size
            )

            self.bwd_times.append(
                t
            )

            self.bwd_ttl.append(
                ttl
            )

        # ====================================================
        # IP FRAGMENTATION
        # ====================================================

        if pkt.haslayer(IP):

            ip = pkt[IP]

            try:

                if (
                    ip.flags.MF
                    or ip.frag > 0
                ):

                    self.frag_cnt += 1

                if ip.flags.DF:

                    self.df_cnt += 1

            except Exception:
                pass

        # ====================================================
        # ICMP
        # ====================================================

        if pkt.haslayer(ICMP):

            self.icmp_type_list.append(
                pkt[ICMP].type
            )

            self.icmp_code_list.append(
                pkt[ICMP].code
            )

        # ====================================================
        # SERVICE
        # ====================================================

        info = (
            detectar_service_y_payload(
                pkt
            )
        )

        self.services.append(
            info["service"]
        )

        # ----------------------------------------------------
        # SNI
        # ----------------------------------------------------

        if info["sni"]:

            self.sni_list.append(
                info["sni"]
            )

        # ----------------------------------------------------
        # JA3
        # ----------------------------------------------------

        if info["ja3"]:

            self.ja3_list.append(
                info["ja3"]
            )

        # ----------------------------------------------------
        # TLS
        # ----------------------------------------------------

        if (
            info["tls_version"]
            is not None
        ):

            self.tls_version_list.append(
                info["tls_version"]
            )

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        if (
            info["dns_qname"]
            is not None
        ):

            self.dns_qname_list.append(
                info["dns_qname"]
            )

            self.dns_qtype_list.append(
                info["dns_qtype"]
            )

        if (
            info["dns_rcode"]
            is not None
        ):

            self.dns_rcode_list.append(
                info["dns_rcode"]
            )

            self.dns_ancount_list.append(
                info["dns_ancount"]
            )

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        if (
            info["http_method"]
            is not None
        ):

            self.http_method_list.append(
                info["http_method"]
            )

            self.http_host_list.append(
                info["http_host"]
            )

            self.http_uri_list.append(
                info["http_uri"]
            )

            self.http_ua_list.append(
                info["http_ua"]
            )

        if (
            info["http_status"]
            is not None
        ):

            self.http_status_list.append(
                info["http_status"]
            )

            self.http_len_list.append(
                info["http_len"]
            )

        # ----------------------------------------------------
        # Entropy
        # ----------------------------------------------------

        if (
            info["entropy"]
            is not None
        ):

            self.entropy_list.append(
                info["entropy"]
            )

        # ====================================================
        # TCP
        # ====================================================

        if pkt.haslayer(TCP):

            tcp = pkt[TCP]

            f = int(
                tcp.flags
            )

            # ------------------------------------------------
            # FLAGS
            # ------------------------------------------------

            if f & 0x02:
                self.syn_cnt += 1

            if f & 0x01:
                self.fin_cnt += 1

            if f & 0x04:
                self.rst_cnt += 1

            if f & 0x08:

                self.psh_cnt += 1

                if direction == "FWD":
                    self.fwd_psh_cnt += 1
                else:
                    self.bwd_psh_cnt += 1

            if f & 0x10:
                self.ack_cnt += 1

            if f & 0x20:

                self.urg_cnt += 1

                if direction == "FWD":
                    self.fwd_urg_cnt += 1
                else:
                    self.bwd_urg_cnt += 1

            if f & 0x40:
                self.ece_cnt += 1

            if f & 0x80:
                self.cwr_cnt += 1

            # ------------------------------------------------
            # Scan signatures
            # ------------------------------------------------

            core = f & 0x3F

            if core == 0x00:

                self.flag_signature = (
                    "null_scan"
                )

            elif core == 0x29:

                self.flag_signature = (
                    "xmas_scan"
                )

            elif (
                core == 0x01
                and
                self.flag_signature
                == "none"
            ):

                self.flag_signature = (
                    "fin_scan"
                )

            # ------------------------------------------------
            # TCP Window
            # ------------------------------------------------

            if tcp.window == 0:

                self.zero_win_cnt += 1

            if (
                direction == "FWD"
                and
                self.fwd_win_init
                is None
            ):

                self.fwd_win_init = (
                    tcp.window
                )

            if (
                direction == "BWD"
                and
                self.bwd_win_init
                is None
            ):

                self.bwd_win_init = (
                    tcp.window
                )

            # ------------------------------------------------
            # Retransmission
            # ------------------------------------------------

            has_payload = (
                len(
                    bytes(
                        tcp.payload
                    )
                ) > 0
            )

            if direction == "FWD":

                if (
                    has_payload
                    and
                    tcp.seq
                    in
                    self.fwd_seen_seq
                ):

                    self.fwd_retrans += 1

                self.fwd_seen_seq.add(
                    tcp.seq
                )

            else:

                if (
                    has_payload
                    and
                    tcp.seq
                    in
                    self.bwd_seen_seq
                ):

                    self.bwd_retrans += 1

                self.bwd_seen_seq.add(
                    tcp.seq
                )

            # ------------------------------------------------
            # FIN direction
            # ------------------------------------------------

            if f & 0x01:

                if direction == "FWD":

                    self.fin_fwd = True

                else:

                    self.fin_bwd = True

            # ------------------------------------------------
            # TCP State
            # ------------------------------------------------

            if (
                f & 0x3F
            ) == 0x02:

                self.syn_time = t

                self.states.append(
                    "S0"
                )

            elif (
                f & 0x12
            ) == 0x12:

                self.synack_time = t

                self.states.append(
                    "S1"
                )

            elif (
                f & 0x11
            ) == 0x11:

                self.states.append(
                    "FIN"
                )

            elif f & 0x04:

                self.states.append(
                    "RST"
                )

            elif f & 0x10:

                self.ack_time = t

                self.states.append(
                    "EST"
                )

            elif f & 0x01:

                self.states.append(
                    "FIN"
                )

    # ========================================================
    # TERMINAL
    # ========================================================

    def is_terminal(self):

        return (
            self.rst_cnt > 0
            or (
                self.fin_fwd
                and
                self.fin_bwd
            )
        )

    # ========================================================
    # JITTER
    # ========================================================

    def _jitter(
        self,
        times
    ):

        return (
            float(
                np.std(
                    np.diff(times)
                )
            )
            if len(times) > 1
            else 0
        )

    # ========================================================
    # IAT
    # ========================================================

    def _iat(
        self,
        times
    ):

        return (
            float(
                np.mean(
                    np.diff(times)
                )
            )
            if len(times) > 1
            else 0
        )

    # ========================================================
    # IAT MIN
    # ========================================================

    def _iat_min(
        self,
        times
    ):

        return (
            float(
                np.min(
                    np.diff(times)
                )
            )
            if len(times) > 1
            else 0
        )

    # ========================================================
    # IAT MAX
    # ========================================================

    def _iat_max(
        self,
        times
    ):

        return (
            float(
                np.max(
                    np.diff(times)
                )
            )
            if len(times) > 1
            else 0
        )

    # ========================================================
    # ACTIVE / IDLE
    # ========================================================

    def _active_idle(
        self,
        gap_threshold=None
    ):

        gap_threshold = (
            gap_threshold
            or CONFIG["active_gap"]
        )

        times = sorted(
            self.fwd_times
            +
            self.bwd_times
        )

        if len(times) < 2:

            return 0.0, 0.0

        actives = []
        idles = []

        burst_start = times[0]
        prev = times[0]

        for t in times[1:]:

            gap = t - prev

            if gap > gap_threshold:

                actives.append(
                    prev - burst_start
                )

                idles.append(
                    gap
                )

                burst_start = t

            prev = t

        actives.append(
            prev - burst_start
        )

        active_mean = (
            float(
                np.mean(
                    actives
                )
            )
            if actives
            else 0.0
        )

        idle_mean = (
            float(
                np.mean(
                    idles
                )
            )
            if idles
            else 0.0
        )

        return (
            active_mean,
            idle_mean
        )

    # ========================================================
    # COMPUTE FLOW
    # ========================================================

    def compute(
        self,
        stats
    ):

        src, dst, sport, dport, proto = (
            self.fid
        )

        duration = max(
            self.end - self.start,
            1e-6
        )

        # ----------------------------------------------------
        # Bytes
        # ----------------------------------------------------

        sum_fwd = sum(
            self.fwd_sizes
        )

        sum_bwd = sum(
            self.bwd_sizes
        )

        # ----------------------------------------------------
        # Packets
        # ----------------------------------------------------

        total_packets = (
            len(self.fwd_sizes)
            +
            len(self.bwd_sizes)
        )

        total_bytes = (
            sum_fwd
            +
            sum_bwd
        )

        # ----------------------------------------------------
        # State
        # ----------------------------------------------------

        if proto in [
            "UDP",
            "ICMP"
        ]:

            state = (
                "CON"
                if len(
                    self.bwd_sizes
                ) > 0
                else "INT"
            )

        else:

            state = (
                max(
                    set(
                        self.states
                    ),
                    key=self.states.count
                )
                if self.states
                else "NONE"
            )

        # ----------------------------------------------------
        # Service
        # ----------------------------------------------------

        service = (
            max(
                set(
                    self.services
                ),
                key=self.services.count
            )
            if self.services
            else "unknown"
        )

        # ----------------------------------------------------
        # TCP RTT
        # ----------------------------------------------------

        synack = (
            self.synack_time
            -
            self.syn_time
            if self.syn_time
            and self.synack_time
            else 0
        )

        tcprtt = (
            self.ack_time
            -
            self.syn_time
            if self.syn_time
            and self.ack_time
            else synack
        )

        # ----------------------------------------------------
        # SNI
        # ----------------------------------------------------

        sni_final = (
            self.sni_list[0]
            if self.sni_list
            else ""
        )

        # ----------------------------------------------------
        # Bytes per packet
        # ----------------------------------------------------

        bytes_per_packet = (
            total_bytes
            /
            total_packets
            if total_packets > 0
            else 0
        )

        # ----------------------------------------------------
        # Size difference
        # ----------------------------------------------------

        size_diff = abs(
            sum_fwd
            -
            sum_bwd
        )

        # ----------------------------------------------------
        # All packet sizes
        # ----------------------------------------------------

        all_sizes = (
            self.fwd_sizes
            +
            self.bwd_sizes
        )

        pkt_size_var = (
            float(
                np.var(
                    all_sizes
                )
            )
            if len(all_sizes) > 1
            else 0.0
        )

        pkt_size_mean = (
            float(
                np.mean(
                    all_sizes
                )
            )
            if all_sizes
            else 0.0
        )

        # ----------------------------------------------------
        # First payload packet
        # ----------------------------------------------------

        payload_sizes = [
            s
            for s in self.fwd_sizes
            if s > 60
        ]

        first_payload_size = (
            payload_sizes[0]
            if payload_sizes
            else 0
        )

        # ----------------------------------------------------
        # Byte ratio
        # ----------------------------------------------------

        byte_ratio = (
            sum_fwd
            /
            sum_bwd
            if sum_bwd > 0
            else float(sum_fwd)
        )

        # ====================================================
        # FWD packet statistics
        # ====================================================

        fwd_min = (
            min(
                self.fwd_sizes
            )
            if self.fwd_sizes
            else 0
        )

        fwd_max = (
            max(
                self.fwd_sizes
            )
            if self.fwd_sizes
            else 0
        )

        fwd_mean = (
            float(
                np.mean(
                    self.fwd_sizes
                )
            )
            if self.fwd_sizes
            else 0.0
        )

        fwd_std = (
            float(
                np.std(
                    self.fwd_sizes
                )
            )
            if len(
                self.fwd_sizes
            ) > 1
            else 0.0
        )

        # ====================================================
        # BWD packet statistics
        # ====================================================

        bwd_min = (
            min(
                self.bwd_sizes
            )
            if self.bwd_sizes
            else 0
        )

        bwd_max = (
            max(
                self.bwd_sizes
            )
            if self.bwd_sizes
            else 0
        )

        bwd_mean = (
            float(
                np.mean(
                    self.bwd_sizes
                )
            )
            if self.bwd_sizes
            else 0.0
        )

        bwd_std = (
            float(
                np.std(
                    self.bwd_sizes
                )
            )
            if len(
                self.bwd_sizes
            ) > 1
            else 0.0
        )

        # ====================================================
        # ACTIVE / IDLE
        # ====================================================

        active_mean, idle_mean = (
            self._active_idle()
        )

        # ====================================================
        # TTL
        # ====================================================

        ttl_src_var = (
            float(
                np.var(
                    self.fwd_ttl
                )
            )
            if len(
                self.fwd_ttl
            ) > 1
            else 0.0
        )

        ttl_dst_var = (
            float(
                np.var(
                    self.bwd_ttl
                )
            )
            if len(
                self.bwd_ttl
            ) > 1
            else 0.0
        )

        # ====================================================
        # ENTROPY
        # ====================================================

        payload_entropy_mean = (
            float(
                np.mean(
                    self.entropy_list
                )
            )
            if self.entropy_list
            else 0.0
        )

        # ====================================================
        # TLS
        # ====================================================

        ja3_final = (
            self.ja3_list[0]
            if self.ja3_list
            else None
        )

        tls_version_final = (
            self.tls_version_list[0]
            if self.tls_version_list
            else None
        )

        # ====================================================
        # DNS
        # ====================================================

        dns_qname_final = (
            self.dns_qname_list[0]
            if self.dns_qname_list
            else None
        )

        dns_qtype_final = (
            self.dns_qtype_list[0]
            if self.dns_qtype_list
            else None
        )

        dns_rcode_final = (
            self.dns_rcode_list[0]
            if self.dns_rcode_list
            else None
        )

        dns_ancount_final = (
            self.dns_ancount_list[0]
            if self.dns_ancount_list
            else None
        )

        dns_qname_len = (
            len(
                dns_qname_final
            )
            if dns_qname_final
            else None
        )

        dns_qname_entropy = (
            _entropia(
                dns_qname_final.encode()
            )
            if dns_qname_final
            else None
        )

        # ====================================================
        # HTTP
        # ====================================================

        http_method_final = (
            self.http_method_list[0]
            if self.http_method_list
            else None
        )

        http_host_final = (
            self.http_host_list[0]
            if self.http_host_list
            else None
        )

        http_uri_final = (
            self.http_uri_list[0]
            if self.http_uri_list
            else None
        )

        http_ua_final = (
            self.http_ua_list[0]
            if self.http_ua_list
            else None
        )

        http_status_final = (
            self.http_status_list[0]
            if self.http_status_list
            else None
        )

        http_len_final = (
            self.http_len_list[0]
            if self.http_len_list
            else None
        )

        # ====================================================
        # ICMP
        # ====================================================

        icmp_type_final = (
            self.icmp_type_list[0]
            if self.icmp_type_list
            else None
        )

        icmp_code_final = (
            self.icmp_code_list[0]
            if self.icmp_code_list
            else None
        )

        # ====================================================
        # SLIDING WINDOW STATISTICS
        # ====================================================

        now = self.end

        while (
            stats["events"]
            and
            now
            -
            stats["events"][0][0]
            >
            CONFIG["time_window"]
        ):

            (
                _,
                s,
                d,
                srv
            ) = (
                stats["events"].popleft()
            )

            stats["src"][s] -= 1

            stats["dst"][d] -= 1

            stats["srv_src"][
                (s, srv)
            ] -= 1

            stats["srv_dst"][
                (d, srv)
            ] -= 1

        # ====================================================
        # TIME
        # ====================================================

        start_clock = (
            datetime.fromtimestamp(
                self.start
            ).strftime(
                "%H:%M:%S.%f"
            )
        )

        end_clock = (
            datetime.fromtimestamp(
                self.end
            ).strftime(
                "%H:%M:%S.%f"
            )
        )

        # ====================================================
        # RESULT
        #
        # SIN LABEL
        # ====================================================

        return {

            "Start Time":
                start_clock,

            "End Time":
                end_clock,

            "Source IP":
                src,

            "Destination IP":
                dst,

            "Source Port":
                sport,

            "Destination Port":
                dport,

            "Protocol":
                proto,

            "State":
                state,

            "Service":
                service,

            "SNI":
                sni_final,

            "Flow Duration":
                duration,

            "Src Bytes":
                sum_fwd,

            "Dst Bytes":
                sum_bwd,

            "Src Packets":
                len(
                    self.fwd_sizes
                ),

            "Dst Packets":
                len(
                    self.bwd_sizes
                ),

            "Flow Bytes/s":
                total_bytes
                /
                duration,

            "Flow Packets/s":
                total_packets
                /
                duration,

            "Src Load":
                sum_fwd
                /
                duration,

            "Dst Load":
                sum_bwd
                /
                duration,

            "Src TTL":
                int(
                    np.mean(
                        self.fwd_ttl
                    )
                )
                if self.fwd_ttl
                else 0,

            "Dst TTL":
                int(
                    np.mean(
                        self.bwd_ttl
                    )
                )
                if self.bwd_ttl
                else 0,

            "Sjit":
                self._jitter(
                    self.fwd_times
                ),

            "Djit":
                self._jitter(
                    self.bwd_times
                ),

            "Sintpkt":
                self._iat(
                    self.fwd_times
                ),

            "Dintpkt":
                self._iat(
                    self.bwd_times
                ),

            "tcprtt":
                tcprtt,

            "synack":
                synack,

            "ct_srv_src":
                stats["srv_src"][
                    (
                        src,
                        service
                    )
                ],

            "ct_srv_dst":
                stats["srv_dst"][
                    (
                        dst,
                        service
                    )
                ],

            "ct_dst_ltm":
                stats["dst"][
                    dst
                ],

            "ct_src_ltm":
                stats["src"][
                    src
                ],

            "Bytes Per Pkt":
                bytes_per_packet,

            "Size Diff":
                size_diff,

            "SYN Count":
                self.syn_cnt,

            "ACK Count":
                self.ack_cnt,

            "FIN Count":
                self.fin_cnt,

            "RST Count":
                self.rst_cnt,

            "PSH Count":
                self.psh_cnt,

            "Pkt Size Mean":
                pkt_size_mean,

            "Pkt Size Var":
                pkt_size_var,

            "First Pkt Size":
                first_payload_size,

            "Byte Ratio":
                byte_ratio,

            "URG Count":
                self.urg_cnt,

            "ECE Count":
                self.ece_cnt,

            "CWR Count":
                self.cwr_cnt,

            "Fwd PSH Count":
                self.fwd_psh_cnt,

            "Bwd PSH Count":
                self.bwd_psh_cnt,

            "Fwd URG Count":
                self.fwd_urg_cnt,

            "Bwd URG Count":
                self.bwd_urg_cnt,

            "Flag Signature":
                self.flag_signature,

            "Fwd Pkt Len Min":
                fwd_min,

            "Fwd Pkt Len Max":
                fwd_max,

            "Fwd Pkt Len Mean":
                fwd_mean,

            "Fwd Pkt Len Std":
                fwd_std,

            "Bwd Pkt Len Min":
                bwd_min,

            "Bwd Pkt Len Max":
                bwd_max,

            "Bwd Pkt Len Mean":
                bwd_mean,

            "Bwd Pkt Len Std":
                bwd_std,

            "Fwd IAT Min":
                self._iat_min(
                    self.fwd_times
                ),

            "Fwd IAT Max":
                self._iat_max(
                    self.fwd_times
                ),

            "Bwd IAT Min":
                self._iat_min(
                    self.bwd_times
                ),

            "Bwd IAT Max":
                self._iat_max(
                    self.bwd_times
                ),

            "Init Fwd Win":
                self.fwd_win_init,

            "Init Bwd Win":
                self.bwd_win_init,

            "Zero Window Count":
                self.zero_win_cnt,

            "Fwd Retrans":
                self.fwd_retrans,

            "Bwd Retrans":
                self.bwd_retrans,

            "Frag Count":
                self.frag_cnt,

            "DF Count":
                self.df_cnt,

            "Src TTL Var":
                ttl_src_var,

            "Dst TTL Var":
                ttl_dst_var,

            "Payload Entropy Mean":
                payload_entropy_mean,

            "Active Mean":
                active_mean,

            "Idle Mean":
                idle_mean,

            "ICMP Type":
                icmp_type_final,

            "ICMP Code":
                icmp_code_final,

            "DNS Qname":
                dns_qname_final,

            "DNS Qtype":
                dns_qtype_final,

            "DNS Rcode":
                dns_rcode_final,

            "DNS Ancount":
                dns_ancount_final,

            "DNS Qname Len":
                dns_qname_len,

            "DNS Qname Entropy":
                dns_qname_entropy,

            "HTTP Method":
                http_method_final,

            "HTTP Host":
                http_host_final,

            "HTTP URI":
                http_uri_final,

            "HTTP User-Agent":
                http_ua_final,

            "HTTP Status":
                http_status_final,

            "HTTP Content-Length":
                http_len_final,

            "TLS Version":
                tls_version_final,

            "JA3":
                ja3_final
        }


# ============================================================
# ANALYZER
# ============================================================

class Analyzer:

    def __init__(
        self,
        output_path,
        csv_file
    ):

        self.flows = {}

        self.stats = {

            "events":
                deque(),

            "src":
                defaultdict(int),

            "dst":
                defaultdict(int),

            "srv_src":
                defaultdict(int),

            "srv_dst":
                defaultdict(int)
        }

        os.makedirs(
            output_path,
            exist_ok=True
        )

        self.output_path = (
            output_path
        )

        self.csv_path = os.path.join(
            output_path,
            csv_file
        )

        if os.path.exists(
            self.csv_path
        ):

            os.remove(
                self.csv_path
            )

        self.init = False

    # ========================================================
    # FLOW ID
    # ========================================================

    def get_id(
        self,
        pkt
    ):

        # ----------------------------------------------------
        # IP
        # ----------------------------------------------------

        if pkt.haslayer(IP):

            src = pkt[IP].src
            dst = pkt[IP].dst

        # ----------------------------------------------------
        # 802.11
        # ----------------------------------------------------

        elif (
            Dot11
            and
            pkt.haslayer(Dot11)
        ):

            src = (
                pkt.addr2
                or
                "None"
            )

            dst = (
                pkt.addr1
                or
                "None"
            )

        # ----------------------------------------------------
        # Ethernet
        # ----------------------------------------------------

        elif pkt.haslayer(Ether):

            src = (
                pkt[Ether].src
            )

            dst = (
                pkt[Ether].dst
            )

        else:

            return None

        # ====================================================
        # PORTS
        # ====================================================

        if pkt.haslayer(TCP):

            sport = (
                pkt[TCP].sport
            )

            dport = (
                pkt[TCP].dport
            )

        elif pkt.haslayer(UDP):

            sport = (
                pkt[UDP].sport
            )

            dport = (
                pkt[UDP].dport
            )

        elif pkt.haslayer(ICMP):

            icmp_id = getattr(
                pkt[ICMP],
                "id",
                None
            )

            sport = (
                icmp_id
                if icmp_id is not None
                else 0
            )

            dport = sport

        else:

            sport = 0
            dport = 0

        proto = (
            detectar_protocolo(
                pkt
            )
        )

        return (
            src,
            dst,
            sport,
            dport,
            proto
        )

    # ========================================================
    # FLUSH
    # ========================================================

    def _flush(
        self,
        fid,
        rev,
        flow
    ):

        if (
            fid not in self.flows
            and
            rev not in self.flows
        ):

            return

        data = (
            flow.compute(
                self.stats
            )
        )

        t = flow.end

        # ----------------------------------------------------
        # Sliding statistics
        # ----------------------------------------------------

        if (
            data["Source IP"]
            !=
            "None"
            and
            data["Destination IP"]
            !=
            "None"
        ):

            self.stats[
                "events"
            ].append(
                (
                    t,
                    data[
                        "Source IP"
                    ],
                    data[
                        "Destination IP"
                    ],
                    data[
                        "Service"
                    ]
                )
            )

            self.stats[
                "src"
            ][
                data[
                    "Source IP"
                ]
            ] += 1

            self.stats[
                "dst"
            ][
                data[
                    "Destination IP"
                ]
            ] += 1

            self.stats[
                "srv_src"
            ][
                (
                    data[
                        "Source IP"
                    ],
                    data[
                        "Service"
                    ]
                )
            ] += 1

            self.stats[
                "srv_dst"
            ][
                (
                    data[
                        "Destination IP"
                    ],
                    data[
                        "Service"
                    ]
                )
            ] += 1

        # ----------------------------------------------------
        # Save
        # ----------------------------------------------------

        self.save(
            data
        )

        # ----------------------------------------------------
        # Delete flow
        # ----------------------------------------------------

        self.flows.pop(
            fid,
            None
        )

        self.flows.pop(
            rev,
            None
        )

    # ========================================================
    # PROCESS
    # ========================================================

    def process(
        self,
        pkt
    ):

        try:

            fid = (
                self.get_id(
                    pkt
                )
            )

            if not fid:

                return

            rev = (
                fid[1],
                fid[0],
                fid[3],
                fid[2],
                fid[4]
            )

            flow = (
                self.flows.get(
                    fid
                )
                or
                self.flows.get(
                    rev
                )
            )

            # ------------------------------------------------
            # New flow
            # ------------------------------------------------

            if flow is None:

                flow = Flow(
                    fid
                )

                self.flows[
                    fid
                ] = flow

                direction = "FWD"

            else:

                direction = (
                    "FWD"
                    if fid in self.flows
                    else "BWD"
                )

            # ------------------------------------------------
            # Add packet
            # ------------------------------------------------

            flow.add(
                pkt,
                direction
            )

            # ------------------------------------------------
            # Min packets
            # ------------------------------------------------

            enough_packets = (
                len(
                    flow.fwd_sizes
                )
                +
                len(
                    flow.bwd_sizes
                )
                >=
                CONFIG[
                    "min_packets"
                ]
            )

            # ------------------------------------------------
            # Terminal
            # ------------------------------------------------

            terminal = (
                flow.is_terminal()
            )

            # ------------------------------------------------
            # Save
            # ------------------------------------------------

            if (
                terminal
                or
                enough_packets
            ):

                self._flush(
                    fid,
                    rev,
                    flow
                )

        except Exception as e:

            print(
                f"[!] Error procesando paquete: {e}"
            )

    # ========================================================
    # FLUSH ACTIVE FLOWS
    # ========================================================

    def flush_all_active(
        self
    ):

        pendientes = len(
            self.flows
        )

        for fid, flow in list(
            self.flows.items()
        ):

            rev = (
                fid[1],
                fid[0],
                fid[3],
                fid[2],
                fid[4]
            )

            self._flush(
                fid,
                rev,
                flow
            )

        return pendientes

    # ========================================================
    # SAVE CSV
    # ========================================================

    def save(
        self,
        data
    ):

        with open(
            self.csv_path,
            "a",
            newline="",
            encoding="utf-8"
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=data.keys()
            )

            if not self.init:

                writer.writeheader()

                self.init = True

            writer.writerow(
                data
            )


# ============================================================
# RUN
# ============================================================

def run():

    root = tk.Tk()

    root.withdraw()

    root.attributes(
        "-topmost",
        True
    )

    # ========================================================
    # SELECT PCAP
    # ========================================================

    file = (
        filedialog.askopenfilename(
            title="Selecciona PCAP",
            filetypes=[
                (
                    "PCAP",
                    "*.pcap *.pcapng"
                )
            ]
        )
    )

    if not file:

        print(
            "❌ No se seleccionó ningún PCAP."
        )

        return

    # ========================================================
    # SELECT OUTPUT
    # ========================================================

    ruta = (
        filedialog.askdirectory(
            title=(
                "Selecciona carpeta "
                "para guardar el CSV"
            )
        )
    )

    if not ruta:

        print(
            "❌ No se seleccionó "
            "carpeta de salida."
        )

        return

    # ========================================================
    # CSV NAME
    # ========================================================

    csv_name = input(
        "\n[?] Nombre CSV "
        "(ENTER = pcap_resultado.csv): "
    ).strip()

    if not csv_name:

        csv_name = (
            CONFIG[
                "csv_file"
            ]
        )

    if not csv_name.lower().endswith(
        ".csv"
    ):

        csv_name += ".csv"

    # ========================================================
    # ANALYZER
    # ========================================================

    analyzer = Analyzer(
        output_path=ruta,
        csv_file=csv_name
    )

    # ========================================================
    # INFO
    # ========================================================

    print()

    print(
        "=" * 60
    )

    print(
        "              ANALIZANDO PCAP"
    )

    print(
        "=" * 60
    )

    print(
        f"📂 PCAP: {file}"
    )

    print(
        f"📁 CSV:  {analyzer.csv_path}"
    )

    print()

    # ========================================================
    # READ PCAP
    # ========================================================

    from scapy.utils import PcapReader

    packet_count = 0

    try:

        with PcapReader(
            file
        ) as pcap:

            for pkt in pcap:

                packet_count += 1

                analyzer.process(
                    pkt
                )

                if (
                    packet_count
                    % 10000
                    == 0
                ):

                    print(
                        "[*] Paquetes "
                        f"procesados: "
                        f"{packet_count}"
                    )

    except KeyboardInterrupt:

        print(
            "\n[!] Análisis interrumpido."
        )

    except Exception as e:

        print(
            "\n[!] Error leyendo PCAP: "
            f"{e}"
        )

    finally:

        # ----------------------------------------------------
        # Save remaining flows
        # ----------------------------------------------------

        pendientes = (
            analyzer.flush_all_active()
        )

    # ========================================================
    # FINAL
    # ========================================================

    print()

    print(
        "=" * 60
    )

    print(
        "                 FINALIZADO"
    )

    print(
        "=" * 60
    )

    print(
        f"📦 Paquetes procesados: "
        f"{packet_count}"
    )

    print(
        f"💾 CSV generado: "
        f"{analyzer.csv_path}"
    )

    print(
        f"🔚 Flows pendientes guardados: "
        f"{pendientes}"
    )

    print()

    print(
        "✅ El CSV fue generado "
        "SIN columna Label."
    )

    print()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    run()
