"""Process the 12 PCAP files with the Flow Engine extractor and time it.

Usage:
  python 01_extract_flowengine.py --data DATA --work WORK --src ../src
Writes WORK/fe/<capture>_fe.csv and WORK/fe/times.tsv (capture, seconds, packets).
"""
import os
import sys
import time
import types

from common import PAIRS, args, stem

a = args([('--src', dict(required=True, help='Flow Engine src folder (contains pcap_conf.py)'))])
sys.path.insert(0, os.path.abspath(a.src))
# pcap_conf imports tkinter for its file dialog; it is not needed here
sys.modules.setdefault('tkinter', types.ModuleType('tkinter'))
sys.modules['tkinter'].filedialog = types.ModuleType('filedialog')
sys.modules['tkinter.filedialog'] = sys.modules['tkinter'].filedialog
import pcap_conf  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

out = os.path.join(a.work, 'fe')
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, 'times.tsv'), 'w') as log:
    for cap in PAIRS:
        t0 = time.time()
        n = 0
        an = pcap_conf.Analyzer(output_path=out, csv_file=f'{stem(cap)}_fe.csv')
        with PcapReader(os.path.join(a.data, cap + '.pcap')) as r:
            for pkt in r:
                n += 1
                an.process(pkt)
        an.flush_all_active()
        dt = time.time() - t0
        log.write(f'{cap}\t{dt:.1f}\t{n}\n')
        log.flush()
        print(f'{cap}: {dt:.1f} s, {n} packets')
