"""Process the 12 PCAP files with the Python CICFlowMeter (pip install cicflowmeter==0.5.0) and time it.

The package's command-line entry point passes its arguments in the wrong order in
version 0.5.0, so the sniffer is created directly.

Usage:
  python 02_extract_cicflowmeter.py --data DATA --work WORK
Writes WORK/cic/<capture>_cic.csv and WORK/cic/times.tsv (capture, seconds).
"""
import os
import time

from cicflowmeter.sniffer import create_sniffer

from common import PAIRS, args, stem

a = args()
out = os.path.join(a.work, 'cic')
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, 'times.tsv'), 'w') as log:
    for cap in PAIRS:
        t0 = time.time()
        sniffer, session = create_sniffer(os.path.join(a.data, cap + '.pcap'), None, 'csv',
                                          os.path.join(out, f'{stem(cap)}_cic.csv'), None, None, False)
        sniffer.start()
        try:
            sniffer.join()
        finally:
            if hasattr(session, '_gc_stop'):
                session._gc_stop.set()
            session.flush_flows()
        dt = time.time() - t0
        log.write(f'{cap}\t{dt:.1f}\n')
        log.flush()
        print(f'{cap}: {dt:.1f} s')
