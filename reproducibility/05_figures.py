"""Draw the data figures of the papers (English and Spanish) from WORK/results.json.

Usage:
  python 05_figures.py --data DATA --work WORK
Writes WORK/figures/en/*.png and WORK/figures/es/*.png.
"""
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from common import args  # noqa: E402

cfg = args()
R = json.load(open(os.path.join(cfg.work, 'results.json')))
FE = '#2a3f6f'; CIC = '#c9a85e'; RD = '#b03a2e'; GR = '#9aa3b5'
plt.rcParams.update({'font.size': 10, 'axes.spines.top': False, 'axes.spines.right': False})
T={'en':dict(lab='Flows labeled as the class',att='Of which involve the attacker (192.168.1.30)',xl='Flows (log scale)',
  pc='Capture',tsec='Processing time (s)',rec='Flow records (log scale)',fe='Flow Engine',cic='CICFlowMeter',
  f1='F1 score',cv='5-fold cross-validation',ho='Captures not seen in training',
  first='Flow Engine: first record of the connection',whole='Session-level record (end of connection)',lat='Time after the first packet (s, log scale)',cdf='Share of connections',
  real='True class',pred='Predicted class',imp='Relative importance',
  exp=['Original labels,\nall features\n(80/20 split)','Original labels,\nno ports or ct_*\n(80/20 split)','Corrected labels,\nno ports or ct_*\n(cross-validation)','Corrected labels,\nno ports or ct_*\n(unseen captures)'],ba='Balanced accuracy',
  cls={'beaconing':'beaconing','bruteforce':'bruteforce','dos':'DoS','fuzzer':'fuzzer','injection':'injection','portscan':'PortScan'}),
 'es':dict(lab='Flujos etiquetados con la clase',att='De ellos, los que involucran al atacante (192.168.1.30)',xl='Flujos (escala logarítmica)',
  pc='Captura',tsec='Tiempo de procesamiento (s)',rec='Registros de flujo (escala logarítmica)',fe='Flow Engine',cic='CICFlowMeter',
  f1='F1',cv='Validación cruzada de 5 particiones',ho='Capturas no vistas en el entrenamiento',
  first='Flow Engine: primer registro de la conexión',whole='Registro por sesión (fin de la conexión)',lat='Tiempo desde el primer paquete (s, escala log.)',cdf='Proporción de conexiones',
  real='Clase real',pred='Clase predicha',imp='Importancia relativa',
  exp=['Etiquetas originales,\ntodas las columnas\n(partición 80/20)','Etiquetas originales,\nsin puertos ni ct_*\n(partición 80/20)','Etiquetas corregidas,\nsin puertos ni ct_*\n(validación cruzada)','Etiquetas corregidas,\nsin puertos ni ct_*\n(capturas no vistas)'],ba='Exactitud balanceada',
  cls={'beaconing':'beaconing','bruteforce':'bruteforce','dos':'DoS','fuzzer':'fuzzer','injection':'injection','portscan':'PortScan'})}
AU=pd.read_csv(os.path.join(cfg.work,'label_audit.csv'),index_col=0)
audit={k.lower():(int(AU.loc[k,'records']),int(AU.loc[k,'touch_attacker'])) for k in AU.index if k!='Total'}
order=['fuzzer','injection','beaconing','bruteforce','portscan','dos']
pcaps=['tcpsyn','webfz','fuzzer','bruteforce (2)','webattack','bruteforce','http','beacon-normal','captura','dos','portscan','prueba de fuego']
for L,t in T.items():
    O=os.path.join(cfg.work,'figures',L)+'/'; os.makedirs(O,exist_ok=True)
    # 1 audit
    fig,ax=plt.subplots(figsize=(7.4,3.6),dpi=220); y=np.arange(len(order)); h=0.38
    a=[audit[c][0] for c in order]; b=[max(audit[c][1],0.8) for c in order]
    ax.barh(y-h/2,a,h,color=GR,label=t['lab']); ax.barh(y+h/2,b,h,color=RD,label=t['att'])
    for yi,(x1,x2) in enumerate([audit[c] for c in order]):
        ax.text(x1*1.08,yi-h/2,f'{x1:,}',va='center',fontsize=8); ax.text(max(x2,0.8)*1.08,yi+h/2,f'{x2:,} ({100*x2/x1:.1f}%)',va='center',fontsize=8,color=RD)
    ax.set_xscale('log'); ax.set_xlim(0.7,4e5); ax.set_yticks(y); ax.set_yticklabels([t['cls'][c] for c in order]); ax.set_xlabel(t['xl'])
    ax.legend(frameon=False,fontsize=8,loc='lower center',bbox_to_anchor=(0.5,1.0),ncol=2); fig.tight_layout(); fig.savefig(O+'audit.png'); plt.close(fig)
    # 2 ablation
    fig,ax=plt.subplots(figsize=(7.4,3.4),dpi=220)
    v=[R['ablation_orig_all_features']['bacc'],R['ablation_orig_no_identifiers']['bacc'],R['fe_cv']['bacc'][0],R['fe_holdout']['bacc']]; cols=[GR,RD,FE,FE]
    bars=ax.bar(range(4),v,color=cols,width=0.6)
    for i,x in enumerate(v): ax.text(i,x+0.02,f'{x:.3f}',ha='center',fontsize=9)
    ax.set_xticks(range(4)); ax.set_xticklabels(t['exp'],fontsize=8); ax.set_ylim(0,1.12); ax.set_ylabel(t['ba']); fig.tight_layout(); fig.savefig(O+'ablation.png'); plt.close(fig)
    # 3 processing time + records
    fig,axs=plt.subplots(1,2,figsize=(9.6,3.9),dpi=220); x=np.arange(len(pcaps)); w=0.4
    tf=[R['time_flowengine'][p] for p in pcaps]; tc=[R['time_cicflowmeter'][p] for p in pcaps]
    axs[0].bar(x-w/2,tf,w,color=FE,label=t['fe']); axs[0].bar(x+w/2,tc,w,color=CIC,label=t['cic'])
    axs[0].set_xticks(x); axs[0].set_xticklabels(pcaps,rotation=60,ha='right',fontsize=7.5); axs[0].set_ylabel(t['tsec']); axs[0].legend(frameon=False,fontsize=8)
    axs[0].set_title(f"{t['fe']}: {sum(tf):.0f} s   {t['cic']}: {sum(tc):.0f} s",fontsize=9)
    rf=[R['records_flowengine'][p] for p in pcaps]; rc=[R['records_cicflowmeter'][p] for p in pcaps]
    axs[1].bar(x-w/2,rf,w,color=FE,label=t['fe']); axs[1].bar(x+w/2,rc,w,color=CIC,label=t['cic']); axs[1].set_yscale('log')
    axs[1].set_xticks(x); axs[1].set_xticklabels(pcaps,rotation=60,ha='right',fontsize=7.5); axs[1].set_ylabel(t['rec'])
    axs[1].set_title(f"{t['fe']}: {sum(rf):,}   {t['cic']}: {sum(rc):,}",fontsize=9)
    fig.tight_layout(); fig.savefig(O+'cic_time_records.png'); plt.close(fig)
    # 4 detection comparison
    fig,axs=plt.subplots(1,2,figsize=(9.2,3.9),dpi=220,sharey=True); cls=['Normal','DoS','PortScan']; x=np.arange(3)
    for k,(name,ax) in enumerate([(t['cv'],axs[0]),(t['ho'],axs[1])]):
        if k==0:
            f=[R['fe_cv']['per'][c]['f1'][0] for c in cls]; fe_e=[R['fe_cv']['per'][c]['f1'][1] for c in cls]
            c_=[R['cic_cv']['per'][c]['f1'][0] for c in cls]; ce=[R['cic_cv']['per'][c]['f1'][1] for c in cls]; xs=x
        else:
            cls2=['Normal','DoS']; xs=np.arange(2); f=[R['fe_holdout']['per'][c]['f1'] for c in cls2]; c_=[R['cic_holdout']['per'][c]['f1'] for c in cls2]; fe_e=ce=None
        ax.bar(xs-w/2,f,w,yerr=fe_e,color=FE,label=t['fe'],capsize=3); ax.bar(xs+w/2,c_,w,yerr=ce,color=CIC,label=t['cic'],capsize=3)
        for i,(a1,a2) in enumerate(zip(f,c_)): ax.text(i-w/2,a1+0.01,f'{a1:.3f}',ha='center',fontsize=7.5); ax.text(i+w/2,a2+0.01,f'{a2:.3f}',ha='center',fontsize=7.5)
        ax.set_xticks(xs); ax.set_xticklabels(cls if k==0 else ['Normal','DoS']); ax.set_title(name,fontsize=9); ax.set_ylim(0.8,1.03)
    axs[0].set_ylabel(t['f1']); fig.legend(*axs[0].get_legend_handles_labels(),frameon=False,fontsize=8,loc='upper center',ncol=2,bbox_to_anchor=(0.5,1.02)); fig.tight_layout(rect=(0,0,1,0.93)); fig.savefig(O+'cic_detection.png'); plt.close(fig)
    # 5 latency CDF
    a1=np.load(os.path.join(cfg.work,'latency_first.npy')); a2=np.load(os.path.join(cfg.work,'latency_whole.npy'))
    fig,ax=plt.subplots(figsize=(6.6,3.6),dpi=220)
    for arr,col,lb in [(a1,FE,t['first']),(a2,CIC,t['whole'])]:
        s=np.sort(np.clip(arr,1e-6,None)); ax.plot(s,np.arange(1,len(s)+1)/len(s),color=col,lw=2,label=lb)
    ax.set_xscale('log'); ax.set_xlabel(t['lat']); ax.set_ylabel(t['cdf']); ax.legend(frameon=False,fontsize=8,loc='lower right'); ax.grid(True,color='#eee')
    fig.tight_layout(); fig.savefig(O+'latency.png'); plt.close(fig)
    # 6 confusion matrix (CV aggregated)
    cm=np.array(R['fe_cv']['cm']); fig,ax=plt.subplots(figsize=(4.6,3.8),dpi=220)
    nrm=cm/cm.sum(axis=1,keepdims=True); ax.imshow(nrm,cmap='Blues',vmin=0,vmax=1)
    for i in range(3):
        for j in range(3): ax.text(j,i,f'{cm[i,j]:,}',ha='center',va='center',color='white' if nrm[i,j]>0.5 else 'black',fontsize=9)
    ax.set_xticks(range(3)); ax.set_yticks(range(3)); ax.set_xticklabels(cls); ax.set_yticklabels(cls); ax.set_xlabel(t['pred']); ax.set_ylabel(t['real'])
    for s in ('top','right'): ax.spines[s].set_visible(True)
    fig.tight_layout(); fig.savefig(O+'confusion.png'); plt.close(fig)
    # 7 importance
    imp=R['fe_importance']; k=list(imp)[:10][::-1]; fig,ax=plt.subplots(figsize=(6.2,3.6),dpi=220)
    ax.barh(k,[imp[i] for i in k],color=FE); ax.set_xlabel(t['imp']); fig.tight_layout(); fig.savefig(O+'importance.png'); plt.close(fig)
print('ok')
