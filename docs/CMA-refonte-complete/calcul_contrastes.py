import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / 'outputs'
OUT.mkdir(exist_ok=True)
palettes = {
 'clair': dict(window='#F3F6F8', surface='#FFFFFF', sidebar='#E9EFF3', text='#172B3A', muted='#4B5D6B', border='#C6D1DB', control='#708392', hover='#E6EEF5', pressed='#D8E5F0', selected='#E3EEFC', accent='#165DB5', primary_hover='#124F9B', primary_pressed='#104386', on_accent='#FFFFFF', focus='#165DB5', success='#17633D', success_bg='#E7F4EC', warning='#784700', warning_bg='#FFF1D6', danger='#AE2633', danger_bg='#FDECEE', info='#165DB5', info_bg='#E3EEFC', neutral='#4B5D6B', neutral_bg='#E9EFF3', disabled='#526472', disabled_bg='#E9EFF3'),
 'sombre': dict(window='#111A22', surface='#1B2935', sidebar='#15212B', text='#F1F5F9', muted='#B6C4D2', border='#3A4D5E', control='#71879A', hover='#263B4C', pressed='#30495E', selected='#223F5B', accent='#80B8FF', primary_hover='#A2CCFF', primary_pressed='#6BA6F0', on_accent='#111A22', focus='#80B8FF', success='#87D7AC', success_bg='#173C2C', warning='#FFD28A', warning_bg='#493419', danger='#FFABB2', danger_bg='#4A242B', info='#80B8FF', info_bg='#223F5B', neutral='#B6C4D2', neutral_bg='#15212B', disabled='#9BACBB', disabled_bg='#263541')}

def luminance(h):
    c = [int(h[i:i+2],16)/255 for i in (1,3,5)]
    c = [v/12.92 if v <= .04045 else ((v+.055)/1.055)**2.4 for v in c]
    return sum(v*w for v,w in zip(c,(.2126,.7152,.0722)))

def ratio(a,b):
    x,y=sorted((luminance(a),luminance(b)))
    return (y+.05)/(x+.05)

pairs = [(fg,bg) for fg in ('text','muted') for bg in ('window','surface','sidebar','hover','pressed','selected')]
pairs += [('on_accent',bg) for bg in ('accent','primary_hover','primary_pressed')]
pairs += [(fg,fg+'_bg') for fg in ('success','warning','danger','info','neutral')]
pairs += [('disabled','disabled_bg')]
pairs += [(fg,bg) for fg in ('accent','danger') for bg in ('surface','window','hover','pressed')]
pairs += [('text',bg+'_bg') for bg in ('success','warning','danger','info')]
palettes['sombre']['control'] = '#8499AB'
rows = ['| Couple texte / fond autorisé | Clair | Sombre |','| --- | ---: | ---: |']
data=[]
for fg,bg in pairs:
    vals=[ratio(p[fg],p[bg]) for p in palettes.values()]
    assert min(vals)>=4.5,(fg,bg,vals)
    rows.append(f'| `{fg}` / `{bg}` | {vals[0]:.2f}:1 | {vals[1]:.2f}:1 |')
    data.append(dict(foreground=fg,background=bg,clair=vals[0],sombre=vals[1]))
(OUT/'contrastes.md').write_text('\n'.join(rows)+'\n',encoding='utf-8')
(OUT/'design-tokens.json').write_text(json.dumps(dict(palettes=palettes,contrast_pairs=data),ensure_ascii=False,indent=2),encoding='utf-8')
print('Text pairs:',len(pairs),'minimum:',min(min(d['clair'],d['sombre']) for d in data))
for fg in ('control','focus'):
    for bg in ('window','surface','sidebar','hover','pressed','selected'):
        vals=[ratio(p[fg],p[bg]) for p in palettes.values()]
        print(fg,bg,*[round(v,2) for v in vals])
