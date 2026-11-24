#!/usr/bin/env python3
"""Build the offline application, preserving legacy source labels for regression tests."""
from pathlib import Path
import re,json
ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'src'
labels={v:k for k,v in json.loads((ROOT/'scripts/source-map.json').read_text(encoding='utf-8')).items()}
html=(SRC/'index.html').read_text(encoding='utf-8')
def stylesheet(match):
    name=match.group(1)
    return '<style data-original="'+labels[name]+'">\n'+(SRC/name).read_text(encoding='utf-8')+'\n</style>'
def script(match):
    name=match.group(1)
    js=(SRC/name).read_text(encoding='utf-8').replace('</script','<\\/script')
    return '<script data-original="'+labels[name]+'">\n'+js+'\n</script>'
html=re.sub(r'<link rel="stylesheet" href="([^"]+\.css)">',stylesheet,html)
html=re.sub(r'<script src="([^"]+\.js)"></script>',script,html)
assert '<script src=' not in html and '<link rel="stylesheet" href=' not in html
output=ROOT/'dist/NullCap-Studio-4.0.1.html'
output.parent.mkdir(parents=True,exist_ok=True)
output.write_bytes(html.encode('utf-8'))
print(f'Created {output.name}: {len(html):,} characters')
