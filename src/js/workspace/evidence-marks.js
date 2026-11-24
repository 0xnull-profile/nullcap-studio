'use strict';
/* A25: case-scoped artifact and conversation marks. Only analyst notes and
   bounded source references enter the dossier, never recovered payloads. */
const NC25_MAX_MARKS=480;
const nc25OldNormalize=nc24NormalizeDossier;
function nc25CleanMark(m){
  if(!m||typeof m!=='object'||!['artifact','conversation'].includes(m.kind))return null;
  if(typeof m.captureId!=='string'||m.captureId.length>600||!m.captureId)return null;
  if(typeof m.sourceKey!=='string'||!m.sourceKey||m.sourceKey.length>350)return null;
  const frames=Array.isArray(m.frames)?[...new Set(m.frames.filter(n=>Number.isSafeInteger(n)&&n>0&&n<300000))].slice(0,64):[];
  if(!frames.length)return null;
  return {kind:m.kind,captureId:m.captureId,sourceKey:m.sourceKey,frames,
    title:nc24Text(m.title,180),protocol:nc24Text(m.protocol,48),src:nc24Text(m.src,140),dst:nc24Text(m.dst,140),
    firstSrc:nc24Text(m.firstSrc,140),firstDst:nc24Text(m.firstDst,140),
    note:nc24Text(m.note,1200),observedAt:Number.isFinite(m.observedAt)?m.observedAt:null};
}
nc24NormalizeDossier=function(value){
  const out=nc25OldNormalize(value),found=new Set();
  out.marks=Array.isArray(value?.marks)?value.marks.slice(0,NC25_MAX_MARKS).map(nc25CleanMark).filter(m=>{
    if(!m)return false;const key=nc25MarkKey(m);if(found.has(key))return false;found.add(key);return true;
  }):[];
  return out;
};
nc40.dossier=nc24NormalizeDossier(nc40.dossier);
// A real capture replaces the synthetic demo; demo-only marks must not leak
// into the real investigation. Imported case markers have their own source ids.
const nc25BaseApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  const oldDemo=!options.isDemo&&nc40.captures.length===1&&nc40.captures[0].isDemo?nc40.captures[0].id:null;
  const result=nc25BaseApplyCapture(packets,options);
  if(oldDemo&&!nc40Slot(oldDemo)){
    const removed=new Set(nc25Marks().filter(m=>m.captureId===oldDemo).map(nc25MarkKey));
    nc40.dossier.marks=nc25Marks().filter(m=>m.captureId!==oldDemo);
    nc40.dossier.order=nc40.dossier.order.filter(k=>!removed.has(k));
    nc24RenderDossier();
  }
  return result;
};
window.NullCap.applyCapture=applyCapture;
function nc25Marks(){return nc40.dossier.marks||(nc40.dossier.marks=[]);}
function nc25MarkKey(m){return 'mark:'+m.captureId+'|'+m.kind+'|'+m.sourceKey;}
function nc25Hash(s){let a=2166136261,b=2246822519;for(let i=0;i<s.length;i++){a=Math.imul(a^s.charCodeAt(i),16777619);b=Math.imul(b^s.charCodeAt(i),3266489917);}return (a>>>0).toString(36)+'-'+(b>>>0).toString(36);}
function nc25ArtifactKey(asset){
  const ids=(asset.packetIds||[]).filter(Number.isSafeInteger);
  const core=[asset.kind,ids.join(','),asset.data?.length||0,asset.contentType||''].join('|');
  const matching=(state.loot||[]).filter(a=>[a.kind,(a.packetIds||[]).filter(Number.isSafeInteger).join(','),a.data?.length||0,a.contentType||''].join('|')===core);
  return 'a-'+nc25Hash(core)+'-'+Math.max(0,matching.indexOf(asset));
}
function nc25FlowKey(f){return 'f-'+nc25Hash(f.id+'|'+f.packets.length+'|'+(f.packets[0]?.id||0)+'|'+(f.packets.at(-1)?.id||0));}
function nc25SourceMark(kind,item){
  const slot=nc40Slot(state.captureId);if(!slot)return null;
  const frames=(kind==='artifact'?(item.packetIds||[]):(item.packets||[]).map(p=>p.id)).filter(n=>Number.isSafeInteger(n)&&n>0).slice(0,64);
  if(!frames.length)return null;
  const first=slot.packets[frames[0]-1];if(!first)return null;
  const sensitive=kind==='artifact'&&!!item.authFinding;
  const entry={kind,captureId:slot.id,sourceKey:kind==='artifact'?nc25ArtifactKey(item):nc25FlowKey(item),frames,
    title:kind==='artifact'?(sensitive?'Autenticazione HTTP in chiaro':nc24Text(item.title||item.filename||'Artefatto',180)):
      ('Conversazione '+(item.transport||'rete')+' · '+(item.a||'?')+' \u2194 '+(item.b||'?')),
    protocol:kind==='artifact'?item.kind:(item.protocol||item.transport||'RETE'),
    src:nc24Text(item.src||first.src,140),dst:nc24Text(item.dst||first.dst,140),
    firstSrc:nc24Text(first.src,140),firstDst:nc24Text(first.dst,140),
    observedAt:Number.isFinite(first.ts)?first.ts:null,note:''};
  return nc25CleanMark(entry);
}
function nc25MarkSourceVerified(m){
  const slot=nc40Slot(m.captureId);if(!slot)return null;
  const p=slot.packets[m.frames[0]-1];
  return p&&p.src===m.firstSrc&&p.dst===m.firstDst?slot:null;
}
let nc25Pending=null,nc25Focus=null;
const nc25Modal=()=>document.getElementById('nc25MarkModal');
function nc25Open(kind,item){
  const mark=nc25SourceMark(kind,item);if(!mark){notify('Fonte non disponibile','La cattura deve appartenere all\'indagine prima di poter segnare la fonte.',true);return;}
  const exists=nc25Marks().find(m=>nc25MarkKey(m)===nc25MarkKey(mark));
  nc25Pending=mark;nc25Focus=document.activeElement;
  document.getElementById('nc25MarkHeading').textContent=exists?'Modifica segnalazione':kind==='artifact'?'Segna artefatto':'Segna conversazione';
  document.getElementById('nc25MarkSubject').textContent=mark.title;
  document.getElementById('nc25MarkCapture').textContent=nc40Label(nc40Slot(mark.captureId));
  document.getElementById('nc25MarkOrigin').textContent=mark.src+' \u2192 '+mark.dst;
  document.getElementById('nc25MarkFrames').textContent=mark.frames.length+' frame di riferimento · primo #'+mark.frames[0];
  document.getElementById('nc25MarkSubmit').textContent=exists?'Aggiorna nota':'Aggiungi al dossier';
  const textarea=document.getElementById('nc25MarkNote');textarea.value=exists?.note||'';textarea.setCustomValidity('');
  nc25Modal().hidden=false;textarea.focus();
}
function nc25Close(){nc25Modal().hidden=true;nc25Pending=null;if(nc25Focus?.isConnected)nc25Focus.focus();nc25Focus=null;}
function nc25Save(e){
  e.preventDefault();const value=document.getElementById('nc25MarkNote'),note=value.value.trim(),m=nc25Pending;
  if(!m)return;
  if(!note){value.setCustomValidity('Scrivi una nota investigativa prima di salvare.');value.reportValidity();return;}
  if(!nc25MarkSourceVerified(m)){notify('Fonte non disponibile','La cattura di origine non e\' piu\' verificabile in questo caso.',true);return;}
  const marks=nc25Marks(),index=marks.findIndex(x=>nc25MarkKey(x)===nc25MarkKey(m));
  if(index<0&&marks.length>=NC25_MAX_MARKS){notify('Limite evidenze','Raggiunto il limite di 480 artefatti e conversazioni segnati.',true);return;}
  m.note=nc24Text(note,1200);
  if(index>=0)marks[index]={...marks[index],note:m.note};else marks.push(m);
  nc25Close();nc24RenderDossier();if(state.caseModalOpen)nc24RenderNotebook();
  if(state.page==='loot'){const a=(state.loot||[]).find(x=>x.id===state.selectedLoot);if(a)nc25UpdateButton(document.getElementById('nc25MarkArtifact'),nc25SourceMark('artifact',a));}
  if(state.page==='flows'){const f=state.flowMap.get(state.selectedFlow);if(f)nc25UpdateButton(document.getElementById('nc25MarkFlow'),nc25SourceMark('conversation',f));}
  notify('Segnalazione salvata',(m.kind==='artifact'?'Artefatto':'Conversazione')+' aggiunta al dossier con la nota investigativa.');
}
function nc25UpdateButton(button,mark){
  if(!button||!mark)return;
  const marked=nc25Marks().some(m=>nc25MarkKey(m)===nc25MarkKey(mark));
  const label=marked?'Modifica segnalazione':mark.kind==='artifact'?'Segna artefatto':'Segna conversazione';
  button.dataset.tip=label;button.setAttribute('aria-label',label);button.setAttribute('aria-pressed',String(marked));
  button.classList.toggle('nc25-is-marked',marked);
}
const nc25BaseLootRender=ncRenderLootDetail;
ncRenderLootDetail=function(){
  nc25BaseLootRender();const a=(state.loot||[]).find(x=>x.id===state.selectedLoot);
  const row=document.querySelector('#lootDetail .loot-action-row');if(!a||!row)return;
  const btn=document.createElement('button');btn.type='button';btn.id='nc25MarkArtifact';btn.className='nc25-mark-icon';
  btn.innerHTML=nc24Icon('i-bookmark');const mark=nc25SourceMark('artifact',a);nc25UpdateButton(btn,mark);
  btn.addEventListener('click',()=>nc25Open('artifact',a));row.append(btn);
};
const nc25BaseFlowRender=renderFlowInspector;
renderFlowInspector=function(){
  nc25BaseFlowRender();const f=state.flowMap.get(state.selectedFlow);
  const row=document.querySelector('#flowInspectorContent .nc15-tools');if(!f||!row)return;
  const btn=document.createElement('button');btn.id='nc25MarkFlow';btn.type='button';btn.className='nc15-action-btn nc14-quick-action nc25-mark-icon';
  btn.innerHTML=nc24Icon('i-bookmark');const mark=nc25SourceMark('conversation',f);nc25UpdateButton(btn,mark);
  btn.addEventListener('click',()=>nc25Open('conversation',f));row.append(btn);
};
const nc25BaseAllEntries=nc24AllEntries;
nc24AllEntries=function(){
  const entries=nc25BaseAllEntries();
  for(const m of nc25Marks())entries.push({...m,key:nc25MarkKey(m),kind:m.kind,mark:m,slot:nc40Slot(m.captureId)});
  const order=new Map((nc40.dossier.order||[]).map((k,i)=>[k,i]));
  entries.sort((a,b)=>(order.get(a.key)??100000)-(order.get(b.key)??100000));
  return entries;
};
const nc25BaseEntryTitle=nc24EntryTitle;
nc24EntryTitle=function(e){return e.kind==='artifact'||e.kind==='conversation'?e.title:nc25BaseEntryTitle(e);};
const nc25BaseEntryDetail=nc24EntryDetail;
nc24EntryDetail=function(e){return e.kind==='artifact'||e.kind==='conversation'?(e.slot?.name||'Cattura da reimportare')+' · '+e.frames.length+' frame di riferimento':nc25BaseEntryDetail(e);};
const nc25BaseSaveNote=nc24SaveNote;
nc24SaveNote=function(e,text){
  if(e.kind!=='artifact'&&e.kind!=='conversation')return nc25BaseSaveNote(e,text);
  const m=nc25Marks().find(x=>nc25MarkKey(x)===e.key);if(m)m.note=nc24Text(text,1200);nc24RenderDossier();
};
const nc25BaseRemoveNote=nc24RemoveNote;
nc24RemoveNote=async function(){
  const e=nc24AllEntries().find(x=>x.key===nc24NotebookSelected);
  if(!e||!['artifact','conversation'].includes(e.kind))return nc25BaseRemoveNote();
  if(!await nc26Confirm('Rimuovere questa segnalazione dal dossier? I dati originali non verranno modificati.'))return;
  nc40.dossier.marks=nc25Marks().filter(x=>nc25MarkKey(x)!==e.key);
  nc40.dossier.order=nc40.dossier.order.filter(x=>x!==e.key);nc24NotebookSelected=null;nc24RenderNotebook();nc24RenderDossier();
};
nc24RenderNotebook=function(){
  const entries=nc24AllEntries(),query=document.getElementById('nc24NotebookFilter')?.value.trim().toLowerCase()||'';
  document.getElementById('nc24NotebookCount').textContent=entries.length+' annotazioni';
  const list=document.getElementById('nc24NotebookList');if(!list)return;
  list.replaceChildren();const found=entries.filter(e=>!query||[nc24EntryTitle(e),nc24EntryDetail(e),e.note].join(' ').toLowerCase().includes(query));
  if(!entries.some(e=>e.key===nc24NotebookSelected))nc24NotebookSelected=entries[0]?.key||null;
  for(const e of found){const b=document.createElement('button');b.type='button';b.className='nc24-note-row'+(nc24NotebookSelected===e.key?' is-selected':'');b.dataset.nc24Entry=e.key;b.setAttribute('role','option');b.setAttribute('aria-selected',String(nc24NotebookSelected===e.key));
    const title=document.createElement('strong');title.textContent=nc24EntryTitle(e);
    const details=document.createElement('small');details.textContent=nc24EntryDetail(e);
    const snippet=document.createElement('span');snippet.textContent=(e.note||'').trim().slice(0,140)||'Annotazione vuota';b.append(title,details,snippet);list.append(b);}
  if(!found.length){const p=document.createElement('p');p.className='nc24-notebook-noresult';p.textContent=entries.length?'Nessuna annotazione corrisponde alla ricerca.':'Nessuna annotazione. Segna un elemento o crea un appunto.';list.append(p);}
  const e=entries.find(x=>x.key===nc24NotebookSelected),editor=document.getElementById('nc24NotebookEditor');
  document.getElementById('nc24NotebookEmpty').hidden=!!e;editor.hidden=!e;if(!e)return;
  document.getElementById('nc24EntryKind').textContent=e.kind==='frame'?'PACCHETTO SEGNATO':e.kind==='artifact'?'ARTEFATTO SEGNATO':e.kind==='conversation'?'CONVERSAZIONE SEGNATA':e.kind==='legacy'?'NOTE GENERALI DELLA CATTURA':'APPUNTO LIBERO';
  document.getElementById('nc24EntryTitle').textContent=nc24EntryTitle(e);
  document.getElementById('nc24EntryContext').textContent=e.kind==='frame'?nc24PacketSubtitle(e.packet)+' · '+nc40Date(e.packet.ts):['artifact','conversation'].includes(e.kind)?nc24EntryDetail(e)+' · '+e.src+' \u2192 '+e.dst:nc24EntryDetail(e);
  const input=document.getElementById('nc24EntryText');input.maxLength=['frame','artifact','conversation'].includes(e.kind)?1200:8000;input.value=e.note;
  const idx=entries.findIndex(x=>x.key===e.key);
  document.getElementById('nc24OrderUp').disabled=idx<=0;document.getElementById('nc24OrderDown').disabled=idx<0||idx>=entries.length-1;
  const open=document.getElementById('nc24OpenFrame');open.hidden=!['frame','artifact','conversation'].includes(e.kind);
  open.textContent=e.kind==='artifact'?'Apri artefatto':e.kind==='conversation'?'Apri conversazione':'Apri frame';
  open.disabled=['artifact','conversation'].includes(e.kind)&&!nc25MarkSourceVerified(e);
  document.getElementById('nc24DeleteEntry').textContent=e.kind==='frame'||['artifact','conversation'].includes(e.kind)?'Rimuovi segnalazione':e.kind==='legacy'?'Cancella note':'Elimina appunto';
};
function nc25OpenSource(e){
  if(e.kind==='frame')return nc40OpenFrame(e.captureId,e.frame);
  const slot=nc25MarkSourceVerified(e);if(!slot){notify('Fonte non verificata','Reimporta la cattura originale per aprire questa evidenza.',true);return;}
  if(nc40.active!==slot.id)nc40Activate(slot.id,false);
  if(e.kind==='conversation'){
    setPage('flows');const f=(state.flows||[]).find(x=>nc25FlowKey(x)===e.sourceKey);
    if(f){state.selectedFlow=f.id;renderFlows();renderFlowInspector();}
    else notify('Conversazione non ricostruita','Puoi ritrovare i frame di origine nella vista Pacchetti.',true);
  }else{
    setPage('loot');const a=(state.loot||[]).find(x=>nc25ArtifactKey(x)===e.sourceKey);
    if(a){state.selectedLoot=a.id;ncRenderLoot();ncRenderLootDetail();}
    else notify('Artefatto da ricostruire','La cattura e\' disponibile. Se necessario, apri i frame di origine.',true);
  }
}
const nc25BaseDossierRender=nc24RenderDossier;
nc24RenderDossier=function(){
  nc25BaseDossierRender();const list=document.getElementById('nc24DossierEvidence');if(!list)return;
  const entries=nc24AllEntries(),evidence=entries.filter(e=>['frame','artifact','conversation'].includes(e.kind));
  const packetNodes=[...list.querySelectorAll('.nc24-evidence-card')],extras=[...list.querySelectorAll('.nc24-evidence-foot')];
  const packetEntries=entries.filter(e=>e.kind==='frame'),packetByKey=new Map(packetEntries.map((e,i)=>[e.key,packetNodes[i]]));
  list.replaceChildren();
  if(!evidence.length){const empty=document.createElement('div');empty.className='nc24-evidence-empty';empty.innerHTML=nc24Icon('i-bookmark')+'<strong>Nessuna evidenza segnata</strong><p>Segna un pacchetto, un artefatto o una conversazione durante l\'analisi, con una nota investigativa.</p>';list.append(empty);}
  for(const e of evidence){
    if(e.kind==='frame'){const node=packetByKey.get(e.key);if(node)list.append(node);continue;}
    const card=document.createElement('article');card.className='nc24-evidence-card nc25-entity-card';
    const top=document.createElement('div');top.className='nc24-evidence-card-top';const title=document.createElement('div'),type=document.createElement('span'),strong=document.createElement('strong');
    type.className='nc24-evidence-type';type.textContent=e.kind==='artifact'?'ARTEFATTO':'CONVERSAZIONE';strong.textContent=e.title;title.append(type,strong);
    const button=document.createElement('button');button.type='button';button.className='soft-button';button.textContent='Apri fonte';button.disabled=!nc25MarkSourceVerified(e);button.addEventListener('click',()=>nc25OpenSource(e));
    top.append(title,button);card.append(top);
    const source=document.createElement('p');source.className='nc24-evidence-source';source.textContent=nc24EntryDetail(e)+' · primo frame #'+e.frames[0]+' · '+e.src+' \u2192 '+e.dst;card.append(source);
    const note=document.createElement('p');note.className='nc24-evidence-note';note.textContent=e.note;card.append(note);list.append(card);
  }
  list.append(...extras);
  document.getElementById('nc24DossierBookmarkCount').textContent=String(evidence.length);
  document.getElementById('nc24NotebookBadge').textContent=String(entries.length);
};
const nc25BaseReportData=nc24ExportReportData;
nc24ExportReportData=function(){
  const out=nc25BaseReportData(),entries=nc24AllEntries(),oldEvidence=out.evidence,byKey=entries.filter(e=>e.kind==='frame');
  const framesByKey=new Map(byKey.map((e,i)=>[e.key,{...oldEvidence[i],kind:'frame',title:'Frame #'+e.frame,frames:[e.frame]}]));
  out.evidence=entries.filter(e=>['frame','artifact','conversation'].includes(e.kind)).map(e=>e.kind==='frame'?framesByKey.get(e.key):{
    kind:e.kind,title:e.title,frames:e.frames,capture:e.slot?.name||'Cattura da reimportare',captureId:e.captureId,
    sha256:e.captureId.startsWith('sha256-files:')?e.captureId.slice(13):null,protocol:e.protocol||'',src:e.src,dst:e.dst,time:nc40Date(e.observedAt),note:e.note,
    verified:!!nc25MarkSourceVerified(e)});
  out.notes=entries.filter(e=>['free','legacy'].includes(e.kind)).map(e=>({label:nc24EntryTitle(e),text:e.note}));
  return out;
};
nc24ReportHTML=function(){
  const d=nc24ExportReportData(),h=nc24Escape,rich=v=>h(v||'Non specificato').replace(/\n/g,'<br>');
  const sources=d.captures.map(c=>`<tr><td>${h(c.name)}</td><td>${h(c.format)} · ${c.frames} frame</td><td>${h(c.id.startsWith('sha256-files:')?c.id.slice(13):'Non verificato / demo')}</td></tr>`).join('');
  const evidence=d.evidence.map((e,i)=>`<article><div class="eyebrow">EVIDENZA ${i+1} · ${h(e.kind==='artifact'?'ARTEFATTO':e.kind==='conversation'?'CONVERSAZIONE':'PACCHETTO')} · ${h(e.time)}</div><h3>${h(e.title)}</h3><p><b>Cattura:</b> ${h(e.capture)}<br><b>SHA-256 sorgente:</b> ${h(e.sha256||'Non verificato')}<br><b>Frame di riferimento:</b> ${h((e.frames||[]).map(n=>'#'+n).join(', '))}<br><b>Origine:</b> ${h(e.src)} → ${h(e.dst)}${e.verified===false?'<br><b>Nota:</b> riferimento non ancora verificato sulla cattura originale':''}</p><blockquote><b>Nota dell\'analista</b><br>${rich(e.note)}</blockquote></article>`).join('')||'<p>Nessuna evidenza selezionata.</p>';
  const notes=d.notes.filter(x=>x.text.trim()).map(x=>`<article><h3>${h(x.label)}</h3><p>${rich(x.text)}</p></article>`).join('')||'<p>Nessun appunto aggiuntivo.</p>';
  return `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${h(d.title)} | Dossier NullCap</title><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'"><style>*,*:before,*:after{box-sizing:border-box}body{font:13px/1.65 Arial,sans-serif;color:#182734;background:white;max-width:950px;padding:0 28px;margin:35px auto}h1{font-size:29px;color:#163e53}h2{color:#18546b;font-size:19px;margin:32px 0 10px;border-bottom:2px solid #dce9eb;padding-bottom:9px}h3{margin:7px 0;color:#1e4859;font-size:15px}p{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{text-align:left;vertical-align:top;border-bottom:1px solid #d8e4e8;padding:8px;word-wrap:break-word}td:last-child{font:10px/1.55 monospace;word-break:break-all}article{margin:10px 0;padding:14px;border:1px solid #dae6e9;border-radius:7px;break-inside:avoid}blockquote{margin:10px 0 0;padding:10px 13px;background:#f3f7f8;border-left:3px solid #69a7af;white-space:normal}.eyebrow{font:10px monospace;color:#476b7b}.warning{padding:12px;border:1px solid #dec8a2;background:#fff8eb;color:#6e5330}.muted{color:#5e7781;font-size:11px}@media print{@page{size:A4;margin:15mm}body{margin:0;max-width:none;padding:0}h2{break-after:avoid}}</style></head><body><div class="eyebrow">NULLCAP STUDIO · DOSSIER INVESTIGATIVO · DOCUMENTO OFFLINE</div><h1>${h(d.title)}</h1><p><b>Analista:</b> ${h(d.analyst||'Non indicato')}<br><b>Generato:</b> ${h(d.generatedAt)}</p><p class="warning">Le note scritte dall'analista possono contenere dati riservati. Controllare il documento prima della condivisione. I payload originali e i valori sensibili estratti non sono aggiunti automaticamente.</p><h2>1 · Obiettivo e contesto</h2><p>${rich(d.objective)}</p><h2>2 · Acquisizioni di riferimento</h2><table><thead><tr><th>Cattura</th><th>Informazioni</th><th>SHA-256</th></tr></thead><tbody>${sources||'<tr><td colspan="3">Nessuna cattura disponibile.</td></tr>'}</tbody></table><h2>3 · Evidenze selezionate (${d.evidence.length})</h2>${evidence}<h2>4 · Appunti dell'analista</h2>${notes}<h2>5 · Valutazioni e conclusioni</h2><p>${rich(d.conclusions)}</p><h2>6 · Limiti e approfondimenti</h2><p>${rich(d.limitations)}</p><p class="muted">L'ordine delle evidenze e' narrativo, distinto dalla cronologia dei frame. I dati tecnici sono osservazioni locali e non provano automaticamente un illecito.</p></body></html>`;
};
nc24ShowPreview=function(){
  const d=nc24ExportReportData(),host=document.getElementById('nc24PreviewContent');host.replaceChildren();
  const section=(label,value)=>{const node=document.createElement('section'),h=document.createElement('h4'),p=document.createElement('p');h.textContent=label;p.textContent=value||'Non specificato';node.append(h,p);host.append(node);};
  section('Obiettivo',d.objective);section('Acquisizioni',d.captures.map(c=>c.name).join(' · '));
  for(const e of d.evidence)section(e.title+' · '+e.capture,e.note);
  for(const e of d.notes)if(e.text.trim())section(e.label,e.text);
  section('Conclusioni',d.conclusions);section('Limiti',d.limitations);
  nc26OpenOverlay('nc24DossierPreview');
};
function nc25Wire(){
  const modal=nc25Modal(),note=document.getElementById('nc25MarkNote');
  document.getElementById('nc25MarkForm').addEventListener('submit',nc25Save);
  note.addEventListener('input',()=>note.setCustomValidity(''));
  document.getElementById('nc25MarkClose').addEventListener('click',nc25Close);
  document.getElementById('nc25MarkCancel').addEventListener('click',nc25Close);
  modal.addEventListener('click',e=>{if(e.target.hasAttribute('data-nc25-close'))nc25Close();});
  window.addEventListener('keydown',e=>{if(modal.hidden)return;if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();nc25Close();}else if(e.key==='Tab')nc24TrapTab(e,document.getElementById('nc25MarkForm'));},true);
  const open=document.getElementById('nc24OpenFrame');open.onclick=()=>{const e=nc24AllEntries().find(x=>x.key===nc24NotebookSelected);if(!e)return;nc31HideCase();nc25OpenSource(e);};
  document.getElementById('nc24NotebookCount').nextElementSibling.textContent='Pacchetti, artefatti, conversazioni e appunti delle acquisizioni';
  const oldLabel=document.getElementById('nc24DossierBookmarkCount').parentElement;oldLabel.lastChild.textContent=' evidenze segnate';
  document.querySelector('#nc24DossierEvidence').closest('.nc26-doc-accordion').querySelector('.nc24-doc-section-title p').textContent='Pacchetti, artefatti e conversazioni entrano nel dossier con una nota e i frame originali.';
  nc24RenderDossier();
}
const nc25OldWire=wireUI;
wireUI=function(){nc25OldWire();nc25Wire();};
