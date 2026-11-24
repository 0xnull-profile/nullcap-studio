'use strict';
/* A24 — Dossier-driven workflow. Reuses v31 frame bookmarks and existing
   capture-scoped notes; keeps PCAP bytes and packet reconstruction unchanged.
   Draft text and ordering are additional analyst-authored case metadata. */
const NC24_MAX_FREE_NOTES=160;
const NC24_MAX_REFERENCES=1500;
function nc24Blank(){return {objective:'',conclusions:'',limitations:'',freeNotes:[],order:[],refs:[]};}
nc40.dossier=nc24Blank();
let nc24PendingMark=null,nc24PreviousFocus=null,nc24CaseFocus=null,nc24NotebookSelected=null;
const nc24El=id=>document.getElementById(id);
const nc24Icon=(id)=>`<svg aria-hidden="true"><use href="#${id}"/></svg>`;
const nc24Escape=val=>escapeHtml(String(val??''));
function nc24Text(v,max=1200){return String(v??'').replace(/\0/g,'').slice(0,max);}
function nc24NormalizeDossier(d){
  const value=d&&typeof d==='object'&&!Array.isArray(d)?d:{};
  const out=nc24Blank();
  out.objective=nc24Text(value.objective,5000);out.conclusions=nc24Text(value.conclusions,5000);out.limitations=nc24Text(value.limitations,3500);
  out.freeNotes=Array.isArray(value.freeNotes)?value.freeNotes.slice(0,NC24_MAX_FREE_NOTES).filter(x=>x&&typeof x==='object'&&typeof x.id==='string'&&/^[a-zA-Z0-9_-]{1,60}$/.test(x.id)).map(x=>({id:x.id,text:nc24Text(x.text,8000)})):[];
  out.order=Array.isArray(value.order)?value.order.slice(0,1700).filter(x=>typeof x==='string'&&x.length<=850):[];
  out.refs=Array.isArray(value.refs)?value.refs.slice(0,NC24_MAX_REFERENCES).filter(x=>x&&typeof x==='object'&&typeof x.captureId==='string'&&x.captureId.length<650&&Number.isSafeInteger(x.frame)&&x.frame>0&&x.frame<300000&&typeof x.src==='string'&&typeof x.dst==='string'&&typeof x.note==='string').map(x=>({captureId:x.captureId,frame:x.frame,src:nc24Text(x.src,160),dst:nc24Text(x.dst,160),length:Number(x.length)||0,protocol:nc24Text(x.protocol,60),note:nc24Text(x.note,1200)})):[];
  return out;
}
function nc24StoredCase(id){
  if(id===state.captureId&&state.investigation)return state.investigation;
  return nc40.portableCases?.[id]||nc31ReadCase(id)||null;
}
function nc24CaptureEntries(){
  const entries=[];
  for(const slot of nc40.captures){
    const saved=nc24StoredCase(slot.id);
    if(saved?.bookmarks&&typeof saved.bookmarks==='object')for(const [key,item] of Object.entries(saved.bookmarks)){
      const frame=Number(key),packet=slot.packets[frame-1];
      if(!Number.isSafeInteger(frame)||!packet||!item||packet.src!==item.src||packet.dst!==item.dst||packet.length!==item.length)continue;
      entries.push({key:'frame:'+slot.id+'|'+frame,kind:'frame',captureId:slot.id,frame,slot,packet,note:nc24Text(item.note,1200)});
    }
    const legacyNote=slot.id===state.captureId?String(state.investigation?.notes||''):String(saved?.notes||nc40.captureNotes?.[slot.id]||'');
    if(legacyNote.trim())entries.push({key:'legacy:'+slot.id,kind:'legacy',captureId:slot.id,slot,note:nc24Text(legacyNote,8000)});
  }
  for(const item of nc40.dossier.freeNotes)entries.push({key:'note:'+item.id,kind:'free',note:item.text,id:item.id});
  const order=new Map(nc40.dossier.order.map((key,i)=>[key,i]));
  entries.sort((a,b)=>(order.has(a.key)?order.get(a.key):100000)-(order.has(b.key)?order.get(b.key):100000)||
    (a.kind==='frame'?0:1)-(b.kind==='frame'?0:1)||(a.slot?.name||'').localeCompare(b.slot?.name||'')||(a.frame||0)-(b.frame||0));
  return entries;
}
function nc24ExportReferences(){
  return nc24CaptureEntries().filter(e=>e.kind==='frame').slice(0,NC24_MAX_REFERENCES).map(e=>({captureId:e.captureId,frame:e.frame,src:e.packet.src,dst:e.packet.dst,length:e.packet.length,protocol:e.packet.protocol,note:e.note}));
}
function nc24ExportDossier(){
  // Keep metadata-only references when their original PCAP has not yet been
  // reimported. A loaded capture is authoritative; deleted marks stay deleted.
  const verified=nc24ExportReferences();
  const unresolved=nc40.dossier.refs.filter(r=>!nc40Slot(r.captureId));
  const refs=[...verified,...unresolved].slice(0,NC24_MAX_REFERENCES);
  return {...nc24NormalizeDossier(nc40.dossier),refs};
}
function nc24ApplyPending(id){
  if(!state.investigation||state.captureId!==id||!nc40.dossier?.refs?.length)return;
  let changed=false;
  for(const r of nc40.dossier.refs){
    if(r.captureId!==id||state.investigation.bookmarks[r.frame])continue;
    const p=state.packets[r.frame-1];
    if(!p||p.src!==r.src||p.dst!==r.dst||p.length!==r.length||p.protocol!==r.protocol)continue;
    if(Object.keys(state.investigation.bookmarks).length>=NC31_CASE_MAX_BOOKMARKS)break;
    state.investigation.bookmarks[r.frame]={id:r.frame,src:p.src,dst:p.dst,length:p.length,protocol:p.protocol,note:r.note};changed=true;
  }
  if(changed){nc31SaveCase();nc31RefreshCase();renderPacketInspector();}
}
function nc24ImportDossier(value){
  nc40.dossier=nc24NormalizeDossier(value);
  for(const [id,key] of [['nc24Objective','objective'],['nc24Conclusions','conclusions'],['nc24Limitations','limitations']]){const el=nc24El(id);if(el)el.value=nc40.dossier[key];}
  nc24ApplyPending(state.captureId);
  nc24RenderDossier();
  if(state.caseModalOpen)nc24RenderNotebook();
}
const nc24OriginalApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  // Replacing the initial demonstration capture starts the real evidence set.
  // Do not carry its synthetic bookmark references into a new real case.
  // Imported ZIP/JSON references are unaffected: they are managed by the
  // workspace restore functions rather than this demo-only transition.
  const retiredDemo=!options.isDemo&&nc40.captures.length===1&&nc40.captures[0].isDemo?nc40.captures[0].id:null;
  const result=nc24OriginalApplyCapture(packets,options);
  if(retiredDemo&&!nc40Slot(retiredDemo)){
    nc40.dossier.refs=nc40.dossier.refs.filter(r=>r.captureId!==retiredDemo);
    nc40.dossier.order=nc40.dossier.order.filter(k=>k!=='legacy:'+retiredDemo&&!k.startsWith('frame:'+retiredDemo+'|'));
    if(nc40.portableCases)delete nc40.portableCases[retiredDemo];
    if(nc40.captureNotes)delete nc40.captureNotes[retiredDemo];
  }
  nc24ApplyPending(state.captureId);
  nc24RenderDossier();
  return result;
};
window.NullCap.applyCapture=applyCapture;
function nc24PersistReference(captureId,frame,item){
  const refs=nc40.dossier.refs;
  const idx=refs.findIndex(x=>x.captureId===captureId&&x.frame===frame);
  if(!item){if(idx>=0)refs.splice(idx,1);return;}
  const p=nc40Slot(captureId)?.packets?.[frame-1];if(!p)return;
  const ref={captureId,frame,src:p.src,dst:p.dst,length:p.length,protocol:p.protocol,note:nc24Text(item.note,1200)};
  if(idx>=0)refs[idx]=ref;else if(refs.length<NC24_MAX_REFERENCES)refs.push(ref);
}
function nc24SaveNote(entry,value){
  const note=nc24Text(value,entry.kind==='frame'?1200:8000);
  if(entry.kind==='free'){
    const item=nc40.dossier.freeNotes.find(x=>x.id===entry.id);if(item)item.text=note;
  }else if(entry.kind==='frame'){
    const c=nc24StoredCase(entry.captureId);
    if(!c?.bookmarks?.[entry.frame])return;
    c.bookmarks[entry.frame].note=note;nc24PersistReference(entry.captureId,entry.frame,c.bookmarks[entry.frame]);
    if(entry.captureId===state.captureId)nc31SaveCase();
    else {nc40.portableCases[entry.captureId]=c;try{localStorage.setItem(NC31_CASE_PREFIX+entry.captureId,JSON.stringify(c));}catch(_){/* exported case is portable source of truth */}}
  }else if(entry.kind==='legacy'){
    const c=nc24StoredCase(entry.captureId);if(!c)return;
    c.notes=note;nc40.captureNotes[entry.captureId]=note;
    if(entry.captureId===state.captureId)nc31SaveCase();
    else {nc40.portableCases[entry.captureId]=c;try{localStorage.setItem(NC31_CASE_PREFIX+entry.captureId,JSON.stringify(c));}catch(_){}}
  }
  nc24RenderDossier();
}
function nc24PacketSubtitle(p){return [p.protocol||p.transport||'RETE',p.src||'?', '→',p.dst||'?'].join(' ');}
function nc24OpenMark(p){
  if(!p||!state.investigation)return;
  const slot=nc40Slot(state.captureId);if(!slot){notify('Pacchetto non nel caso','Aggiungi la cattura al workspace per segnare il frame.',true);return;}
  nc24PendingMark={captureId:slot.id,frame:p.id};nc24PreviousFocus=document.activeElement;
  const existing=state.investigation.bookmarks[p.id];
  nc24El('nc24MarkFrame').textContent='Frame #'+p.id+' · '+(p.protocol||'RETE');
  nc24El('nc24MarkCapture').textContent=nc40Label(slot);
  nc24El('nc24MarkRoute').textContent=(p.src||'?')+'  →  '+(p.dst||'?')+(p.dstPort?' :'+p.dstPort:'');
  nc24El('nc24MarkTime').textContent=nc40Date(p.ts);
  nc24El('nc24MarkTitle').textContent=existing?'Modifica segnalazione':'Segna pacchetto';
  nc24El('nc24MarkSubmit').innerHTML=nc24Icon('i-bookmark')+(existing?' Aggiorna nota':' Aggiungi al dossier');
  nc24El('nc24MarkNote').value=existing?.note||'';
  nc24El('nc24MarkModal').hidden=false;nc24El('nc24MarkNote').focus();
}
function nc24CloseMark(){nc24El('nc24MarkModal').hidden=true;nc24PendingMark=null;nc24PreviousFocus?.focus?.();}
const nc24OriginalMark=nc31MarkPacket;
nc31MarkPacket=function(packet){nc24OpenMark(packet);};
function nc24ConfirmMark(e){
  e.preventDefault();const ref=nc24PendingMark,note=nc24El('nc24MarkNote').value.trim();
  if(!ref||!note){nc24El('nc24MarkNote').setCustomValidity('Aggiungi una nota prima di salvare.');nc24El('nc24MarkNote').reportValidity();return;}
  if(ref.captureId!==state.captureId||!state.investigation){notify('Cattura cambiata','Apri nuovamente il pacchetto.',true);nc24CloseMark();return;}
  const p=state.packets[ref.frame-1];if(!p){nc24CloseMark();return;}
  const c=state.investigation,already=!!c.bookmarks[p.id];
  if(!already&&Object.keys(c.bookmarks).length>=NC31_CASE_MAX_BOOKMARKS){notify('Limite raggiunto','Massimo 250 pacchetti segnati.',true);return;}
  c.bookmarks[p.id]={id:p.id,src:p.src,dst:p.dst,length:p.length,protocol:p.protocol,note:note.slice(0,1200)};
  nc24PersistReference(ref.captureId,p.id,c.bookmarks[p.id]);
  nc31SaveCase();nc31RefreshCase();renderPacketInspector();
  if(String(state.advancedExpr||'').includes('tag:'))renderPacketTable();
  nc24RenderDossier();nc24CloseMark();
  notify('Segnalazione salvata',`Frame #${p.id} aggiunto al dossier con la nota investigativa.`);
}
const nc24OriginalInspector=renderPacketInspector;
renderPacketInspector=function(){
  nc24OriginalInspector();
  const b=nc24El('nc31MarkPacket');if(!b)return;
  // A09 already renders this as a 35px icon-only button with a custom hover/
  // keyboard-focus tooltip. Do not inject visible text into that button.
  const label=nc31CurrentBookmark()?'Modifica segnalazione':'Segna pacchetto';
  b.setAttribute('aria-label',label);
  b.setAttribute('data-tip',label);
  b.removeAttribute('title');
};
function nc24AllEntries(){return nc24CaptureEntries();}
function nc24EntryTitle(entry){return entry.kind==='frame'?'Frame #'+entry.frame:entry.kind==='legacy'?'Note generali · '+(entry.slot?.name||'cattura'):'Appunto libero';}
function nc24EntryDetail(entry){return entry.kind==='frame'?(entry.slot?.name||'Cattura')+' · '+(entry.packet?.protocol||'RETE'):(entry.kind==='legacy'?'Note della cattura':'Annotazione dell’analista');}
function nc24RenderNotebook(){
  const entries=nc24AllEntries(),query=nc24El('nc24NotebookFilter')?.value.trim().toLowerCase()||'';
  nc24El('nc24NotebookCount').textContent=entries.length+' annotazioni';
  const list=nc24El('nc24NotebookList');if(!list)return;
  list.replaceChildren();
  const found=entries.filter(e=>!query||[nc24EntryTitle(e),nc24EntryDetail(e),e.note].join(' ').toLowerCase().includes(query));
  if(!nc24NotebookSelected&&entries.length)nc24NotebookSelected=entries[0].key;
  for(const e of found){const button=document.createElement('button');button.type='button';button.className='nc24-note-row'+(nc24NotebookSelected===e.key?' is-selected':'');button.dataset.nc24Entry=e.key;button.setAttribute('role','option');button.setAttribute('aria-selected',String(nc24NotebookSelected===e.key));
    const heading=document.createElement('strong');heading.textContent=nc24EntryTitle(e);const details=document.createElement('small');details.textContent=nc24EntryDetail(e);const snippet=document.createElement('span');snippet.textContent=e.note.trim().slice(0,140)||'Annotazione vuota';button.append(heading,details,snippet);list.append(button);
  }
  if(!found.length){const hint=document.createElement('p');hint.className='nc24-notebook-noresult';hint.textContent=entries.length?'Nessuna annotazione corrisponde alla ricerca.':'Nessuna annotazione. Segna un pacchetto o crea un appunto.';list.append(hint);}
  const selected=entries.find(e=>e.key===nc24NotebookSelected);
  nc24El('nc24NotebookEmpty').hidden=!!selected;nc24El('nc24NotebookEditor').hidden=!selected;
  if(!selected)return;
  nc24El('nc24EntryKind').textContent=selected.kind==='frame'?'PACCHETTO SEGNATO':selected.kind==='legacy'?'NOTE GENERALI DELLA CATTURA':'APPUNTO LIBERO';
  nc24El('nc24EntryTitle').textContent=nc24EntryTitle(selected);
  nc24El('nc24EntryContext').textContent=selected.kind==='frame'?nc24PacketSubtitle(selected.packet)+' · '+nc40Date(selected.packet.ts):nc24EntryDetail(selected);
  const textarea=nc24El('nc24EntryText');textarea.maxLength=selected.kind==='frame'?1200:8000;textarea.value=selected.note;
  const idx=entries.findIndex(e=>e.key===selected.key);
  nc24El('nc24OrderUp').disabled=idx<=0;nc24El('nc24OrderDown').disabled=idx<0||idx>=entries.length-1;
  nc24El('nc24OpenFrame').hidden=selected.kind!=='frame';
  nc24El('nc24DeleteEntry').textContent=selected.kind==='frame'?'Rimuovi segnalazione':selected.kind==='legacy'?'Cancella note':'Elimina appunto';
}
function nc24AddFreeNote(){
  if(nc40.dossier.freeNotes.length>=NC24_MAX_FREE_NOTES){notify('Limite note','Massimo 160 appunti liberi.',true);return;}
  const id=(globalThis.crypto?.randomUUID?.()||Date.now().toString(36)+Math.random().toString(36).slice(2)).replace(/[^a-zA-Z0-9_-]/g,'').slice(0,60);
  nc40.dossier.freeNotes.push({id,text:''});nc24NotebookSelected='note:'+id;
  nc24RenderNotebook();nc24El('nc24EntryText').focus();nc24RenderDossier();
}
function nc24MoveNote(delta){
  const entries=nc24AllEntries(),index=entries.findIndex(e=>e.key===nc24NotebookSelected);if(index<0||index+delta<0||index+delta>=entries.length)return;
  const order=entries.map(e=>e.key);[order[index],order[index+delta]]=[order[index+delta],order[index]];
  nc40.dossier.order=order;nc24RenderNotebook();nc24RenderDossier();
}
async function nc24RemoveNote(){
  const e=nc24AllEntries().find(x=>x.key===nc24NotebookSelected);if(!e||!await nc26Confirm('Rimuovere questa annotazione dal taccuino? I frame originali non saranno modificati.'))return;
  if(e.kind==='free')nc40.dossier.freeNotes=nc40.dossier.freeNotes.filter(x=>x.id!==e.id);
  else if(e.kind==='frame'){
    const c=nc24StoredCase(e.captureId);if(c?.bookmarks?.[e.frame]){delete c.bookmarks[e.frame];nc24PersistReference(e.captureId,e.frame,null);if(e.captureId===state.captureId)nc31SaveCase();else{nc40.portableCases[e.captureId]=c;try{localStorage.setItem(NC31_CASE_PREFIX+e.captureId,JSON.stringify(c));}catch(_){}}}
    if(e.captureId===state.captureId){nc31RefreshCase();renderPacketInspector();if(String(state.advancedExpr||'').includes('tag:'))renderPacketTable();}
  }else nc24SaveNote(e,'');
  nc40.dossier.order=nc40.dossier.order.filter(k=>k!==e.key);nc24NotebookSelected=null;nc24RenderNotebook();nc24RenderDossier();
}
const nc24OldShowCase=nc31ShowCase;
nc31ShowCase=function(){nc24CaseFocus=document.activeElement;nc24OldShowCase();nc24NotebookSelected=null;nc24RenderNotebook();nc24El('nc24NotebookFilter').focus();};
const nc24OldHideCase=nc31HideCase;
nc31HideCase=function(){nc24OldHideCase();nc24NotebookSelected=null;if(nc24CaseFocus?.isConnected)nc24CaseFocus.focus();nc24CaseFocus=null;};
function nc24RenderDossier(){
  const root=nc24El('nc24Dossier');if(!root)return;
  const entries=nc24AllEntries(),frames=entries.filter(e=>e.kind==='frame'),free=entries.filter(e=>e.kind==='free');
  nc24El('nc24DossierCaptureCount').textContent=String(nc40.captures.length);
  nc24El('nc24DossierBookmarkCount').textContent=String(frames.length);
  nc24El('nc24DossierFreeCount').textContent=String(free.length);
  nc24El('nc24NotebookBadge').textContent=String(entries.length);
  const list=nc24El('nc24DossierEvidence');list.replaceChildren();
  if(!frames.length){const empty=document.createElement('div');empty.className='nc24-evidence-empty';empty.innerHTML=nc24Icon('i-bookmark')+'<strong>Ancora nessun pacchetto segnato</strong><p>Seleziona un pacchetto durante l’analisi e usa «Segna pacchetto» per aggiungerlo al dossier insieme alla nota.</p>';list.append(empty);}
  for(const e of frames){const card=document.createElement('article');card.className='nc24-evidence-card';
    const top=document.createElement('div');top.className='nc24-evidence-card-top';
    const text=document.createElement('div'),tag=document.createElement('span'),heading=document.createElement('strong');tag.className='nc24-evidence-type';tag.textContent=e.packet?.protocol||'RETE';heading.textContent='Frame #'+e.frame; text.append(tag,heading);
    const action=document.createElement('button');action.className='soft-button';action.type='button';action.dataset.nc24OpenFrame=e.key;action.innerHTML=nc24Icon('i-open-packets')+' Apri frame';top.append(text,action);card.append(top);
    const source=document.createElement('p');source.className='nc24-evidence-source';source.textContent=(e.slot?.name||'Cattura')+' · '+nc40Date(e.packet?.ts)+' · '+(e.packet?.src||'?')+' → '+(e.packet?.dst||'?');card.append(source);
    const note=document.createElement('p');note.className='nc24-evidence-note';note.textContent=e.note||'(Nessuna nota)';card.append(note);list.append(card);
  }
  const noteCount=free.length;
  if(noteCount){const info=document.createElement('p');info.className='nc24-evidence-foot';info.textContent=noteCount+' appunti liberi disponibili nel Taccuino; possono essere organizzati nella ricostruzione del caso.';list.append(info);}
}
function nc24ExportReportData(){
  nc40SaveFields();const entries=nc24AllEntries();return {title:nc40.title,analyst:nc40.analyst,objective:nc40.dossier.objective,conclusions:nc40.dossier.conclusions,limitations:nc40.dossier.limitations,
    captures:nc40.captures.map(s=>({name:s.name,id:s.id,format:s.format,frames:s.packets.length,ready:s.ready,partial:s.partial})),
    evidence:entries.filter(e=>e.kind==='frame').map(e=>({frame:e.frame,capture:e.slot?.name||'Cattura',captureId:e.captureId,sha256:e.slot?.id.startsWith('sha256-files:')?e.slot.id.slice(13):null,protocol:e.packet?.protocol||'RETE',src:e.packet?.src||'',dst:e.packet?.dst||'',time:nc40Date(e.packet?.ts),note:e.note})),
    notes:entries.filter(e=>e.kind!=='frame').map(e=>({label:nc24EntryTitle(e),text:e.note})),generatedAt:new Date().toISOString()};
}
function nc24ReportHTML(){
  const d=nc24ExportReportData(),h=nc24Escape,rich=v=>h(v||'Non specificato').replace(/\n/g,'<br>');
  const sources=d.captures.map(c=>`<tr><td>${h(c.name)}</td><td>${h(c.format)} · ${c.frames} frame</td><td>${h(c.id.startsWith('sha256-files:')?c.id.slice(13):'Non verificato / demo')}</td></tr>`).join('');
  const evidence=d.evidence.map((e,i)=>`<article><div class="eyebrow">EVIDENZA ${i+1} · ${h(e.protocol)} · ${h(e.time)}</div><h3>Frame #${e.frame}</h3><p><b>Acquisizione:</b> ${h(e.capture)}<br><b>SHA-256 sorgente:</b> ${h(e.sha256||'Non verificato')}<br><b>Origine:</b> ${h(e.src)} → ${h(e.dst)}</p><blockquote><b>Nota dell'analista</b><br>${rich(e.note)}</blockquote></article>`).join('')||'<p>Nessuna evidenza selezionata.</p>';
  const notes=d.notes.filter(x=>x.text.trim()).map(x=>`<article><h3>${h(x.label)}</h3><p>${rich(x.text)}</p></article>`).join('')||'<p>Nessun appunto aggiuntivo.</p>';
  return `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${h(d.title)} | Dossier NullCap</title><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'"><style>*,*:before,*:after{box-sizing:border-box}body{font:13px/1.65 Arial,sans-serif;color:#182734;background:white;max-width:950px;padding:0 28px;margin:35px auto}h1{font-size:29px;color:#163e53}h2{color:#18546b;font-size:19px;margin:32px 0 10px;border-bottom:2px solid #dce9eb;padding-bottom:9px}h3{margin:7px 0;color:#1e4859;font-size:15px}p{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{text-align:left;vertical-align:top;border-bottom:1px solid #d8e4e8;padding:8px;word-wrap:break-word}td:last-child{font:10px/1.55 monospace;word-break:break-all}article{margin:10px 0;padding:14px;border:1px solid #dae6e9;border-radius:7px;break-inside:avoid}blockquote{margin:10px 0 0;padding:10px 13px;background:#f3f7f8;border-left:3px solid #69a7af;white-space:normal}.eyebrow{font:10px monospace;color:#476b7b}.warning{padding:12px;border:1px solid #dec8a2;background:#fff8eb;color:#6e5330}.muted{color:#5e7781;font-size:11px}@media print{@page{size:A4;margin:15mm}body{margin:0;max-width:none;padding:0}h2{break-after:avoid}}</style></head><body><div class="eyebrow">NULLCAP STUDIO · DOSSIER INVESTIGATIVO · DOCUMENTO OFFLINE</div><h1>${h(d.title)}</h1><p><b>Analista:</b> ${h(d.analyst||'Non indicato')}<br><b>Generato:</b> ${h(d.generatedAt)}</p><p class="warning">Documento redatto dall'analista: le note potrebbero contenere informazioni riservate inserite manualmente. Verificare prima della condivisione. Nessun payload originale viene inserito automaticamente.</p><h2>1 · Obiettivo e contesto</h2><p>${rich(d.objective)}</p><h2>2 · Acquisizioni di riferimento</h2><table><thead><tr><th>Cattura</th><th>Informazioni</th><th>Identificativo SHA-256</th></tr></thead><tbody>${sources||'<tr><td colspan="3">Nessuna cattura disponibile.</td></tr>'}</tbody></table><p class="muted">Gli hash identificano i file letti dalla piattaforma; non sono firme digitali né verifiche indipendenti della catena di custodia.</p><h2>3 · Evidenze selezionate (${d.evidence.length})</h2>${evidence}<h2>4 · Appunti dell'analista</h2>${notes}<h2>5 · Valutazioni e conclusioni</h2><p>${rich(d.conclusions)}</p><h2>6 · Limiti e approfondimenti</h2><p>${rich(d.limitations)}</p><p class="muted">L'ordine delle evidenze è narrativo e scelto dall'analista; non sostituisce la cronologia originale dei frame. Le note non provano da sole la validità di credenziali o un esito di autenticazione.</p></body></html>`;
}
function nc24ShowPreview(){
  const data=nc24ExportReportData();const content=nc24El('nc24PreviewContent');content.replaceChildren();
  const section=(title,body)=>{const row=document.createElement('section');const heading=document.createElement('h4');heading.textContent=title;const text=document.createElement('p');text.textContent=body||'Non specificato';row.append(heading,text);content.append(row);};
  section('Obiettivo',data.objective);section('Acquisizioni',data.captures.map(c=>c.name).join(' · '));
  for(const e of data.evidence)section('Frame #'+e.frame+' · '+e.capture,e.note);
  for(const e of data.notes)if(e.text.trim())section(e.label,e.text);
  section('Conclusioni',data.conclusions);section('Limiti',data.limitations);
  nc26OpenOverlay('nc24DossierPreview');
}
async function nc24DownloadReport(mode){
  if(!await nc26Confirm('Il dossier conterrà le note scritte dall’analista, potenzialmente anche dati riservati. Hai controllato il contenuto da condividere?'))return;
  const html=nc24ReportHTML(),blob=new Blob([html],{type:'text/html;charset=utf-8'});
  if(mode==='print'){
    const url=URL.createObjectURL(blob),tab=window.open(url,'_blank','noopener,noreferrer');
    if(!tab){URL.revokeObjectURL(url);notify('Finestra bloccata','Consenti le finestre popup o scarica HTML per stampare in PDF.',true);}else{notify('Documento aperto','Nella nuova scheda usa Stampa del browser per salvare un PDF.');setTimeout(()=>URL.revokeObjectURL(url),120000);}
  }else nc31DownloadFile(blob,'NullCap-Dossier-'+nc401SafeName(nc40.title)+'.html');
}
const nc24OriginalRefresh=nc40Refresh;
nc40Refresh=function(...args){const result=nc24OriginalRefresh(...args);nc24RenderDossier();if(state.caseModalOpen)nc24RenderNotebook();return result;};
function nc24TrapTab(event,root){
  if(event.key!=='Tab')return;
  const nodes=[...root.querySelectorAll('button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex="0"]')]
    .filter(el=>!el.hidden&&el.getAttribute('aria-hidden')!=='true'&&el.getClientRects().length);
  if(!nodes.length)return;
  const first=nodes[0],last=nodes[nodes.length-1],active=document.activeElement;
  if(event.shiftKey&&(active===first||!root.contains(active))){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&(active===last||!root.contains(active))){event.preventDefault();first.focus();}
}
function nc24Wire(){
  document.addEventListener('keydown',e=>{
    if(!nc24El('nc24MarkModal').hidden)nc24TrapTab(e,nc24El('nc24MarkForm'));
    else if(!nc24El('caseModal').classList.contains('hidden'))nc24TrapTab(e,nc24El('caseModal').querySelector('.nc31-case-dialog'));
  },true);
  nc24El('nc24MarkForm').addEventListener('submit',nc24ConfirmMark);
  nc24El('nc24MarkNote').addEventListener('input',e=>e.target.setCustomValidity(''));
  nc24El('nc24MarkClose').onclick=nc24CloseMark;nc24El('nc24MarkCancel').onclick=nc24CloseMark;
  nc24El('nc24MarkModal').addEventListener('click',e=>{if(e.target.hasAttribute('data-nc24-mark-close'))nc24CloseMark();});
  window.addEventListener('keydown',e=>{if(e.key==='Escape'&&!nc24El('nc24MarkModal').hidden){e.preventDefault();e.stopImmediatePropagation();nc24CloseMark();}},true);
  // Reuse the existing capture notebook modal; only its presentation changes.
  nc24El('caseClose').title='Chiudi taccuino';nc24El('caseClose').setAttribute('aria-label','Chiudi taccuino');
  nc24El('nc24OpenNotebook').onclick=nc31ShowCase;nc24El('nc24OpenNotebookAside').onclick=nc31ShowCase;
  nc24El('nc24AddFreeNote').onclick=nc24AddFreeNote;
  nc24El('nc24NotebookFilter').addEventListener('input',nc24RenderNotebook);
  nc24El('nc24NotebookList').addEventListener('click',e=>{const target=e.target.closest('[data-nc24-entry]');if(!target)return;nc24NotebookSelected=target.dataset.nc24Entry;nc24RenderNotebook();});
  nc24El('nc24EntryText').addEventListener('input',e=>{const entry=nc24AllEntries().find(x=>x.key===nc24NotebookSelected);if(!entry)return;nc24SaveNote(entry,e.target.value);nc24El('nc24EntrySaveHint').textContent='Nota aggiornata nel caso in memoria. Salva l’archivio ZIP per condividerla.';});
  nc24El('nc24EntryText').addEventListener('blur',nc24RenderNotebook);
  nc24El('nc24OrderUp').onclick=()=>nc24MoveNote(-1);nc24El('nc24OrderDown').onclick=()=>nc24MoveNote(1);
  nc24El('nc24DeleteEntry').onclick=nc24RemoveNote;
  nc24El('nc24OpenFrame').onclick=()=>{const entry=nc24AllEntries().find(e=>e.key===nc24NotebookSelected);if(entry?.kind==='frame'){nc31HideCase();nc40OpenFrame(entry.captureId,entry.frame);}};
  nc24El('nc24NotebookDossier').onclick=()=>{nc31HideCase();setPage('forensic');nc24El('nc24Dossier').scrollIntoView({behavior:'smooth'});};
  for(const id of ['nc24Objective','nc24Conclusions','nc24Limitations']){
    const key={nc24Objective:'objective',nc24Conclusions:'conclusions',nc24Limitations:'limitations'}[id];
    nc24El(id).addEventListener('input',e=>{nc40.dossier[key]=nc24Text(e.target.value,e.target.maxLength);});
  }
  const oldOpen=nc24El('openCase');if(oldOpen){oldOpen.title='Apri il Taccuino Investigativo';}
  nc24El('nc24DossierEvidence').addEventListener('click',e=>{const b=e.target.closest('[data-nc24-open-frame]');if(!b)return;const entry=nc24AllEntries().find(x=>x.key===b.dataset.nc24OpenFrame);if(entry)nc40OpenFrame(entry.captureId,entry.frame);});
  document.querySelectorAll('[data-nc24-go]').forEach(b=>b.onclick=()=>setPage(b.dataset.nc24Go));
  nc24El('nc24ExportDossier').onclick=nc24ShowPreview;nc24El('nc24PreviewReport').onclick=nc24ShowPreview;
  nc24El('nc24ClosePreview').onclick=nc26ClosePreview;
  nc24El('nc24PreviewDownload').onclick=()=>nc24DownloadReport('html');
  nc24El('nc24PreviewPrint').onclick=()=>nc24DownloadReport('print');
  nc24RenderDossier();
}
const nc24PreviousWireUI=wireUI;
wireUI=function(){nc24PreviousWireUI();nc24Wire();};
