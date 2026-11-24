'use strict';
/* Studio 3.1: investigation records, advanced filters, stream entry points. */
const NC31_CASE_PREFIX='nullcap.case.v31.';
const NC31_CASE_MAX_BOOKMARKS=250;
let nc31ActiveFilter=null;
state.advancedExpr='';
state.captureId='';
state.investigation=null;
state.caseModalOpen=false;
state.streamModalOpen=false;

// SHA-256 fallback for local file origins where Web Crypto is unavailable.
// Uses the same digest as crypto.subtle, keeping investigation IDs portable.
async function nc31SHA256Fallback(buffer){
  const bytes=new Uint8Array(buffer),size=bytes.length;
  const k=new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ]);
  const h=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const padded=Math.ceil((size+9)/64)*64,word=new Uint32Array(64);
  const bits=BigInt(size)*8n,lastBytes=Array.from({length:8},(_,i)=>Number((bits>>BigInt((7-i)*8))&255n));
  const r=(v,n)=>(v>>>n)|(v<<(32-n));
  function byteAt(i){return i<size?bytes[i]:i===size?128:i>=padded-8?lastBytes[i-(padded-8)]:0;}
  for(let offset=0;offset<padded;offset+=64){
    for(let j=0;j<16;j++){const o=offset+j*4;word[j]=((byteAt(o)<<24)|(byteAt(o+1)<<16)|(byteAt(o+2)<<8)|byteAt(o+3))>>>0;}
    for(let j=16;j<64;j++){
      const x=word[j-15],y=word[j-2];
      word[j]=(word[j-16]+(r(x,7)^r(x,18)^(x>>>3))+word[j-7]+(r(y,17)^r(y,19)^(y>>>10)))>>>0;
    }
    let [a,b,c,d,e,f,g,q]=h;
    for(let j=0;j<64;j++){
      const one=(q+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+k[j]+word[j])>>>0;
      const two=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
      q=g;g=f;f=e;e=(d+one)>>>0;d=c;c=b;b=a;a=(one+two)>>>0;
    }
    for(let j=0;j<8;j++)h[j]=(h[j]+[a,b,c,d,e,f,g,q][j])>>>0;
    if(offset&&offset%(1024*1024)===0)await new Promise(resolve=>setTimeout(resolve,0));
  }
  return Array.from(h,v=>v.toString(16).padStart(8,'0')).join('');
}
async function nc31HashBuffer(buffer){
  if(globalThis.crypto?.subtle?.digest){
    const bytes=new Uint8Array(await crypto.subtle.digest('SHA-256',buffer));
    return Array.from(bytes,v=>v.toString(16).padStart(2,'0')).join('');
  }
  return nc31SHA256Fallback(buffer);
}
function nc31DownloadFile(blob,filename){
  const url=URL.createObjectURL(blob),a=document.createElement('a');
  a.href=url;a.download=filename;document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1500);
}
function nc31NewCase(captureId){
  return {format:'NullCap Studio investigation',version:1,captureId,notes:'',bookmarks:{},aliases:{},advancedExpr:'',packetSearch:'',packetProto:'ALL'};
}
function nc31SafeCase(value,id){
  const out=nc31NewCase(id);
  if(!value||value.format!==out.format||value.version!==1||value.captureId!==id)return out;
  out.notes=typeof value.notes==='string'?value.notes.slice(0,8000):'';
  out.advancedExpr=typeof value.advancedExpr==='string'?value.advancedExpr.slice(0,600):'';
  out.packetSearch=typeof value.packetSearch==='string'?value.packetSearch.slice(0,200):'';
  out.packetProto=typeof value.packetProto==='string'?value.packetProto.slice(0,20):'ALL';
  if(value.aliases&&typeof value.aliases==='object'&&!Array.isArray(value.aliases)){
    for(const [ip,label] of Object.entries(value.aliases).slice(0,10000)){
      if(ip.length<=160&&typeof label==='string'&&label.trim()&&label.length<=64)out.aliases[ip]=label.trim();
    }
  }
  if(value.bookmarks&&typeof value.bookmarks==='object'&&!Array.isArray(value.bookmarks)){
    for(const [key,entry] of Object.entries(value.bookmarks).slice(0,NC31_CASE_MAX_BOOKMARKS)){
      const idNumber=Number(key),packet=state.packets[idNumber-1];
      if(!Number.isSafeInteger(idNumber)||!packet||idNumber<1||!entry||typeof entry!=='object')continue;
      if(entry.src!==packet.src||entry.dst!==packet.dst||entry.length!==packet.length)continue;
      out.bookmarks[idNumber]={id:idNumber,src:packet.src,dst:packet.dst,length:packet.length,protocol:packet.protocol,note:typeof entry.note==='string'?entry.note.slice(0,1200):''};
    }
  }
  return out;
}
function nc31ReadCase(captureId){
  try{return JSON.parse(localStorage.getItem(NC31_CASE_PREFIX+captureId)||'null');}
  catch(_){return null;}
}
function nc31SaveCase(){
  if(!state.investigation)return false;
  state.investigation.aliases=Object.fromEntries(state.hostAliases||[]);
  try{localStorage.setItem(NC31_CASE_PREFIX+state.captureId,JSON.stringify(state.investigation));return true;}
  catch(_){return false;}
}
// Switch from version 3 global host labels to capture-scoped labels.
nc3PersistAliases=function(){return nc31SaveCase();};
const nc31PreviousApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  const first=packets.find(Boolean),last=packets.at(-1),id=options.captureId||(options.isDemo?'demo-nullcap-studio-v31':`inmemory-${packets.length}-${first?.ts}-${first?.src}-${last?.ts}-${last?.dst}`);
  state.captureId=id;
  // Bookmarks are validated after the new packet sequence has been indexed.
  const stored=nc31ReadCase(id);
  state.hostAliases=new Map(Object.entries(stored?.aliases||{}).filter(([ip,label])=>ip.length<=160&&typeof label==='string'&&label.length<=64));
  state.investigation=nc31NewCase(id);
  state.advancedExpr='';nc31ActiveFilter=null;
  nc31PreviousApplyCapture(packets,options);
  state.investigation=nc31SafeCase(stored,id);
  state.hostAliases=new Map(Object.entries(state.investigation.aliases));
  nc3ApplyLabels();
  state.advancedExpr=state.investigation.advancedExpr;
  $('advancedExpression').value=state.advancedExpr;
  state.packetSearch=state.investigation.packetSearch;
  $('packetSearch').value=state.packetSearch;
  state.packetProto=state.investigation.packetProto;
  if(![...$('packetProto').options].some(x=>x.value===state.packetProto))state.packetProto='ALL';
  $('packetProto').value=state.packetProto;
  try{nc31ActiveFilter=state.advancedExpr?nc31CompileFilter(state.advancedExpr):null;}
  catch(_){nc31ActiveFilter=null;state.advancedExpr='';$('advancedExpression').value='';}
  nc31FilterFeedback();renderPacketTable();
  $('aliasModal').querySelector('.alias-info p').textContent='Le etichette valgono solo per questa cattura e vengono salvate nel browser, quando disponibile. Non modificano i pacchetti.';
  $('caseCaptureName').textContent=state.source;
  $('caseSignature').textContent=id.startsWith('sha256-files:')?'Identificatore della cattura: '+id.slice(13,37)+'...':'Identificatore: '+id;
  nc31RefreshCase();
};
window.NullCap.applyCapture=applyCapture;
const nc31OldPacketBrowser=getPacketBrowser;
getPacketBrowser=function(){const list=nc31OldPacketBrowser();return nc31ActiveFilter?list.filter(nc31ActiveFilter):list;};
function nc31FilterFeedback(error=''){
  const el=$('advancedFeedback');
  el.classList.toggle('is-error',Boolean(error));
  if(error){el.textContent=error;return;}
  el.textContent=state.advancedExpr?`Filtro attivo | ${formatN(getPacketBrowser().length)} pacchetti corrispondenti. AND / OR / NOT, len >= 500, time < 10, tag:marked.`:'Campi: src, dst, ip, port, srcport, dstport, proto, flags, len, time, info, tag, timestamp';
  $('toggleAdvanced').classList.toggle('is-active',Boolean(state.advancedExpr));
}
function nc31ApplyAdvanced(){
  const expression=$('advancedExpression').value.trim();
  try{
    const compiled=nc31CompileFilter(expression);
    nc31ActiveFilter=expression?compiled:null;state.advancedExpr=expression;
    state.investigation.advancedExpr=expression;state.packetPage=0;
    nc31SaveCase();renderPacketTable();nc31FilterFeedback();
  }catch(err){nc31FilterFeedback(String(err.message||err));}
}
function nc31CurrentBookmark(){return state.selectedPacket&&state.investigation?.bookmarks?.[state.selectedPacket.id];}
function nc31MarkPacket(p){
  if(!p||!state.investigation)return;
  const bookmarks=state.investigation.bookmarks;
  if(bookmarks[p.id])delete bookmarks[p.id];
  else{
    if(Object.keys(bookmarks).length>=NC31_CASE_MAX_BOOKMARKS){notify('Limite raggiunto','Massimo '+NC31_CASE_MAX_BOOKMARKS+' pacchetti segnati.',true);return;}
    bookmarks[p.id]={id:p.id,src:p.src,dst:p.dst,length:p.length,protocol:p.protocol,note:''};
  }
  nc31SaveCase();nc31RefreshCase();renderPacketInspector();
  if(state.advancedExpr.includes('tag:'))renderPacketTable();
}
function nc31RefreshCase(){
  const c=state.investigation;if(!c)return;
  const entries=Object.values(c.bookmarks).sort((a,b)=>a.id-b.id);
  $('caseBookmarkCount').textContent=String(entries.length);
  const current=state.selectedPacket;
  $('caseMarkSelected').disabled=!current;
  $('caseMarkSelected').innerHTML=ncIcon('bookmark')+' '+(current&&c.bookmarks[current.id]?'Rimuovi segno dal frame #'+current.id:current?'Segna frame #'+current.id:'Seleziona prima un pacchetto');
  $('caseNotes').value=c.notes;
  const list=$('caseBookmarks');
  list.innerHTML=entries.length?entries.map(entry=>`<div class="nc31-case-bookmark" data-mark-id="${entry.id}"><div class="nc31-bookmark-title"><span><b>#${entry.id}</b> ${escapeHtml(entry.protocol)} | ${escapeHtml(shortAddr(entry.src))} - ${escapeHtml(shortAddr(entry.dst))}</span><div class="nc31-bookmark-controls"><button type="button" class="soft-button" data-case-open="${entry.id}">${ncIcon("eye")} Apri</button><button type="button" class="soft-button" data-case-remove="${entry.id}">${ncIcon("close")} Rimuovi</button></div></div><textarea data-case-note="${entry.id}" maxlength="1200" placeholder="Nota su questo frame..."></textarea></div>`).join(''):'<div class="nc31-empty-bookmarks">Nessun frame segnato. Usa il pulsante Segna nel Packet inspector.</div>';
  for(const entry of entries){const area=list.querySelector(`[data-case-note="${entry.id}"]`);area.value=entry.note;}
  $('caseSaveStatus').textContent=nc31SaveCase()?'Salvataggio locale disponibile':'Memoria browser non disponibile; esporta il JSON per conservare le note';
}
function nc31ShowCase(){state.caseModalOpen=true;nc31RefreshCase();$('caseModal').classList.remove('hidden');$('caseNotes').focus();}
function nc31HideCase(){state.caseModalOpen=false;$('caseModal').classList.add('hidden');nc31SaveCase();}
function nc31ExportCase(){
  if(!state.investigation)return;
  nc31SaveCase();
  const json=JSON.stringify({...state.investigation,captureName:state.source,exportedAt:new Date().toISOString()},null,2);
  nc31DownloadFile(new Blob([json],{type:'application/json;charset=utf-8'}),'nullcap-indagine-v31.json');
  notify('Indagine esportata','Note, filtri, etichette e pacchetti segnati, senza payload.');
}
async function nc31ImportCase(file){
  if(!file)return;
  if(file.size>2*1024*1024){notify('Indagine troppo grande','Massimo 2 MiB per il file JSON.',true);return;}
  try{
    const parsed=JSON.parse(await file.text());
    if(parsed?.format!=='NullCap Studio investigation'||parsed.version!==1)throw Error('Formato indagine incompatibile.');
    if(parsed.captureId!==state.captureId)throw Error('Cattura diversa: apri prima il PCAP/PCAPNG da cui proviene questa indagine.');
    state.investigation=nc31SafeCase(parsed,state.captureId);
    state.hostAliases=new Map(Object.entries(state.investigation.aliases));nc3ApplyLabels();
    state.advancedExpr=state.investigation.advancedExpr;
    $('advancedExpression').value=state.advancedExpr;
    nc31ActiveFilter=state.advancedExpr?nc31CompileFilter(state.advancedExpr):null;
    state.packetSearch=state.investigation.packetSearch;$('packetSearch').value=state.packetSearch;
    state.packetProto=state.investigation.packetProto;
    if(![...$('packetProto').options].some(x=>x.value===state.packetProto))state.packetProto='ALL';
    $('packetProto').value=state.packetProto;state.packetPage=0;
    nc31SaveCase();nc31FilterFeedback();nc31RefreshCase();renderPacketTable();updateSnapshot(true);drawGraph();
    notify('Indagine ripristinata','Filtri, note, segni e nomi host caricati.');
  }catch(err){notify('Importazione indagine non riuscita',String(err.message||err),true);}
}
const nc31OldInspector=renderPacketInspector;
renderPacketInspector=function(){
  nc31OldInspector();const p=state.selectedPacket;if(!p)return;
  const area=$('packetInspectorContent').querySelector('.inspector-buttons');if(!area)return;
  const bookmark=document.createElement('button');bookmark.id='nc31MarkPacket';bookmark.type='button';
  bookmark.classList.toggle('is-bookmarked',!!nc31CurrentBookmark());bookmark.innerHTML=ncIcon('bookmark')+(nc31CurrentBookmark()?' Segnato':' Segna');
  bookmark.title='Aggiungi o rimuovi un frame dal taccuino';bookmark.onclick=()=>nc31MarkPacket(p);area.append(bookmark);
  if(p.transport==='TCP'){
    const follow=document.createElement('button');follow.type='button';follow.id='nc31FollowTCP';follow.innerHTML=ncIcon('flows')+' Segui TCP';follow.title='Ricostruisci lo stream bidirezionale';follow.onclick=()=>nc31OpenStream(p);area.append(follow);
  }
};
const nc31OldFlowInspector=renderFlowInspector;
renderFlowInspector=function(){
  nc31OldFlowInspector();const f=state.flowMap.get(state.selectedFlow);
  if(!f||f.transport!=='TCP')return;
  const target=$('flowInspectorContent').querySelector('.inspector-buttons');if(!target)return;
  const btn=document.createElement('button');btn.id='nc31FlowFollowTCP';btn.type='button';btn.textContent='Segui TCP';btn.onclick=()=>nc31OpenStream(f.packets[0]);target.append(btn);
};
const nc31OldWireUI=wireUI;
wireUI=function(){
  nc31OldWireUI();
  $('openCase').onclick=nc31ShowCase;
  $('caseClose').onclick=nc31HideCase;$('caseBackdrop').onclick=nc31HideCase;
  $('caseNotes').oninput=e=>{state.investigation.notes=e.target.value.slice(0,8000);nc31SaveCase();};
  $('caseMarkSelected').onclick=()=>nc31MarkPacket(state.selectedPacket);
  $('caseBookmarks').addEventListener('input',e=>{
    const id=Number(e.target.dataset.caseNote);if(id&&state.investigation.bookmarks[id]){
      state.investigation.bookmarks[id].note=e.target.value.slice(0,1200);nc31SaveCase();
    }
  });
  $('caseBookmarks').addEventListener('click',e=>{
    const open=e.target.closest('[data-case-open]'),remove=e.target.closest('[data-case-remove]');
    if(open){nc31HideCase();openPacketById(Number(open.dataset.caseOpen));}
    if(remove){const p=state.packets[Number(remove.dataset.caseRemove)-1];nc31MarkPacket(p);}
  });
  $('caseExportButton').onclick=nc31ExportCase;
  $('caseImportButton').onclick=()=>$('caseImportInput').click();
  $('caseImportInput').onchange=async e=>{await nc31ImportCase(e.target.files?.[0]);e.target.value='';};
  $('toggleAdvanced').onclick=()=>{
    const el=$('advancedFilters'),show=el.classList.contains('hidden');
    el.classList.toggle('hidden',!show);$('toggleAdvanced').setAttribute('aria-expanded',String(show));
    if(show)$('advancedExpression').focus();
  };
  $('applyAdvanced').onclick=nc31ApplyAdvanced;
  $('clearAdvanced').onclick=()=>{$('advancedExpression').value='';nc31ApplyAdvanced();};
  $('advancedExpression').onkeydown=e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();nc31ApplyAdvanced();}};
  $('packetSearch').addEventListener('input',()=>{if(state.investigation){state.investigation.packetSearch=state.packetSearch;nc31SaveCase();}});
  $('packetProto').addEventListener('change',()=>{if(state.investigation){state.investigation.packetProto=state.packetProto;nc31SaveCase();}});
  $('streamClose').onclick=nc31CloseStream;$('streamBackdrop').onclick=nc31CloseStream;
  $('streamMode').onchange=()=>{nc31StreamRenderBudget=NC31_STREAM_RENDER_INITIAL;nc31RenderStream();};
  $('streamDirection').onchange=()=>{nc31StreamRenderBudget=NC31_STREAM_RENDER_INITIAL;nc31RenderStream();};
  $('streamShowMore').onclick=()=>{nc31StreamRenderBudget+=NC31_STREAM_RENDER_STEP;nc31RenderStream();};
  $('streamExportA').onclick=()=>nc31DownloadStream('a');$('streamExportB').onclick=()=>nc31DownloadStream('b');
  window.addEventListener('keydown',e=>{
    if(e.key!=='Escape')return;
    if(!$('streamModal').classList.contains('hidden')){if(window.nca10InterceptStreamEscape?.(e))return;e.preventDefault();e.stopImmediatePropagation();nc31CloseStream();}
    else if(!$('caseModal').classList.contains('hidden')){e.preventDefault();e.stopImmediatePropagation();nc31HideCase();}
  },true);
};
Object.assign(window.NullCap,{
  compileAdvancedFilter:nc31CompileFilter,
  buildTCPStream:nc31BuildStream,
  openTCPStream:nc31OpenStream,
  openInvestigation:nc31ShowCase,
  getInvestigation:()=>state.investigation,
  getCaptureId:()=>state.captureId,
  importInvestigation:nc31ImportCase
});
