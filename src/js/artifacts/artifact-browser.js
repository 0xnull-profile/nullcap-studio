'use strict';
/* A16 · Bottino. Shared components; no external resources or active networking.
 * Quality of the TCP source is separate from the completeness of an HTTP/email object.
 */
const nc16UI={menu:null,searchOpen:false,inspectorOpen:true,sort:'rel',direction:'asc',quality:'all',infoOpen:false,infoOrigin:null};
const nc16Node=id=>document.getElementById(id);
const nc16SVG=name=>`<svg aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`;
const nc16Kinds=[['ALL','Tutte'],['image','Immagini'],['file','File'],['email','Email'],['api','API / JSON / XML'],['audio','Audio'],['auth','Credenziali / token'],['http','HTTP']];
const nc16Sorts=[['rel','Primo evento'],['title','Nome'],['bytes','Dimensione'],['kind','Tipo']];
const nc16Qualities=[['all','Tutti gli stati'],['complete','Senza limiti rilevati'],['partial','Parziali / lacune'],['ambiguous','Ambigui']];
function nc16IsHTTP(a){return !!(a.httpResponseStatus||/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s|^HTTP\/1\.[01]\s/i.test(String(a.metadata||''))||a.authFinding);}
function nc16KindMatch(a,kind){return kind==='ALL'||(kind==='auth'?Boolean(a.authFinding):kind==='http'?nc16IsHTTP(a):a.kind===kind);}
function nc16Quality(a){if(a.reassemblyQuality==='ambiguous')return 'ambiguous';if(a.status==='partial'||a.reassemblyQuality==='partial')return 'partial';return 'complete';}
function nc16FilterSort(assets){
 const kind=state.lootKind||'ALL',arr=assets.filter(a=>nc16KindMatch(a,kind));
 const result=arr.filter(a=>nc16UI.quality==='all'||nc16Quality(a)===nc16UI.quality);
 const mult=nc16UI.direction==='desc'?-1:1;
 result.sort((a,b)=>{
  let diff=0;
  if(nc16UI.sort==='title')diff=String(a.title||'').localeCompare(String(b.title||''),'it');
  else if(nc16UI.sort==='kind')diff=String(a.kind||'').localeCompare(String(b.kind||''),'it');
  else if(nc16UI.sort==='bytes')diff=(a.data?.length||0)-(b.data?.length||0);
  else diff=(Number(a.rel)||0)-(Number(b.rel)||0);
  return mult*diff||a.id-b.id;
 });
 return result;
}
function nc16RefreshToolbar(){
 const kind=nc16Kinds.find(([id])=>id===state.lootKind)?.[1]||'Tutte';
 nc16Node('nc16KindValue').textContent=kind;
 nc16Node('nc16SortValue').textContent=nc16Sorts.find(([id])=>id===nc16UI.sort)?.[1]||'Primo evento';
 const active=Number(nc16UI.quality!=='all')+Number(Boolean(state.lootShowSecondary));
 const count=nc16Node('nc16FilterCount');count.textContent=String(active);count.hidden=active===0;
 nc16SyncSearch();
 const status=nc16Node('lootScanStatus');if(status){status.classList.toggle('is-partial',state.lootStatus==='limited'||state.lootStatus==='error');}
}
function nc16SyncSearch(){
 const input=nc16Node('lootSearch'),has=!!input.value.trim(),wrap=nc16Node('nc16SearchWrap');
 wrap.classList.toggle('has-query',has);wrap.classList.toggle('is-open',nc16UI.searchOpen);
 nc16Node('nc16SearchToggle').setAttribute('aria-expanded',String(nc16UI.searchOpen));
 input.tabIndex=nc16UI.searchOpen?0:-1;
 nc16Node('nc16SearchClear').hidden=!has||!nc16UI.searchOpen;
}
function nc16SearchSet(open,focus=false){nc16UI.searchOpen=!!open;nc16SyncSearch();if(open&&focus)requestAnimationFrame(()=>nc16Node('lootSearch').focus());}
function nc16MenusClose(refocus=false){
 const prior=nc16UI.menu;nc16UI.menu=null;
 for(const kind of ['kind','sort','filter']){
  nc16Node('nc16'+kind[0].toUpperCase()+kind.slice(1)+'Menu').hidden=true;
  nc16Node('nc16'+kind[0].toUpperCase()+kind.slice(1)+'Toggle').setAttribute('aria-expanded','false');
 }
 if(refocus&&prior)nc16Node('nc16'+prior[0].toUpperCase()+prior.slice(1)+'Toggle')?.focus();
}
function nc16MenuLine(label,value,selected,attrs=''){
 return `<button type="button" class="nc16-menu-opt" role="menuitemradio" aria-checked="${selected}" ${attrs} data-nc16-value="${escapeHtml(String(value))}"><span>${escapeHtml(label)}</span>${selected?nc16SVG('check'):''}</button>`;
}
function nc16MenuBuild(kind){
 const menu=nc16Node('nc16'+kind[0].toUpperCase()+kind.slice(1)+'Menu');
 if(kind==='kind'){
  const base=(state.loot||[]).filter(a=>!a.secondary);
  menu.innerHTML='<div class="nc16-menu-title">CATEGORIA DI ARTEFATTO</div>'+nc16Kinds.map(([v,label])=>{
   const amount=base.filter(a=>nc16KindMatch(a,v)).length;
   return nc16MenuLine(label,v,state.lootKind===v).replace('</button>',`<small>${formatN(amount)}</small></button>`);
  }).join('');
 }else if(kind==='sort'){
  menu.innerHTML='<div class="nc16-menu-title">ORDINA PER</div>'+nc16Sorts.map(([v,label])=>nc16MenuLine(label,v,nc16UI.sort===v)).join('')+
   '<div class="nc16-menu-sep"></div><div class="nc16-menu-title">DIREZIONE</div><div class="nc16-menu-pair">'+
   ['asc','desc'].map((v)=>nc16MenuLine(v==='asc'?'Crescente':'Decrescente','dir:'+v,nc16UI.direction===v)).join('')+'</div>';
 }else{
  menu.innerHTML='<div class="nc16-menu-title">AFFIDABILITÀ / COMPLETEZZA</div>'+nc16Qualities.map(([v,label])=>nc16MenuLine(label,v,nc16UI.quality===v)).join('')+
   '<div class="nc16-menu-sep"></div><div class="nc16-menu-title">ALTRE OSSERVAZIONI</div>'+nc16MenuLine('Includi elementi secondari','secondary',Boolean(state.lootShowSecondary));
 }
 menu.querySelectorAll('[data-nc16-value]').forEach(opt=>{
  opt.onclick=()=>{
   const v=opt.dataset.nc16Value;
   if(kind==='kind'){state.lootKind=v;nc16MenusClose(true);}
   else if(kind==='sort'){if(v.startsWith('dir:'))nc16UI.direction=v.slice(4);else nc16UI.sort=v;nc16MenusClose(true);}
   else{if(v==='secondary')state.lootShowSecondary=!state.lootShowSecondary;else nc16UI.quality=v;nc16MenusClose(true);}
   nc16Node('lootShowSecondary').checked=!!state.lootShowSecondary;
   nc16Node('lootGallery').scrollTop=0;ncRenderLoot();
  };
  opt.onkeydown=e=>{
   const opts=[...menu.querySelectorAll('[role="menuitemradio"]')],i=opts.indexOf(opt);
   if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();opts[(i+(e.key==='ArrowDown'?1:-1)+opts.length)%opts.length]?.focus();}
   else if(e.key==='Home'||e.key==='End'){e.preventDefault();opts[e.key==='Home'?0:opts.length-1]?.focus();}
   else if(e.key==='Escape'){e.preventDefault();e.stopPropagation();nc16MenusClose(true);}
   else if(e.key==='Enter'||e.key===' '){e.preventDefault();opt.click();}
  };
 });
}
function nc16PositionFloating(node,anchor,width,desiredHeight=310){
 const rect=anchor.getBoundingClientRect(),w=Math.min(width,innerWidth-18),below=innerHeight-rect.bottom-12,above=rect.top-12,down=below>=Math.min(desiredHeight,170)||below>=above;
 node.style.width=w+'px';node.style.left=Math.max(9,Math.min(rect.left,innerWidth-w-9))+'px';
 node.style.maxHeight=Math.max(80,Math.min(desiredHeight,down?below:above))+'px';
 node.style.top=(down?rect.bottom+6:Math.max(9,rect.top-Math.min(desiredHeight,above)-6))+'px';
}
function nc16MenuToggle(kind,focus=false){
 if(nc16UI.menu===kind){nc16MenusClose();return;}
 nc16InfoClose();nc16MenusClose();nc16UI.menu=kind;nc16MenuBuild(kind);
 const menu=nc16Node('nc16'+kind[0].toUpperCase()+kind.slice(1)+'Menu');
 const button=nc16Node('nc16'+kind[0].toUpperCase()+kind.slice(1)+'Toggle');
 menu.hidden=false;button.setAttribute('aria-expanded','true');nc16PositionFloating(menu,button,kind==='kind'?245:255);
 if(focus)menu.querySelector('[aria-checked="true"]')?.focus();
}
function nc16InfoClose(){nc16UI.infoOpen=false;nc16UI.infoOrigin=null;nc16Node('nc16InfoPopover').hidden=true;nc16Node('nc16InformationToggle').setAttribute('aria-expanded','false');}
function nc16InfoToggle(mode='click'){
 nc16MenusClose();
 if(mode==='click'&&nc16UI.infoOpen&&nc16UI.infoOrigin==='hover'){nc16UI.infoOrigin='click';return;}
 nc16UI.infoOpen=!nc16UI.infoOpen;nc16UI.infoOrigin=nc16UI.infoOpen?mode:null;
 const p=nc16Node('nc16InfoPopover'),btn=nc16Node('nc16InformationToggle');
 p.hidden=!nc16UI.infoOpen;btn.setAttribute('aria-expanded',String(nc16UI.infoOpen));
 if(nc16UI.infoOpen)nc16PositionFloating(p,btn,305,220);
}
function nc16InspectorToggle(open){
 nc16UI.inspectorOpen=!!open;
 nc16Node('nc16ReopenInspector').hidden=!!open;
 nc16Node('nc16ReopenInspector').setAttribute('aria-expanded',String(open));
 document.querySelector('#view-loot .nc16-workspace').classList.toggle('is-inspector-closed',!open);
 nc16Node('nc16Inspector').setAttribute('aria-hidden',String(!open));
}
function nc16EnhanceDetail(){
 const host=nc16Node('lootDetail'),a=(state.loot||[]).find(x=>x.id===state.selectedLoot);
 if(!a)return;
 const actions=host.querySelector('.loot-action-row');
 for(const [id,label] of [['lootDownload','Esporta artefatto'],['lootInspectPacket','Apri primo frame di origine']]){
  const b=nc16Node(id);if(!b)continue;b.setAttribute('aria-label',label);b.dataset.tip=label;
  b.innerHTML=nc16SVG(id==='lootDownload'?'download':'open-packets');
 }
 const src=escapeHtml(a.src||'N/D'),dst=escapeHtml(a.dst||'N/D');
 const origin=document.createElement('div');origin.className='nc16-origin';
 origin.innerHTML=`<span class="nc16-origin-label">PROVENIENZA OSSERVATA</span><div class="nc16-origin-path"><span>${src}</span>${nc16SVG('arrow-right')}<span>${dst}</span></div><span class="nc16-origin-meta">${a.packetIds.length} frame associati · primo #${a.packetIds[0]} · ${Number.isFinite(a.rel)?formatTime(a.rel,true):'timestamp N/D'}</span>`;
 if(a.data?.length){
  const hash=document.createElement('div');hash.className='nc16-hash';hash.innerHTML='<span>SHA-256 dei byte estratti</span><code>Calcolo locale…</code>';origin.append(hash);
  if(!a.nc16HashPromise){
   const buf=a.data.buffer.slice(a.data.byteOffset,a.data.byteOffset+a.data.byteLength);
   a.nc16HashPromise=nc31HashBuffer(buf).then(sum=>(a.nc16Sha256=sum)).catch(()=>null);
  }
  a.nc16HashPromise.then(sum=>{if(sum&&hash.isConnected)hash.querySelector('code').textContent=sum;else if(!sum&&hash.isConnected)hash.querySelector('code').textContent='Non disponibile';});
 }
 const quality=nc16Quality(a),box=document.createElement('div');box.className='nc16-proof'+(quality==='partial'?' is-partial':quality==='ambiguous'?' is-ambiguous':'');
 const note=quality==='ambiguous'?'Sorgente TCP ambigua: byte sovrapposti in conflitto. Verifica i frame originali.':
  quality==='partial'?'La ricostruzione o l’artefatto presenta limiti; consultare provenienza e frame originali.':
  a.authFinding?'Osservazione di dati in chiaro. Nessuna verifica attiva delle credenziali.':
  'Nessuna lacuna rilevata nei byte usati per questo artefatto; ciò non certifica l’intera cattura.';
 box.innerHTML=nc16SVG(quality==='complete'?'check-circle':'alert')+`<span>${escapeHtml(note)}</span>`;
 const title=host.querySelector('h3');if(title){title.after(origin);if(actions)origin.after(actions);if(actions)actions.after(box);else origin.after(box);}
}
const nc16PriorLootDetail=ncRenderLootDetail;
ncRenderLootDetail=function(){nc16PriorLootDetail();nc16EnhanceDetail();};
const nc16PriorLootRender=ncRenderLoot;
ncRenderLoot=function(){const gallery=nc16Node('lootGallery'),scroll=gallery?.scrollTop||0;nc16PriorLootRender();if(gallery)gallery.scrollTop=scroll;nc16RefreshToolbar();};
function nc16Init(){
 const q=nc16Node('lootSearch');
 q.addEventListener('input',()=>{nc16Node('lootGallery').scrollTop=0;});
 nc16Node('nc16SearchToggle').addEventListener('click',()=>nc16SearchSet(!nc16UI.searchOpen,true));
 nc16Node('nc16SearchClear').addEventListener('click',()=>{q.value='';q.dispatchEvent(new Event('input',{bubbles:true}));q.focus();});
 for(const kind of ['kind','sort','filter'])nc16Node('nc16'+kind[0].toUpperCase()+kind.slice(1)+'Toggle').addEventListener('click',()=>nc16MenuToggle(kind));
 nc16Node('nc16CloseInspector').addEventListener('click',()=>nc16InspectorToggle(false));
 nc16Node('nc16ReopenInspector').addEventListener('click',()=>nc16InspectorToggle(true));
 nc16Node('nc16InformationToggle').addEventListener('click',()=>nc16InfoToggle('click'));
 nc16Node('nc16InformationToggle').addEventListener('pointerenter',()=>{if(!nc16UI.infoOpen)nc16InfoToggle('hover');});
 document.addEventListener('pointerdown',e=>{
  if(!nc16Node('view-loot').classList.contains('is-active'))return;
  if(!e.target.closest('#nc16SearchWrap'))nc16SearchSet(false);
  if(nc16UI.menu&&!e.target.closest('.nc16-menu, .nc16-control'))nc16MenusClose();
  if(nc16UI.infoOpen&&!e.target.closest('#nc16InfoPopover,#nc16InformationToggle'))nc16InfoClose();
 });
 document.addEventListener('keydown',e=>{
  if(e.key!=='Escape'||!nc16Node('view-loot').classList.contains('is-active'))return;
  if(nc16UI.menu){nc16MenusClose(true);e.preventDefault();e.stopImmediatePropagation();}
  else if(nc16UI.infoOpen){nc16InfoClose();e.preventDefault();e.stopImmediatePropagation();}
  else if(nc16UI.searchOpen){nc16SearchSet(false);nc16Node('nc16SearchToggle').focus();e.preventDefault();e.stopImmediatePropagation();}
 },true);
 nc16SearchSet(false);nc16RefreshToolbar();
}
const nc16PreviousWire=wireUI;
wireUI=function(){nc16PreviousWire();nc16Init();};

/* A12-powered reconstruction for artifact parsing. Session boundaries are respected.
 * Each contiguous run retains original frame provenance; no gap fillers, no decryption.
 * It is intentionally bounded: for large captures, the historical bounded parser remains
 * available and the scan is explicitly marked as limited.
 */
function nc16BuildTCPGroups(packets){
 if(typeof NullCapTCPReassembler==='undefined')return null;
 const parsed=NullCapTCPReassembler.collect(packets);
 state.lootIPIncomplete=parsed.partial.length+(parsed.stats?.invalidFragments||0);
 const source=parsed.tcp;
 if(source.length>75000||source.reduce((total,x)=>total+(x.bytes?.length||0),0)>NC_LOOT_TOTAL_LIMIT)return null;
 const tuple=new Map();
 for(const r of source){
  const key=JSON.stringify([[r.src,r.srcPort],[r.dst,r.dstPort]].sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))));
  if(!tuple.has(key))tuple.set(key,[]);tuple.get(key).push(r);
  if(tuple.size>2800)return null;
 }
 const directional=new Map();
 for(const records of tuple.values()){
  records.sort((a,b)=>a.packetId-b.packetId);
  for(const session of NullCapTCPReassembler.sessions(records)){
   const directions=new Map();
   for(const r of session.records){
    const key=JSON.stringify([r.src,r.srcPort,r.dst,r.dstPort]);
    if(!directions.has(key))directions.set(key,[]);directions.get(key).push(r);
   }
   for(const segmentList of directions.values()){
    if(!segmentList.some(x=>x.bytes?.length))continue;
    const first=segmentList[0],src=first.src,dst=first.dst,srcPort=first.srcPort,dstPort=first.dstPort;
    const side=NullCapTCPReassembler.assembleDirection(segmentList,NC_LOOT_STREAM_LIMIT);
    const quality=(side.conflicts.length||side.ipAmbiguous)?'ambiguous':(side.gaps.length||side.truncated||side.capturedTruncated)?'partial':'continuous';
    const warnings=[];
    if(side.conflicts.length)warnings.push('sovrapposizioni con byte discordanti');
    if(side.gaps.length)warnings.push(side.gaps.length+' lacune di sequenza');
    if(side.truncated||side.capturedTruncated)warnings.push('dati troncati o limite di memoria');
    if(side.ipAmbiguous)warnings.push('frammentazione IP ambigua');
    const byId=new Map(segmentList.map(r=>[r.packetId,r]));
    const runs=side.runs.map(part=>{
     const len=part.parts.reduce((n,b)=>n+b.length,0),bytes=ncByteChunks(part.parts,len);
     const segments=part.sources.map(x=>({start:x.start-part.start,end:x.end-part.start,packetId:x.frame,
       packetIds:x.frames,rel:byId.get(x.frame)?.rel??0}));
     return {bytes,segments,src,dst,srcPort,dstPort,rel:segments[0]?.rel??0,reassemblyQuality:quality,reassemblyWarnings:warnings};
    }).filter(run=>run.bytes.length>0);
    const key=JSON.stringify([src,srcPort,dst,dstPort]);
    if(!directional.has(key))directional.set(key,{src,dst,srcPort,dstPort,runs:[]});
    directional.get(key).runs.push(...runs);
   }
  }
 }
 return [...directional.values()];
}
window.NullCap.lootA16={get quality(){return nc16Quality;},get state(){return nc16UI;},buildTCPGroups:nc16BuildTCPGroups};
