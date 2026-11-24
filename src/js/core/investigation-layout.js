'use strict';
/* NullCap Studio 3.0 — compact investigation timeline, live graph coordinates,
   local host aliases, and consistent icon actions. Browser-only, no network. */

const NC_ALIAS_KEY='nullcap.host-labels.v1';
state.hostAliases=new Map();
state.aliasSelectedIP=null;
state.aliasQuery='';
state.aliasModalOpen=false;

function nc3LoadAliases(){
  try{
    const stored=JSON.parse(localStorage.getItem(NC_ALIAS_KEY)||'{}');
    if(stored&&typeof stored==='object'&&!Array.isArray(stored)){
      for(const [ip,name] of Object.entries(stored)){
        if(typeof name==='string'&&name.trim()&&name.length<=64&&ip.length<=160)state.hostAliases.set(ip,name.trim());
      }
    }
  }catch(_){ /* Private/opaque storage is optional. In-memory aliases still work. */ }
}
nc3LoadAliases();
function nc3PersistAliases(){
  try{localStorage.setItem(NC_ALIAS_KEY,JSON.stringify(Object.fromEntries(state.hostAliases)));return true;}
  catch(_){return false;}
}
function nc3CurrentLabel(h){return state.hostAliases.get(h.id)||h.baseLabel||h.label||shortAddr(h.id);}
function nc3ApplyLabels(){
  for(const h of state.hosts){
    h.baseLabel=h.baseLabel||h.label;
    h.customLabel=state.hostAliases.get(h.id)||'';
    h.label=nc3CurrentLabel(h);
  }
}
const nc3BaseIndexCapture=indexCapture;
indexCapture=function(){nc3BaseIndexCapture();nc3ApplyLabels();};

function nc3Svg(id){return `<svg aria-hidden="true"><use href="#${id}"/></svg>`;}
function nc3SetIcon(id,icon){const el=$(id);if(el)el.innerHTML=nc3Svg(icon);}

/* Single visual track. Color segments inside each pixel column show co-occurring
   protocols rather than allowing the last packet to overwrite every earlier one. */
buildTracks=function(){
  const stats=new Map();state.trackPackets=new Map();
  for(const p of state.packets){
    if(!Number.isFinite(p.rel))continue;
    stats.set(p.protocol,(stats.get(p.protocol)||0)+1);
    if(!state.trackPackets.has(p.protocol))state.trackPackets.set(p.protocol,[]);
    state.trackPackets.get(p.protocol).push(p);
  }
  state.tracks=[{name:'TUTTO IL TRAFFICO',protocol:'ALL',count:state.packets.length-state.undatedCount,color:'#72ede1'}];
  $('timelineCount').textContent='1 traccia · '+formatN(state.packets.length-state.undatedCount)+' eventi';
  $('trackLabels').innerHTML='<div class="track-label-ruler"><span>TRACCIA</span><span>EVENTI</span></div>'+`<div class="track-label-item is-total" style="--tc:#70e5d8"><i class="track-color"></i><span class="track-name"><strong>TUTTO IL TRAFFICO</strong><small>Pacchetti sovrapposti</small></span><span class="track-count">${formatN(state.packets.length-state.undatedCount)}</span></div>`;
  const entries=[...stats.entries()].sort((a,b)=>b[1]-a[1]);
  $('timelineLegend').innerHTML=`<span class="tl-legend-label">PROTOCOLLI</span><button type="button" data-legend-proto="ALL" class="tl-proto ${state.filter==='ALL'?'is-active':''}"><span class="tl-dot tl-all"></span>Tutti</button>`+entries.map(([proto,count])=>`<button type="button" class="tl-proto ${state.filter===proto?'is-active':''}" data-legend-proto="${escapeHtml(proto)}" title="${escapeHtml(proto)} · ${formatN(count)} pacchetti" style="--tl-color:${colorOf(proto)}"><span class="tl-dot"></span>${escapeHtml(proto)}<small>${formatN(count)}</small></button>`).join('');
  $('timelineLegend').querySelectorAll('[data-legend-proto]').forEach(el=>el.onclick=()=>{
    state.filter=state.filter===el.dataset.legendProto?'ALL':el.dataset.legendProto;
    renderProtocolFilters();nc3UpdateLegendSelection();updateSnapshot(true);drawGraph();drawTimeline();
  });
};
function nc3UpdateLegendSelection(){
  $('timelineLegend')?.querySelectorAll('[data-legend-proto]').forEach(el=>el.classList.toggle('is-active',el.dataset.legendProto===state.filter));
}
const nc3OldProtocolFilters=renderProtocolFilters;
renderProtocolFilters=function(){
  nc3OldProtocolFilters();nc3UpdateLegendSelection();
  $('filterChips')?.querySelectorAll('[data-proto]').forEach(b=>b.addEventListener('click',()=>requestAnimationFrame(drawGraph)));
};

resizeTimeline=function(){
  const vp=$('timelineViewport'),canvas=$('timelineCanvas');
  if(!vp||!vp.clientWidth)return;
  const w=Math.max(420,Math.floor(vp.clientWidth*state.timelineZoom)),h=63;
  const ratio=Math.min(2,window.devicePixelRatio||1);
  state.timelineSize={w,h};$('timelineWidth').style.width=w+'px';$('timelineWidth').style.height=h+'px';
  canvas.style.width=w+'px';canvas.style.height=h+'px';canvas.width=Math.floor(w*ratio);canvas.height=Math.floor(h*ratio);
  canvas.getContext('2d').setTransform(ratio,0,0,ratio,0,0);drawTimeline();
};
drawTimeline=function(){
  const canvas=$('timelineCanvas'),{w,h}=state.timelineSize;
  if(!canvas.width||!w)return;
  const ctx=canvas.getContext('2d');ctx.clearRect(0,0,w,h);
  ctx.fillStyle='#0b192b';ctx.fillRect(0,0,w,h);
  const y=27,trackH=h-y;
  ctx.fillStyle='rgba(41,66,88,.17)';ctx.fillRect(0,y,w,trackH);
  const duration=Math.max(.001,state.duration),ticks=Math.max(4,Math.floor(w/125));
  ctx.font='9px ui-monospace,Consolas,monospace';ctx.textBaseline='alphabetic';
  for(let i=0;i<=ticks;i++){
    const x=i/ticks*w,tt=i/ticks*duration;
    ctx.fillStyle='rgba(126,163,194,.12)';ctx.fillRect(Math.round(x),27,1,trackH);
    ctx.textAlign=i===0?'left':i===ticks?'right':'center';ctx.fillStyle='#879eb5';
    ctx.fillText(formatTime(tt,true),Math.max(8,Math.min(w-8,x)),17);
  }
  ctx.fillStyle='rgba(151,183,209,.12)';ctx.fillRect(0,h-1,w,1);
  const bins=new Array(Math.ceil(w));
  for(const p of state.packets){
    if(!Number.isFinite(p.rel))continue;
    const x=Math.max(0,Math.min(bins.length-1,Math.floor((p.rel/duration)*(w-1))));
    let bin=bins[x];if(!bin){bin={count:0,bytes:0,groups:new Map()};bins[x]=bin;}
    bin.count++;bin.bytes+=p.length;const weight=state.nc32TimelineMetric==='bytes'?p.length:1;bin.groups.set(p.protocol,(bin.groups.get(p.protocol)||0)+weight);
  }
  for(let x=0;x<bins.length;x++){
    const bin=bins[x];if(!bin)continue;
    const parts=[...bin.groups.entries()].sort((a,b)=>b[1]-a[1]);
    const metric=state.nc32TimelineMetric==='bytes'?bin.bytes:bin.count;const height=Math.min(30,Math.max(11,7+Math.sqrt(metric/(state.nc32TimelineMetric==='bytes'?128:1))*3.5));const groupTotal=[...bin.groups.values()].reduce((a,b)=>a+b,0);
    const top=y+(trackH-height)/2;
    let cursor=top;
    // Partition a column by protocol, preserving the contribution of each color.
    for(let j=0;j<parts.length;j++){
      const [proto,n]=parts[j];
      let partHeight=j===parts.length-1?top+height-cursor:height*n/Math.max(1,groupTotal);
      ctx.globalAlpha=(state.filter==='ALL'||state.filter===proto)? .92 : .18;
      ctx.fillStyle=colorOf(proto);
      ctx.fillRect(x,cursor,bin.count===1?2:1.8,Math.max(1,partHeight));
      cursor+=partHeight;
    }
  }
  ctx.globalAlpha=1;
  // Range selection is drawn on top of the original packet colors.
  const s=state.timelineSelection;
  if(s){
    const a=s.start/duration*w,b=s.end/duration*w,l=Math.min(a,b),r=Math.max(a,b);
    ctx.fillStyle='rgba(104,236,209,.14)';ctx.fillRect(l,0,Math.max(2,r-l),h);
    ctx.strokeStyle='#99fbe8';ctx.lineWidth=1.3;
    for(const x of [l,r]){ctx.beginPath();ctx.moveTo(x+.5,0);ctx.lineTo(x+.5,h);ctx.stroke();}
  }
};

/* Host identity directory: optional persistent user annotations, not capture bytes. */
function nc3ShowModal(ip){
  state.aliasModalOpen=true;state.aliasQuery='';$('aliasSearch').value='';
  $('aliasModal').classList.remove('hidden');
  const selected=ip&&state.hostMap.has(ip)?ip:state.selected.type==='node'&&state.hostMap.has(state.selected.id)?state.selected.id:state.hosts[0]?.id||null;
  nc3SelectHost(selected);nc3RenderDirectory();$('aliasSearch').focus();
}
function nc3HideModal(){state.aliasModalOpen=false;$('aliasModal').classList.add('hidden');$('aliasFeedback').textContent='';$('manageHosts').focus();}
function nc3SelectHost(id){
  state.aliasSelectedIP=id&&state.hostMap.has(id)?id:null;
  const host=state.aliasSelectedIP?state.hostMap.get(state.aliasSelectedIP):null;
  $('aliasForm').classList.toggle('hidden',!host);
  $('aliasSelectHint').classList.toggle('hidden',!!host);
  if(host){
    $('aliasIP').textContent=host.id;$('aliasKind').textContent=host.local?'HOST LOCALE':'ENDPOINT REMOTO';
    $('aliasInput').value=state.hostAliases.get(host.id)||'';
    $('aliasInput').placeholder=host.baseLabel||shortAddr(host.id);
    $('aliasRemove').disabled=!state.hostAliases.has(host.id);
    $('aliasFeedback').textContent='';
  }
  nc3RenderDirectory();
}
function nc3RenderDirectory(){
  const q=state.aliasQuery.trim().toLowerCase();
  const hosts=state.hosts.filter(h=>!q||h.id.toLowerCase().includes(q)||h.label.toLowerCase().includes(q));
  const shown=hosts.slice(0,100);
  $('aliasListCount').textContent=shown.length===hosts.length?`${hosts.length} host`:`${shown.length}/${hosts.length}`;
  $('aliasList').innerHTML=shown.map(h=>`<button class="alias-host ${state.aliasSelectedIP===h.id?'is-selected':''}" type="button" data-alias-ip="${escapeHtml(h.id)}"><span class="alias-host-icon ${h.local?'local':'remote'}">${nc3Svg('i-network')}</span><span class="alias-host-text"><strong>${escapeHtml(h.label)}</strong><small>${escapeHtml(h.id)}</small></span>${state.hostAliases.has(h.id)?'<span class="alias-custom-mark" title="Etichetta personalizzata">'+nc3Svg('i-pencil')+'</span>':''}</button>`).join('')||'<div class="alias-none">Nessun host trovato. Prova un altro indirizzo o nome.</div>';
  $('aliasListFoot').textContent=hosts.length>100?`Visualizzati 100 di ${hosts.length} host. Usa la ricerca per restringere l'elenco.`:`${hosts.length} host corrispondenti · ${state.hostAliases.size} etichette salvate`;
}
function nc3RefreshHostInfo(){
  nc3ApplyLabels();updateSnapshot(true);drawGraph();renderFocus();
  ncRunDashboard();
  if(state.page==='flows'){renderFlows();renderFlowInspector();}
  nc3RenderDirectory();
}
function nc3SaveAlias(){
  if(!state.aliasSelectedIP)return;
  const name=$('aliasInput').value.trim().replace(/\s+/g,' ');
  if(name.length>64){$('aliasFeedback').textContent='Massimo 64 caratteri.';return;}
  if(name)state.hostAliases.set(state.aliasSelectedIP,name);
  else state.hostAliases.delete(state.aliasSelectedIP);
  const persisted=nc3PersistAliases();nc3RefreshHostInfo();
  $('aliasFeedback').textContent=persisted?'Etichetta aggiornata e salvata nel browser.':'Etichetta aggiornata per questa sessione; salvataggio non disponibile.';
  $('aliasInput').value=name;
  $('aliasRemove').disabled=!name;
  notify('Etichetta host aggiornata',`${state.aliasSelectedIP} → ${name||'etichetta originale'}`);
}
function nc3ResetAlias(){if(!state.aliasSelectedIP)return;state.hostAliases.delete(state.aliasSelectedIP);nc3PersistAliases();nc3RefreshHostInfo();$('aliasInput').value='';$('aliasFeedback').textContent='Etichetta originale ripristinata.';}
function nc3ExportAliases(){
  const data={format:'NullCap host aliases',version:1,labels:Object.fromEntries(state.hostAliases)};
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='nullcap-host-aliases.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  notify('Etichette esportate',`${state.hostAliases.size} associazioni IP/nome in JSON.`);
}
async function nc3ImportAliases(file){
  if(!file)return;
  if(file.size>512*1024){notify('JSON troppo grande','Massimo 512 KB per le etichette.',true);return;}
  try{
    const src=JSON.parse(await file.text()),labels=src?.labels&&typeof src.labels==='object'?src.labels:src;
    if(!labels||typeof labels!=='object'||Array.isArray(labels))throw new Error('Formato non valido');
    let count=0;
    for(const [ip,label] of Object.entries(labels).slice(0,10000)){
      if(typeof label!=='string'||!label.trim()||label.trim().length>64||ip.length>160)continue;
      state.hostAliases.set(ip,label.trim());count++;
    }
    nc3PersistAliases();nc3RefreshHostInfo();nc3SelectHost(state.aliasSelectedIP);
    notify('Etichette importate',`${count} nomi aggiunti o aggiornati. Nessun pacchetto modificato.`);
  }catch(err){notify('Impossibile importare le etichette',String(err.message||err),true);}
}

const nc3PreviousFocus=renderFocus;
renderFocus=function(){
  nc3PreviousFocus();
  if(state.page!=='explorer'||state.selected.type!=='node'||state.quickPacket)return;
  const area=$('focusContent').querySelector('.focus-cta');
  if(!area)return;
  const edit=document.createElement('button');edit.className='focus-alias-button';edit.type='button';
  edit.innerHTML=nc3Svg('i-pencil')+' Rinomina host';
  edit.addEventListener('click',()=>nc3ShowModal(state.selected.id));area.append(edit);
};

const nc3PreviousCollapseInspector=collapseInspector;
collapseInspector=function(){nc3PreviousCollapseInspector();nc3SetIcon('toggleInspectorSize','i-expand');};
const nc3PreviousToggleInspectorSize=toggleInspectorSize;
toggleInspectorSize=function(){nc3PreviousToggleInspectorSize();nc3SetIcon('toggleInspectorSize',document.querySelector('.packet-inspector').classList.contains('is-expanded')?'i-shrink':'i-expand');};

const nc3PreviousWireUI=wireUI;
wireUI=function(){
  nc3PreviousWireUI();
  $('manageHosts').onclick=()=>nc3ShowModal();
  $('resetLayout').onclick=()=>{ncLayoutRadial();state.graphPan={x:0,y:0};state.graphZoom=1;updateSnapshot(true);drawGraph();notify('Layout ripristinato','Le etichette personalizzate non sono state modificate.');};
  $('aliasClose').onclick=nc3HideModal;$('aliasBackdrop').onclick=nc3HideModal;
  $('aliasSearch').oninput=e=>{state.aliasQuery=e.target.value;nc3RenderDirectory();};
  $('aliasList').addEventListener('click',e=>{const button=e.target.closest('[data-alias-ip]');if(button)nc3SelectHost(button.dataset.aliasIp);});
  $('aliasSave').onclick=nc3SaveAlias;$('aliasRemove').onclick=nc3ResetAlias;
  $('aliasInput').onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();nc3SaveAlias();}};
  $('aliasExportButton').onclick=nc3ExportAliases;
  $('aliasImportButton').onclick=()=>$('aliasImportInput').click();
  $('aliasImportInput').onchange=async e=>{await nc3ImportAliases(e.target.files[0]);e.target.value='';};
  document.addEventListener('keydown',e=>{
    if(state.aliasModalOpen){if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();nc3HideModal();}return;}
    if(e.key==='F2'&&state.page==='explorer'&&state.selected.type==='node'){
      e.preventDefault();e.stopImmediatePropagation();nc3ShowModal(state.selected.id);$('aliasInput').focus();
    }
  },true);
  // A standard graph context menu opens the editor for the exact clicked node.
  $('graphCanvas').addEventListener('contextmenu',e=>{
    const rect=$('graphCanvas').getBoundingClientRect(),hit=graphHitAt(e.clientX-rect.left,e.clientY-rect.top);
    if(hit?.type==='node'){e.preventDefault();e.stopPropagation();nc3ShowModal(hit.id);$('aliasInput').focus();}
  });
  $('collapseTimeline').onclick=()=>{
    const box=$('timelinePanel'),collapsed=box.classList.toggle('is-collapsed');
    $('collapseTimeline').innerHTML=nc3Svg('i-chevrondown');
    $('collapseTimeline').classList.toggle('is-rotated',collapsed);
    $('collapseTimeline').setAttribute('aria-label',collapsed?'Espandi timeline':'Comprimi timeline');
    setTimeout(()=>{resizeTimeline();resizeGraph();},100);
  };
};
Object.assign(window.NullCap,{getAliases:()=>Object.fromEntries(state.hostAliases),openHostAliases:nc3ShowModal,renameHost:(ip,name)=>{
  if(!state.hostMap.has(ip))return false;
  if(name?.trim())state.hostAliases.set(ip,String(name).trim().slice(0,64));else state.hostAliases.delete(ip);
  nc3PersistAliases();nc3ApplyLabels();updateSnapshot(true);drawGraph();return true;
}});
