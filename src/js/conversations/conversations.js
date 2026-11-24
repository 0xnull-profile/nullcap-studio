'use strict';
/* A13 · Conversazioni — single NullCap UI system, original packet data authoritative. */
const nc13UI={protocol:'ALL',sort:'bytes',direction:'desc',menu:null,searchOpen:false,inspectorOpen:true,captureRef:null,visible:[]};
const nc13E=id=>document.getElementById(id);
const nc13Symbol=name=>`<svg aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`;
const nc13SortFields=[['bytes','Volume'],['count','Pacchetti'],['duration','Durata'],['last','Ultima attività']];
function nc13Field(f,key){if(key==='duration')return Number.isFinite(f.first)&&Number.isFinite(f.last)?Math.max(0,f.last-f.first):-1;return Number(f[key])||0;}
function nc13SetSearch(open,focus=false){
 nc13UI.searchOpen=!!open;
 nc13E('nc13SearchWrap').classList.toggle('is-open',nc13UI.searchOpen);
 nc13E('nc13SearchToggle').setAttribute('aria-expanded',String(nc13UI.searchOpen));
 nc13E('flowSearch').tabIndex=nc13UI.searchOpen?0:-1;
 nc13E('nc13SearchClear').tabIndex=nc13UI.searchOpen&&!!nc13E('flowSearch').value.trim()?0:-1;
 if(nc13UI.searchOpen&&focus)requestAnimationFrame(()=>nc13E('flowSearch').focus());
}
function nc13SyncSearch(){const input=nc13E('flowSearch'),has=!!input.value.trim();nc13E('nc13SearchWrap').classList.toggle('has-query',has);nc13E('nc13SearchClear').hidden=!has;nc13E('nc13SearchClear').tabIndex=has&&nc13UI.searchOpen?0:-1;}
function nc13MenusClose(refocus=false){
 const prev=nc13UI.menu;nc13UI.menu=null;
 for(const kind of ['proto','sort']){
  nc13E(kind==='proto'?'nc13ProtoMenu':'nc13SortMenu').hidden=true;
  nc13E(kind==='proto'?'nc13ProtoToggle':'nc13SortToggle').setAttribute('aria-expanded','false');
 }
 if(refocus&&prev)nc13E(prev==='proto'?'nc13ProtoToggle':'nc13SortToggle').focus();
}
function nc13RefreshToolbar(){
 nc13E('nc13ProtoValue').textContent=nc13UI.protocol==='ALL'?'Tutti':nc13UI.protocol;
 const label=nc13SortFields.find(([x])=>x===nc13UI.sort)?.[1]||'Volume';
 nc13E('nc13SortValue').textContent=label;
 nc13E('nc13SortToggle').setAttribute('aria-label','Ordina conversazioni per '+label+' in ordine '+(nc13UI.direction==='asc'?'crescente':'decrescente'));
 nc13E('nc13SortToggle').classList.toggle('nc14-desc',nc13UI.direction==='desc');
}
function nc13BuildMenu(kind){
 const menu=nc13E(kind==='proto'?'nc13ProtoMenu':'nc13SortMenu');
 if(kind==='sort'){
  menu.innerHTML='<div class="ncps-menu-kicker">ORDINA PER</div><div class="nc14-sort-options" role="radiogroup" aria-label="Criterio di ordinamento">'+
   nc13SortFields.map(([value,label])=>'<button type="button" class="ncps-a09-option" role="radio" aria-checked="'+String(value===nc13UI.sort)+'" data-nc14-sort="'+value+'"><span>'+label+'</span>'+nc13Symbol('check')+'</button>').join('')+
   '</div><div class="ncps-a09-separator"></div><div class="ncps-menu-kicker">DIREZIONE</div><div class="ncps-a09-directions" role="radiogroup" aria-label="Direzione ordinamento">'+
   [['asc','Crescente'],['desc','Decrescente']].map(([value,label])=>'<button type="button" class="ncps-a09-direction" role="radio" aria-checked="'+String(value===nc13UI.direction)+'" data-nc14-dir="'+value+'">'+label+'</button>').join('')+'</div>';
  const activate=btn=>{
   if(btn.dataset.nc14Sort)nc13UI.sort=btn.dataset.nc14Sort;
   else if(btn.dataset.nc14Dir)nc13UI.direction=btn.dataset.nc14Dir;
   else return;
   menu.querySelectorAll('[data-nc14-sort]').forEach(b=>b.setAttribute('aria-checked',String(b.dataset.nc14Sort===nc13UI.sort)));
   menu.querySelectorAll('[data-nc14-dir]').forEach(b=>b.setAttribute('aria-checked',String(b.dataset.nc14Dir===nc13UI.direction)));
   nc13RefreshToolbar();nc13E('flowsList').scrollTop=0;renderFlows();renderFlowInspector();
  };
  menu.querySelectorAll('[data-nc14-sort],[data-nc14-dir]').forEach(opt=>opt.addEventListener('click',()=>activate(opt)));
 }else{
  const counts=new Map();for(const f of state.flows){for(const p of new Set([f.protocol,f.transport]))counts.set(p,(counts.get(p)||0)+1);}
  const entries=[['ALL','Tutti i protocolli',state.flows.length],...[...counts].sort((a,b)=>String(a[0]).localeCompare(String(b[0]))).map(([name,count])=>[name,name,count])];
  menu.innerHTML='<div class="nc13-menu-title">FILTRA PER PROTOCOLLO</div>'+entries.map(([value,label,count])=>{
   const color=value!=='ALL'?colorOf(value):'#a4ccd9';
   return `<button type="button" role="option" tabindex="-1" aria-selected="${value===nc13UI.protocol}" class="nc13-menu-option" data-nc13-value="${escapeHtml(value)}" style="--pc:${color}"><span class="nc13-option-dot" aria-hidden="true"></span><span>${escapeHtml(label)}</span><small>${formatN(count)}</small>${nc13Symbol('check')}</button>`;
  }).join('');
  menu.querySelectorAll('[data-nc13-value]').forEach(opt=>opt.addEventListener('click',()=>{
   nc13UI.protocol=opt.dataset.nc13Value;nc13RefreshToolbar();nc13MenusClose(true);nc13E('flowsList').scrollTop=0;renderFlows();renderFlowInspector();
  }));
 }
 menu.querySelectorAll('button').forEach(opt=>opt.addEventListener('keydown',e=>{
  const options=[...menu.querySelectorAll('button')],pos=options.indexOf(opt);
  if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();options[(pos+(e.key==='ArrowDown'?1:-1)+options.length)%options.length]?.focus();}
  else if(e.key==='Home'||e.key==='End'){e.preventDefault();options[e.key==='Home'?0:options.length-1]?.focus();}
  else if(e.key==='Escape'){e.preventDefault();e.stopPropagation();nc13MenusClose(true);}
  else if(e.key===' '||e.key==='Enter'){e.preventDefault();opt.click();}
 }));
}
function nc13PositionMenu(kind){
 const menu=nc13E(kind==='proto'?'nc13ProtoMenu':'nc13SortMenu'),button=nc13E(kind==='proto'?'nc13ProtoToggle':'nc13SortToggle');
 const rect=button.getBoundingClientRect(),width=Math.min(kind==='proto'?254:256,window.innerWidth-18);
 menu.style.width=width+'px';menu.style.left=Math.max(9,Math.min(rect.left,window.innerWidth-width-9))+'px';
 const bottom=window.innerHeight-rect.bottom-10,top=rect.top-10,preferDown=bottom>=240||bottom>=top;
 const maxHeight=Math.min(kind==='sort'?340:310,Math.max(60,preferDown?bottom:top));menu.style.maxHeight=maxHeight+'px';
 menu.style.top=(preferDown?rect.bottom+6:Math.max(9,rect.top-maxHeight-6))+'px';
}
function nc13MenuToggle(kind,focus=false){
 if(nc13UI.menu===kind){nc13MenusClose();return;}
 nc13MenusClose();nc13UI.menu=kind;nc13BuildMenu(kind);
 nc13E(kind==='proto'?'nc13ProtoMenu':'nc13SortMenu').hidden=false;
 nc13E(kind==='proto'?'nc13ProtoToggle':'nc13SortToggle').setAttribute('aria-expanded','true');
 nc13PositionMenu(kind);
 if(focus)(nc13E(kind==='proto'?'nc13ProtoMenu':'nc13SortMenu').querySelector('[aria-selected="true"],[aria-checked="true"]'))?.focus();
}
function nc13RefreshCapture(){
 if(nc13UI.captureRef===state.packets)return;
 nc13UI.captureRef=state.packets;nc13UI.protocol='ALL';nc13UI.sort='bytes';nc13UI.direction='desc';
 nc13MenusClose();nc13RefreshToolbar();
}
function nc13Label(ip){return state.hostMap?.get(ip)?.label||ip;}
function nc13ContainsQuery(f,q){return [f.a,f.b,f.src,f.dst,f.protocol,f.transport,f.id,nc13Label(f.src),nc13Label(f.dst)].some(x=>String(x??'').toLocaleLowerCase().includes(q));}
function nc13FlowRows(){
 const q=nc13E('flowSearch').value.toLocaleLowerCase().trim();
 const all=state.flows.filter(f=>(nc13UI.protocol==='ALL'||f.protocol===nc13UI.protocol||f.transport===nc13UI.protocol)&&(!q||nc13ContainsQuery(f,q)));
 const multiplier=nc13UI.direction==='asc'?1:-1;
 all.sort((a,b)=>multiplier*(nc13Field(a,nc13UI.sort)-nc13Field(b,nc13UI.sort))||a.id.localeCompare(b.id));
 return all;
}
renderFlows=function(){
 const host=nc13E('flowsList');if(!host)return;
 nc13RefreshCapture();nc13RefreshToolbar();nc13SyncSearch();
 const before=host.scrollTop,records=nc13FlowRows();nc13UI.visible=records;
 const visibleIds=new Set(records.map(f=>f.id));
 if(!visibleIds.has(state.selectedFlow))state.selectedFlow=records[0]?.id||null;
 nc13E('flowCount').textContent=formatN(records.length)+' / '+formatN(state.flows.length)+' flussi';
 nc13E('nc13FooterCount').textContent=formatN(records.length)+' / '+formatN(state.flows.length)+' conversazioni · ';
 const result=records.slice(0,350);
 host.innerHTML=result.length?result.map(f=>{
  const max=Math.max(1,f.forward,f.reverse),ab=Math.min(100,f.forward/max*100),ba=Math.min(100,f.reverse/max*100);
  const from=f.a,to=f.b;
  const duration=f.packets.some(p=>Number.isFinite(p.rel))?tinyTime(Math.max(0,f.last-f.first)):'N/D';
  return `<button type="button" class="nc13-flow-row${state.selectedFlow===f.id?' is-selected':''}" data-flow="${escapeHtml(f.id)}" aria-pressed="${state.selectedFlow===f.id}" title="${escapeHtml(from+' → '+to+' · '+f.protocol)}">
   <span class="nc13-flow-endpoints"><span class="nc13-flow-route"><strong>${escapeHtml(from)}</strong><span class="nc13-route-arrow">${nc13Symbol('arrow-left-right')}</span><strong>${escapeHtml(to)}</strong></span><span class="nc13-flow-services"><i class="nc13-proto-dot" style="--pc:${colorOf(f.protocol)}" aria-hidden="true"></i><span>${escapeHtml(f.protocol)}</span><span class="nc13-mini-sep">·</span><span>${escapeHtml(f.transport)}</span></span></span>
   <span class="nc13-flow-traffic"><span class="nc13-traffic-line"><em>A → B</em><span class="nc13-meter"><i style="width:${ab}%"></i></span><b>${formatBytes(f.forward)}</b></span><span class="nc13-traffic-line is-reverse"><em>B → A</em><span class="nc13-meter"><i style="width:${ba}%"></i></span><b>${formatBytes(f.reverse)}</b></span></span>
   <span class="nc13-flow-summary"><strong>${formatBytes(f.bytes)}</strong><span>${formatN(f.count)} pacch. · ${duration}</span></span></button>`;
 }).join(''):'<div class="nc13-empty">Nessuna conversazione corrisponde ai filtri impostati.<button type="button" id="nc13ResetFilters">Mostra tutte</button></div>';
 if(records.length>350){host.insertAdjacentHTML('beforeend',`<div class="nc13-overflow">Visualizzate 350 conversazioni su ${formatN(records.length)}. Usa ricerca e filtri per restringere l’elenco.</div>`);}
 host.querySelectorAll('[data-flow]').forEach(b=>b.addEventListener('click',()=>{state.selectedFlow=b.dataset.flow;renderFlows();renderFlowInspector();}));
 nc13E('nc13ResetFilters')?.addEventListener('click',()=>{nc13UI.protocol='ALL';nc13E('flowSearch').value='';renderFlows();renderFlowInspector();});
 host.scrollTop=before;
};
renderFlowInspector=function(){
 const el=nc13E('flowInspectorContent'),f=state.flowMap.get(state.selectedFlow);
 if(!f||!nc13UI.visible.some(x=>x.id===f.id)){
  el.innerHTML='<div class="inspector-empty"><svg aria-hidden="true" focusable="false"><use href="#i-flows"/></svg><strong>Seleziona una conversazione</strong><span>Cerca un flusso e selezionalo per esaminare volumi, porte e pacchetti originali.</span></div>';return;
 }
 const knownTime=f.packets.some(p=>Number.isFinite(p.rel)),total=Math.max(1,f.forward+f.reverse),max=Math.max(f.forward,f.reverse,1);
 const oneWay=f.count>6&&Math.min(f.forward,f.reverse)<total*.07;
 const unusual=f.portA>1024&&f.portB>1024&&f.count>3;
 const hints=[...(oneWay?['Traffico fortemente asimmetrico']:[]),...(unusual?['Entrambe le porte oltre 1024']:[])];
 const tcp=f.transport==='TCP';
 el.innerHTML=`<div class="nc13-detail-card"><span class="nc13-detail-eyebrow">CONVERSAZIONE OSSERVATA <span class="nc13-detail-badge" style="--pc:${colorOf(f.protocol)}">${escapeHtml(f.protocol)}</span>${hints.length?`<button type="button" id="nc14WarningToggle" class="nc14-warning-trigger" aria-label="${hints.length} avvisi statistici: mostra i dettagli" aria-expanded="false" aria-controls="nc14WarningPopover">${nc13Symbol('alert')}<span class="nc14-warning-count">${hints.length}</span></button>`:''}</span><div class="nc13-detail-point"><small>ENDPOINT A</small><strong>${escapeHtml(f.a)}</strong></div><div class="nc13-detail-point"><small>ENDPOINT B</small><strong>${escapeHtml(f.b)}</strong></div><div class="nc13-detail-time">${nc13Symbol('clock')} ${knownTime?'T+'+formatTime(f.first,true)+' – T+'+formatTime(f.last,true):'Timestamp non disponibile'}</div></div>
 <div class="nc14-sticky-actions" role="group" aria-label="Azioni rapide della conversazione">
  <button type="button" id="flowToPackets" class="nc14-quick-action" data-tip="Apri pacchetti" aria-label="Apri pacchetti della conversazione">${nc13Symbol('open-packets')}</button>
  <button type="button" id="flowToGraph" class="nc14-quick-action" data-tip="Mostra nel grafo" aria-label="Mostra conversazione nella topologia" ${knownTime?'':'disabled'}>${nc13Symbol('network')}</button>
  <button type="button" id="nc13FollowTCP" class="nc14-quick-action" data-tip="Segui TCP" aria-label="Ricostruisci stream TCP" ${tcp?'':'disabled'}>${nc13Symbol('arrow-left-right')}</button>
 </div>
 <div class="nc13-stats"><div><small>PACCHETTI</small><strong>${formatN(f.count)}</strong></div><div><small>VOLUME SU WIRE</small><strong>${formatBytes(f.bytes)}</strong></div><div><small>DURATA OSSERVATA</small><strong>${knownTime?tinyTime(Math.max(0,f.last-f.first)):'N/D'}</strong></div><div><small>TRASPORTO</small><strong>${escapeHtml(f.transport)}</strong></div></div>
 <div class="nc13-direction-card"><div class="nc13-section-heading">TRAFFICO BIDIREZIONALE</div><div class="nc13-inspector-bar"><span>A → B</span><div class="nc13-meter"><i style="width:${100*f.forward/max}%"></i></div><strong>${formatBytes(f.forward)}</strong></div><div class="nc13-inspector-bar reverse"><span>B → A</span><div class="nc13-meter"><i style="width:${100*f.reverse/max}%"></i></div><strong>${formatBytes(f.reverse)}</strong></div><p>Rapporto calcolato sui byte dei frame osservati, non sul solo payload TCP.</p></div>
 <div class="nc13-section-heading nc13-packets-heading">PACCHETTI OSSERVATI <small>${formatN(f.count)}</small></div><div class="nc13-packet-list">${f.packets.slice(0,12).map(p=>`<button type="button" class="nc13-packet" data-packet="${p.id}"><i class="nc13-proto-dot" style="--pc:${colorOf(p.protocol)}"></i><strong>#${p.id}</strong><span>${escapeHtml(p.protocol)}</span><small>${Number.isFinite(p.rel)?formatTime(p.rel,true):'N/D'}</small>${nc13Symbol('chevron')}</button>`).join('')}</div>${f.packets.length>12?`<button type="button" id="flowMore" class="nc13-more">Apri tutti i ${formatN(f.packets.length)} pacchetti ${nc13Symbol('open-packets')}</button>`:''}`;
 nc14AttachWarning(hints);
 nc13E('flowToPackets').addEventListener('click',()=>openPacketScope({type:'flow',id:f.id}));
 nc13E('flowToGraph').addEventListener('click',()=>{if(!knownTime)return;state.filter='ALL';renderProtocolFilters();setPlayhead(f.first);state.selected={type:'edge',id:pairKey(f.src,f.dst)};setPage('explorer');});
 nc13E('nc13FollowTCP')?.addEventListener('click',()=>{
  const packet=f.packets.find(p=>p.transport==='TCP');
  if(packet&&typeof nc31OpenStream==='function')nc31OpenStream(packet);
  else notify('Stream TCP non disponibile','Non ci sono segmenti TCP ricostruibili in questa conversazione.',true);
 });
 nc13E('flowMore')?.addEventListener('click',()=>openPacketScope({type:'flow',id:f.id}));
 el.querySelectorAll('[data-packet]').forEach(b=>b.addEventListener('click',()=>openPacketById(Number(b.dataset.packet))));
};
(function nc13Initialize(){
 const root=nc13E('nc13Layout');if(!root)return;
 for(const kind of ['proto','sort']){
  const el=document.createElement('div');el.id=kind==='proto'?'nc13ProtoMenu':'nc13SortMenu';el.className='nc13-dropdown';el.hidden=true;el.setAttribute('role',kind==='proto'?'listbox':'group');el.setAttribute('aria-label',kind==='proto'?'Filtra conversazioni per protocollo':'Ordina conversazioni');document.body.append(el);
 }
 const popup=document.createElement('div');popup.id='nc14WarningPopover';popup.className='nc14-warning-popover';popup.hidden=true;popup.setAttribute('role','tooltip');document.body.append(popup);
 popup.addEventListener('mouseenter',()=>{clearTimeout(nc14NoticeTimer);nc14NoticeHover=true;});
 popup.addEventListener('mouseleave',()=>{nc14NoticeHover=false;nc14HideWarning();});
 document.addEventListener('pointerdown',e=>{if(!e.target.closest('#nc14WarningToggle,#nc14WarningPopover'))nc14HideWarning(true);});
 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!popup.hidden){e.preventDefault();e.stopPropagation();nc14HideWarning(true);nc13E('nc14WarningToggle')?.focus();}},true);
 window.addEventListener('resize',nc14PositionWarning);
 window.addEventListener('scroll',nc14PositionWarning,true);
 nc13E('nc13SearchToggle').addEventListener('click',()=>nc13SetSearch(!nc13UI.searchOpen,true));
 nc13E('nc13SearchClear').addEventListener('click',()=>{nc13E('flowSearch').value='';nc13E('flowSearch').dispatchEvent(new Event('input',{bubbles:true}));nc13E('flowSearch').focus();});
 nc13E('flowSearch').addEventListener('input',nc13SyncSearch);
 nc13E('nc13ProtoToggle').addEventListener('click',()=>nc13MenuToggle('proto'));
 nc13E('nc13SortToggle').addEventListener('click',()=>nc13MenuToggle('sort'));
 nc13E('nc13CloseInspector').addEventListener('click',()=>nc13SetInspector(false));
 nc13E('nc13ReopenInspector').addEventListener('click',()=>nc13SetInspector(true));
 document.addEventListener('pointerdown',e=>{
  if(nc13UI.menu&&!e.target.closest('#nc13ProtoToggle,#nc13SortToggle,#nc13ProtoMenu,#nc13SortMenu'))nc13MenusClose();
  if(nc13UI.searchOpen&&!e.target.closest('#nc13SearchWrap'))nc13SetSearch(false);
 });
 document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
   if(nc13UI.menu){e.stopPropagation();nc13MenusClose(true);}
   else if(nc13UI.searchOpen&&!nc13E('flowSearch').value){nc13SetSearch(false);nc13E('nc13SearchToggle').focus();}
  }else if(nc13UI.menu&&(e.key==='ArrowDown'||e.key==='ArrowUp')){
   const trigger=e.target.closest('#nc13ProtoToggle,#nc13SortToggle');
   if(trigger){e.preventDefault();nc13E(nc13UI.menu==='proto'?'nc13ProtoMenu':'nc13SortMenu').querySelector('[aria-selected="true"],[aria-checked="true"]')?.focus();}
  }
 },true);
 window.addEventListener('resize',()=>nc13UI.menu&&nc13PositionMenu(nc13UI.menu));
 window.addEventListener('scroll',()=>nc13UI.menu&&nc13PositionMenu(nc13UI.menu),true);
 nc13SetSearch(false);nc13SetInspector(true);nc13RefreshToolbar();
})();

// A14: shared disclosure behavior (hover, click, keyboard, Escape and outside click).
let nc14NoticePinned=false,nc14NoticeHover=false,nc14NoticeTimer=0;
function nc14NoticeNode(){return document.getElementById('nc14WarningPopover');}
function nc14PositionWarning(){
 const trigger=nc13E('nc14WarningToggle'),pop=nc14NoticeNode();if(!trigger||!pop||pop.hidden)return;
 const rect=trigger.getBoundingClientRect(),w=Math.min(306,window.innerWidth-18);
 pop.style.width=w+'px';pop.style.left=Math.max(9,Math.min(rect.right-w,window.innerWidth-w-9))+'px';
 const ph=pop.getBoundingClientRect().height;pop.style.top=(rect.bottom+ph+8<window.innerHeight?rect.bottom+8:Math.max(8,rect.top-ph-8))+'px';
}
function nc14HideWarning(force=false){
 if(!force&&(nc14NoticePinned||nc14NoticeHover))return;
 clearTimeout(nc14NoticeTimer);nc14NoticePinned=false;if(force)nc14NoticeHover=false;
 const pop=nc14NoticeNode();if(pop)pop.hidden=true;
 const trigger=nc13E('nc14WarningToggle');if(trigger)trigger.setAttribute('aria-expanded','false');
}
function nc14ShowWarning(pin=false){
 const pop=nc14NoticeNode(),trigger=nc13E('nc14WarningToggle');if(!pop||!trigger)return;
 clearTimeout(nc14NoticeTimer);nc14NoticePinned=pin||nc14NoticePinned;pop.hidden=false;
 trigger.setAttribute('aria-expanded','true');nc14PositionWarning();
}
function nc14AttachWarning(hints){
 nc14HideWarning(true);
 const trigger=nc13E('nc14WarningToggle'),pop=nc14NoticeNode();if(!trigger||!pop)return;
 pop.innerHTML='<div class="nc14-warning-popover-title">'+nc13Symbol('alert')+'<strong>Indizi statistici</strong></div><div class="nc14-warning-popover-body">'+hints.map(h=>'<p>'+escapeHtml(h)+'</p>').join('')+'<small>Indicazione statistica: non è una rilevazione di minaccia.</small></div>';
 trigger.addEventListener('mouseenter',()=>nc14ShowWarning());
 trigger.addEventListener('mouseleave',()=>{nc14NoticeTimer=setTimeout(()=>nc14HideWarning(),160);});
 trigger.addEventListener('focus',()=>nc14ShowWarning());
 trigger.addEventListener('blur',()=>{nc14NoticeTimer=setTimeout(()=>nc14HideWarning(),160);});
 trigger.addEventListener('click',e=>{e.stopPropagation();if(nc14NoticePinned)nc14HideWarning(true);else nc14ShowWarning(true);});
}
function nc13SetInspector(open){
 nc13UI.inspectorOpen=!!open;
 nc13E('nc13Layout').classList.toggle('nc13-inspector-closed',!open);
 nc13E('nc13Inspector').hidden=!open;nc13E('nc13ReopenInspector').hidden=open;
 nc13E('nc13ReopenInspector').setAttribute('aria-expanded',String(open));
 if(!open)nc13E('nc13ReopenInspector').focus({preventScroll:true});
}
