'use strict';
/* NullCap Studio 4.0.1 / Explorer UX A03.
   Unifies network search, gives protocols one visible owner, simplifies focus.
   Nothing here mutates packet bytes or source capture objects. */

const ncuxAddressCache=new Map();
let ncuxScopeCacheKey=null;
let ncuxScopeCache=null;
let ncuxInspectorIsOpen=true;
let ncuxProtocolIsOpen=false;

function ncuxIPv4Value(ip){
  if(!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip))return null;
  const parts=ip.split('.').map(Number);
  if(!parts.every(n=>Number.isInteger(n)&&n>=0&&n<=255))return null;
  return parts.reduce((n,p)=>((n<<8)|p)>>>0,0);
}
function ncuxIPv4Display(value){
  return [value>>>24,(value>>>16)&255,(value>>>8)&255,value&255].join('.');
}
function ncuxIPv6Value(ip){
  if(!ip||/[^0-9a-f:.]/i.test(ip))return null;
  let address=ip.toLowerCase();
  if(address.includes('.')){
    const last=address.lastIndexOf(':');
    if(last<0)return null;
    const ipv4=ncuxIPv4Value(address.slice(last+1));
    if(ipv4===null)return null;
    address=address.slice(0,last+1)+((ipv4>>>16)&65535).toString(16)+':'+(ipv4&65535).toString(16);
  }
  if(address.split('::').length>2)return null;
  const compressed=address.includes('::');
  const halves=compressed?address.split('::'):[address,''];
  const left=halves[0]?halves[0].split(':'):[];
  const right=compressed&&halves[1]?halves[1].split(':'):[];
  const items=[...left,...right];
  if(items.some(s=>!/^[a-f\d]{1,4}$/i.test(s)))return null;
  const omitted=8-items.length;
  if(compressed?omitted<1:omitted!==0)return null;
  const groups=compressed?[...left,...Array(omitted).fill('0'),...right]:left;
  if(groups.length!==8)return null;
  return groups.reduce((sum,word)=>(sum<<16n)|BigInt(parseInt(word,16)),0n);
}
function ncuxIPv6Display(value){
  const parts=[];
  for(let i=7;i>=0;i--)parts.push(Number((value>>BigInt(i*16))&65535n).toString(16));
  let start=-1,length=0;
  for(let i=0;i<parts.length;){
    if(parts[i]!=='0'){i++;continue;}
    let j=i;while(j<parts.length&&parts[j]==='0')j++;
    if(j-i>length&&j-i>=2){start=i;length=j-i;}
    i=j;
  }
  if(start<0)return parts.join(':');
  return parts.slice(0,start).join(':')+'::'+parts.slice(start+length).join(':');
}
function ncuxParseCIDR(raw){
  if(typeof raw!=='string')return null;
  const value=raw.trim();
  const slash=value.lastIndexOf('/');
  if(slash<=0||slash!==value.indexOf('/'))return null;
  const host=value.slice(0,slash),bits=value.slice(slash+1);
  if(!/^\d{1,3}$/.test(bits))return null;
  const prefix=Number(bits);
  if(host.includes(':')){
    const parsed=ncuxIPv6Value(host);
    if(parsed===null||prefix>128)return null;
    const mask=prefix===0?0n:(((1n<<BigInt(prefix))-1n)<<BigInt(128-prefix));
    const network=parsed&mask;
    return {family:6,network,mask,prefix,display:ncuxIPv6Display(network)+'/'+prefix};
  }
  const parsed=ncuxIPv4Value(host);
  if(parsed===null||prefix>32)return null;
  const mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0;
  const network=(parsed&mask)>>>0;
  return {family:4,network,mask,prefix,display:ncuxIPv4Display(network)+'/'+prefix};
}
function ncuxMaybeCIDR(raw){
  const s=raw.trim();
  return s.includes('/')&&/^[0-9a-f:.]+\//i.test(s);
}
function ncuxSubnetForCurrentState(){
  const value=state.nc32Subnet||'ALL';
  if(value===ncuxScopeCacheKey)return ncuxScopeCache;
  ncuxScopeCacheKey=value;
  ncuxScopeCache=value==='ALL'?null:ncuxParseCIDR(value);
  return ncuxScopeCache;
}
function ncuxHostInSubnet(ip,net){
  if(!net)return true;
  const key=net.family+':'+ip;
  let address=ncuxAddressCache.get(key);
  if(address===undefined){
    address=net.family===4?ncuxIPv4Value(ip):ncuxIPv6Value(ip);
    ncuxAddressCache.set(key,address);
  }
  if(address===null)return false;
  if(net.family===4)return ((address&net.mask)>>>0)===net.network;
  return (address&net.mask)===net.network;
}

/* The historical subnet selector was limited to /24 labels. A CIDR now selects
   actual IPv4 or IPv6 hosts, with the existing top-75 and pinned-host policy. */
nc32GraphVisibleHostList=function(){
  const net=ncuxSubnetForCurrentState();
  const pool=net?state.hosts.filter(host=>ncuxHostInSubnet(host.id,net)):state.hosts;
  return [...pool.filter(h=>state.nc32Pinned.has(h.id)),
          ...pool.filter(h=>!state.nc32Pinned.has(h.id))].slice(0,MAX_HOSTS_GRAPH);
};
nc32SubnetOptions=function(){
  /* Legacy DOM select stays inert for the historical event wire-up only. */
  if(state.nc32Subnet!=='ALL'){
    const parsed=ncuxParseCIDR(state.nc32Subnet);
    state.nc32Subnet=parsed?parsed.display:'ALL';
  }
  ncuxScopeCacheKey=null;
  const legacy=$('nc32Subnet');
  if(legacy){
    const choices=new Set(state.hosts.map(h=>nc32SubnetOf(h.id)));
    legacy.innerHTML='<option value="ALL">Tutte le reti</option>'+[...choices].map(x=>
      '<option value="'+escapeHtml(x)+'">'+escapeHtml(x)+'</option>').join('');
    legacy.value=choices.has(state.nc32Subnet)?state.nc32Subnet:'ALL';
  }
  ncuxUpdateScopeChip();
};
function ncuxUpdateScopeChip(){
  const net=ncuxSubnetForCurrentState();
  const chip=$('ncuxActiveSubnet');
  if(!chip)return;
  chip.classList.toggle('hidden',!net);
  $('ncuxSubnetText').textContent=net?net.display:'';
  chip.title=net?'Filtro di rete attivo: '+net.display:'Tutte le reti';
  if($('ncuxSearchToggle'))$('ncuxSearchToggle').classList.toggle('has-scope',!!net);
}
function ncuxRefreshNoMatch(){
  const el=$('ncuxNoNetworkMatch');
  if(!el||!state.snapshot)return;
  el.classList.toggle('hidden',!(state.nc32Subnet!=='ALL'&&state.snapshot.count>0&&state.snapshot.nodes.length===0));
}
const ncuxPreviousUpdateSnapshot=updateSnapshot;
updateSnapshot=function(force=false){
  ncuxPreviousUpdateSnapshot(force);
  ncuxRefreshNoMatch();
};

function ncuxSetSearchOpen(open,restoreFocus=true){
  const wrap=$('ncuxSearchWrap'),input=$('graphSearch'),toggle=$('ncuxSearchToggle');
  if(!wrap||!input)return;
  wrap.classList.toggle('is-open',!!open);
  toggle.setAttribute('aria-expanded',String(!!open));
  toggle.setAttribute('aria-label',open?'Chiudi ricerca':'Apri ricerca host, IP o subnet');
  input.tabIndex=open?0:-1;
  if(open)requestAnimationFrame(()=>input.focus());
  else{ncuxSetSearchError('');if(restoreFocus)toggle.focus({preventScroll:true});}
}
function ncuxSetSearchError(message,error=false){
  const wrap=$('ncuxSearchWrap'),hint=$('ncuxSearchHint');
  if(!wrap||!hint)return;
  wrap.classList.toggle('is-error',!!error);
  wrap.classList.toggle('has-hint',!!message);
  hint.textContent=message||'';
  $('graphSearch').setAttribute('aria-invalid',error?'true':'false');
}
function ncuxResetSearchText(){
  const input=$('graphSearch');
  input.value='';state.graphQuery='';
  $('ncuxSearchWrap').classList.remove('has-query');
  ncuxSetSearchError('');
  drawGraph();
}
function ncuxRemoveSubnet(){
  state.nc32Subnet='ALL';
  ncuxScopeCacheKey=null;
  ncuxUpdateScopeChip();
  nc32GraphRefresh();
  ncuxRefreshNoMatch();
}
function ncuxApplyCIDR(raw){
  const result=ncuxParseCIDR(raw);
  if(!result){
    ncuxSetSearchError('CIDR non valido. Usa un indirizzo con prefisso, per esempio 192.168.1.0/23.',true);
    return false;
  }
  state.nc32Subnet=result.display;
  ncuxScopeCacheKey=null;
  ncuxResetSearchText();
  ncuxUpdateScopeChip();
  nc32GraphRefresh();
  ncuxRefreshNoMatch();
  ncuxSetSearchOpen(false);
  return true;
}
function ncuxOnSearchInput(e){
  /* Capture listener replaces the older highlight-only bubble listener. */
  e.stopImmediatePropagation();
  const text=e.target.value.trim();
  $('ncuxSearchWrap').classList.toggle('has-query',!!text);
  if(ncuxMaybeCIDR(text)){
    state.graphQuery='';
    ncuxSetSearchError('Premi Invio per applicare il filtro di rete CIDR.');
  }else{
    ncuxSetSearchError('');
    state.graphQuery=text.toLowerCase();
  }
  drawGraph();
}
function ncuxOnSearchKeydown(e){
  if(e.key==='Escape'){
    e.preventDefault();e.stopPropagation();
    ncuxResetSearchText();ncuxSetSearchOpen(false);
  }else if(e.key==='Enter'){
    e.preventDefault();e.stopPropagation();
    const value=e.target.value.trim();
    if(!value){ncuxResetSearchText();ncuxSetSearchOpen(false);return;}
    if(ncuxMaybeCIDR(value))ncuxApplyCIDR(value);
    else ncuxSetSearchError('Host o IP evidenziato nella mappa.');
  }
}

function ncuxRenderProtocolMenu(){
  const panel=$('ncuxProtoMenu'),label=$('ncuxProtoValue'),toggle=$('ncuxProtoToggle');
  if(!panel||!state.packets)return;
  const counts=new Map();
  for(const p of state.packets)counts.set(p.protocol,(counts.get(p.protocol)||0)+1);
  const selected=state.filter||'ALL';
  const items=[['ALL','Tutti i protocolli',state.packets.length],
    ...[...counts.entries()].sort((a,b)=>b[1]-a[1]).map(([k,n])=>[k,k,n])];
  panel.innerHTML='<div class="ncux-proto-menu-caption">VISUALIZZA PROTOCOLLO</div>'+items.map(([key,name,count])=>
    '<button type="button" role="option" class="ncux-proto-row" data-ncux-proto="'+escapeHtml(key)+'" aria-selected="'+(selected===key)+'" tabindex="-1" style="--pc:'+colorOf(key)+'">'+
      '<i aria-hidden="true"></i><span>'+escapeHtml(name)+'</span><span class="ncux-proto-count">'+formatN(count)+'</span>'+
      '<span class="ncux-row-selected" aria-hidden="true">'+ncIcon('check')+'</span></button>'
  ).join('');
  label.textContent=selected==='ALL'?'Tutti':selected;
  toggle.setAttribute('aria-label','Filtra per protocollo: '+(selected==='ALL'?'tutti':selected));
  $('ncuxProtocolSelector').classList.toggle('has-filter',selected!=='ALL');
  $('ncuxProtoActiveDot').style.setProperty('--ncux-protocol-color',selected==='ALL'?'#a9c8d8':colorOf(selected));
  if(!ncuxProtocolIsOpen)panel.classList.add('hidden');
}
const ncuxPreviousRenderProtocolFilters=renderProtocolFilters;
renderProtocolFilters=function(){
  ncuxPreviousRenderProtocolFilters();
  ncuxRenderProtocolMenu();
};
function ncuxPositionMenu(){
  const panel=$('ncuxProtoMenu'),button=$('ncuxProtoToggle'),r=button.getBoundingClientRect();
  panel.style.position='fixed';
  panel.style.width=Math.max(255,Math.min(325,window.innerWidth-30))+'px';
  const w=Math.max(255,Math.min(325,window.innerWidth-30));
  panel.style.left=Math.max(8,Math.min(r.right-w,window.innerWidth-w-8))+'px';
  const h=Math.min(panel.scrollHeight||320,340);
  panel.style.top=(window.innerHeight-r.bottom>h+12?r.bottom+7:Math.max(8,r.top-h-7))+'px';
}
function ncuxSetProtocolOpen(open,focusChoice=false){
  ncuxProtocolIsOpen=!!open;
  const panel=$('ncuxProtoMenu'),toggle=$('ncuxProtoToggle');
  if(!panel||!toggle)return;
  panel.classList.toggle('hidden',!open);
  toggle.setAttribute('aria-expanded',String(!!open));
  if(open){ncuxPositionMenu();if(focusChoice){
    const option=panel.querySelector('[aria-selected="true"]')||panel.querySelector('[role="option"]');
    option?.focus();
  }}
}
function ncuxChooseProtocol(value){
  state.filter=value;
  ncuxSetProtocolOpen(false);
  renderProtocolFilters();
  updateSnapshot(true);drawTimeline();drawGraph();
  $('ncuxProtoToggle').focus();
}
function ncuxMenuKeydown(e){
  const choices=[...$('ncuxProtoMenu').querySelectorAll('[role="option"]')];
  const i=choices.indexOf(document.activeElement);
  if(e.key==='Escape'){e.preventDefault();ncuxSetProtocolOpen(false);$('ncuxProtoToggle').focus();}
  else if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){
    e.preventDefault();
    let next=e.key==='Home'?0:e.key==='End'?choices.length-1:e.key==='ArrowDown'?Math.min(choices.length-1,i+1):Math.max(0,i-1);
    choices[next]?.focus();
  }else if((e.key==='Enter'||e.key===' ')&&i>=0){
    e.preventDefault();ncuxChooseProtocol(choices[i].dataset.ncuxProto);
  }
}

function ncuxTimeDescription(){
  return state.mode==='window'?'Finestra attiva: ultimi '+state.window+' s':'Dall\'inizio della cattura a ora';
}
function ncuxTimeDisplay(time){return Number.isFinite(time)?formatTime(time,true):'N/D';}
function ncuxStat(label,value,small=false){
  return '<div class="ncux-inspect-stat"><small>'+escapeHtml(label)+'</small><strong class="'+(small?'ncux-small-value':'')+'">'+escapeHtml(String(value))+'</strong></div>';
}
function ncuxProtoList(packets){
  const counts=new Map();
  for(const p of packets)counts.set(p.protocol,(counts.get(p.protocol)||0)+1);
  return [...counts].sort((a,b)=>b[1]-a[1]).map(([proto,count])=>({proto,count}));
}
function ncuxProtosHTML(protos){
  if(!protos.length)return '';
  const visible=protos.slice(0,3);
  const extra=protos.length-visible.length;
  return '<div class="ncux-inspect-protocols"><span>PROTOCOLLI</span>'+visible.map(({proto})=>
    '<span class="ncux-proto-tag" style="--pc:'+colorOf(proto)+'"><i aria-hidden="true"></i>'+escapeHtml(proto)+'</span>'
  ).join('')+(extra?'<span class="ncux-proto-tag">+'+extra+'</span>':'')+'</div>';
}
function ncuxCard(label,title,sub,route=''){
  return '<div class="ncux-inspect-intro"><i aria-hidden="true"></i>'+escapeHtml(label)+'</div>'+ 
    '<div class="ncux-inspect-entity"><h3>'+escapeHtml(title)+'</h3>'+(sub?'<p>'+escapeHtml(sub)+'</p>':'')+route+'</div>';
}
function ncuxCardRoute(a,b){
  return '<div class="ncux-inspect-route"><span>'+escapeHtml(a)+'</span>'+ncIcon('arrow-left-right')+'<span>'+escapeHtml(b)+'</span></div>';
}
function ncuxAction(title,action){
  return '<button class="ncux-inspect-action" type="button" data-ncux-inspect="'+action+'">'+ncIcon('open-packets')+escapeHtml(title)+'</button>';
}
function ncuxFocusScope(){
  return state.selected.type?{type:state.selected.type,id:state.selected.id}:
    {type:'time',start:state.mode==='window'?Math.max(0,state.playhead-state.window):0,end:state.playhead};
}
/* Deliberately show summary metadata only, even for a selected frame. */
renderFocus=function(){
  if(state.page!=='explorer')return;
  const focus=$('focusContent'),s=state.snapshot,selection=state.selected;
  if(!focus||!s)return;
  const p=state.quickPacket;
  let markup='';
  if(p){
    markup=ncuxCard('PACCHETTO SELEZIONATO','Frame #'+p.id, 'Comunicazione osservata', ncuxCardRoute(p.src,p.dst))+
      '<p class="ncux-inspect-time-context">Anteprima essenziale, senza contenuto del payload.</p>'+
      '<div class="ncux-inspect-stats">'+ncuxStat('PROTOCOLLO',p.protocol,true)+ncuxStat('QUANDO',ncuxTimeDisplay(p.rel),true)+
      ncuxStat('PACCHETTI','1')+ncuxStat('DIMENSIONE',formatBytes(p.length))+'</div>'+
      ncuxAction('Apri Packet Inspector','packet')+'<button class="ncux-inspect-secondary" type="button" data-ncux-inspect="back">Torna alla panoramica</button>';
  }else if(selection.type==='node'&&s.hostMap.has(selection.id)){
    const node=s.hostMap.get(selection.id);
    const packets=s.packets.filter(p=>p.src===node.id||p.dst===node.id);
    const protos=ncuxProtoList(packets);
    const times=packets.filter(p=>Number.isFinite(p.rel)).map(p=>p.rel);
    const last=times.length?times.reduce((value,t)=>Math.max(value,t),-Infinity):NaN;
    const peers=new Set(packets.map(p=>p.src===node.id?p.dst:p.src));
    markup=ncuxCard('HOST OSSERVATO',node.label,node.id+'  |  '+(node.local?'Host privato':'Endpoint remoto'))+
      '<p class="ncux-inspect-time-context">'+escapeHtml(ncuxTimeDescription())+'  |  '+peers.size+' interlocutori osservati</p>'+
      '<div class="ncux-inspect-stats">'+ncuxStat('ULTIMA ATTIVITA',ncuxTimeDisplay(last),true)+ncuxStat('PACCHETTI',formatN(node.count))+
      ncuxStat('VOLUME',formatBytes(node.bytes))+ncuxStat('DIM. MEDIA',formatBytes(node.count?Math.round(node.bytes/node.count):0))+'</div>'+
      ncuxProtosHTML(protos)+ncuxAction('Vedi pacchetti dell\'host','scope');
  }else if(selection.type==='edge'&&s.edgeMap.has(selection.id)){
    const edge=s.edgeMap.get(selection.id),packets=s.packets.filter(p=>p.pair===edge.id);
    const protos=ncuxProtoList(packets);
    const nameA=state.hostMap.get(edge.a)?.label||edge.a;
    const nameB=state.hostMap.get(edge.b)?.label||edge.b;
    markup=ncuxCard('COMUNICAZIONE SELEZIONATA',nameA+'  /  '+nameB,
      'Endpoint comunicanti',ncuxCardRoute(edge.a,edge.b))+
      '<p class="ncux-inspect-time-context">'+escapeHtml(ncuxTimeDescription())+'  |  Primo evento: '+ncuxTimeDisplay(edge.first)+'</p>'+
      '<div class="ncux-inspect-stats">'+ncuxStat('ULTIMO EVENTO',ncuxTimeDisplay(edge.last),true)+
      ncuxStat('PACCHETTI',formatN(edge.count))+
      ncuxStat('VOLUME',formatBytes(edge.bytes))+ncuxStat('DIM. MEDIA',formatBytes(edge.count?Math.round(edge.bytes/edge.count):0))+'</div>'+
      ncuxProtosHTML(protos)+ncuxAction('Apri pacchetti di questa comunicazione','scope');
  }else{
    const visible=new Set(s.nodes.map(node=>node.id));
    const packets=s.packets.filter(p=>visible.has(p.src)||visible.has(p.dst));
    const bytes=packets.reduce((sum,p)=>sum+p.length,0);
    markup=ncuxCard('PANORAMICA',s.nodes.length?'Comunicazioni osservate':'In attesa di comunicazioni',
      'Seleziona un host o una connessione nella mappa per vedere il riepilogo.')+
      '<p class="ncux-inspect-time-context">'+escapeHtml(ncuxTimeDescription())+'</p>'+
      '<div class="ncux-inspect-stats">'+ncuxStat('HOST VISIBILI',s.nodes.length)+ncuxStat('CONNESSIONI',s.edges.length)+
      ncuxStat('PACCHETTI',formatN(packets.length))+ncuxStat('VOLUME',formatBytes(bytes))+'</div>'+
      (packets.length?ncuxAction('Esplora tutti i pacchetti','scope'):'<div class="ncux-inspect-empty">'+ncIcon('network')+'<b>Nessun traffico nella vista</b><span>Avanza nella timeline, cambia finestra o modifica i filtri.</span></div>');
  }
  focus.innerHTML=markup;
  focus.querySelectorAll('[data-ncux-inspect]').forEach(button=>button.onclick=()=>{
    switch(button.dataset.ncuxInspect){
      case 'scope': openPacketScope(ncuxFocusScope());break;
      case 'packet': if(p)openPacketById(p.id);break;
      case 'back': state.quickPacket=null;renderFocus();drawGraph();break;
    }
  });
};

function ncuxMoveInspector(){
  const aside=$('ncuxFocusPane'),layout=document.querySelector('#view-explorer .explorer-layout');
  const main=$('mainScroll'),timeline=$('timelinePanel');
  if(!aside||!layout||!timeline||!main)return;
  if(window.matchMedia('(max-width:900px)').matches){
    if(aside.parentElement!==main)timeline.insertAdjacentElement('afterend',aside);
    aside.dataset.ncuxMobile='true';
  }else{
    if(aside.parentElement!==layout)layout.appendChild(aside);
    delete aside.dataset.ncuxMobile;
  }
}
function ncuxSetInspectorOpen(isOpen){
  ncuxInspectorIsOpen=!!isOpen;
  document.body.classList.toggle('ncux-inspector-closed',!isOpen);
  $('ncuxCloseInspector').setAttribute('aria-expanded',String(!!isOpen));
  $('ncuxReopenInspector').setAttribute('aria-expanded',String(!!isOpen));
  $('ncuxFocusPane').inert=!isOpen;
  $('ncuxFocusPane').setAttribute('aria-hidden',String(!isOpen));
  if(!isOpen)$('ncuxReopenInspector').focus();
  else $('ncuxCloseInspector').focus();
  requestAnimationFrame(resizeGraph);
  setTimeout(resizeGraph,260);
}

const ncuxPreviousApplyCapture=applyCapture;
applyCapture=function(...args){
  ncuxAddressCache.clear();ncuxScopeCacheKey=null;
  const value=ncuxPreviousApplyCapture(...args);
  if($('graphSearch'))ncuxResetSearchText();
  ncuxUpdateScopeChip();ncuxRenderProtocolMenu();ncuxRefreshNoMatch();
  ncuxSetSearchOpen(false);
  return value;
};
window.NullCap.applyCapture=applyCapture;

function ncuxBindUI(){
  const search=$('graphSearch');
  search.tabIndex=-1;
  search.addEventListener('input',ncuxOnSearchInput,true);
  search.addEventListener('keydown',ncuxOnSearchKeydown);
  $('ncuxSearchToggle').onclick=()=>{
    const open=$('ncuxSearchWrap').classList.contains('is-open');
    if(open)ncuxResetSearchText();
    ncuxSetSearchOpen(!open);
  };
  $('ncuxClearSearch').onclick=()=>{ncuxResetSearchText();search.focus();};
  $('ncuxClearSubnet').onclick=ncuxRemoveSubnet;
  $('ncuxNoMatchReset').onclick=ncuxRemoveSubnet;
  $('ncuxProtoToggle').onclick=()=>ncuxSetProtocolOpen(!ncuxProtocolIsOpen,true);
  $('ncuxProtoToggle').onkeydown=e=>{
    if(['ArrowDown','ArrowUp','Enter',' '].includes(e.key)){
      e.preventDefault();ncuxSetProtocolOpen(true,true);
    }else if(e.key==='Escape')ncuxSetProtocolOpen(false);
  };
  $('ncuxProtoMenu').addEventListener('keydown',ncuxMenuKeydown);
  $('ncuxProtoMenu').addEventListener('click',e=>{
    const button=e.target.closest('[data-ncux-proto]');
    if(button)ncuxChooseProtocol(button.dataset.ncuxProto);
  });
  document.addEventListener('pointerdown',e=>{
    if(ncuxProtocolIsOpen&&!$('ncuxProtocolSelector').contains(e.target))ncuxSetProtocolOpen(false);
    if($('ncuxSearchWrap').classList.contains('is-open')&&
       !$('ncuxSearchWrap').contains(e.target)&&!search.value.trim())ncuxSetSearchOpen(false,false);
  });
  window.addEventListener('resize',()=>{ncuxMoveInspector();if(ncuxProtocolIsOpen)ncuxPositionMenu();});
  $('ncuxCloseInspector').onclick=()=>ncuxSetInspectorOpen(false);
  $('ncuxReopenInspector').onclick=()=>ncuxSetInspectorOpen(true);
  ncuxMoveInspector();
  ncuxUpdateScopeChip();
  ncuxRenderProtocolMenu();
}
const ncuxPreviousWireUI=wireUI;
wireUI=function(){ncuxPreviousWireUI();ncuxBindUI();};
Object.assign(window.NullCap,{explorerUX:{parseCIDR:ncuxParseCIDR,applyCIDR:ncuxApplyCIDR,clearCIDR:ncuxRemoveSubnet,openInspector:ncuxSetInspectorOpen}});
