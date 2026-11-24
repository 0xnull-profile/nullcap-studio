'use strict';
/* A09: packet presentation only. The original capture order and raw bytes are unchanged. */
const ncpsA09=id=>document.getElementById(id);
const ncpsA09Svg=name=>'<svg aria-hidden="true"><use href="#i-'+name+'"/></svg>';
const ncpsA09Fields=[['timestamp','Timestamp'],['src','Sorgente'],['dst','Destinazione'],['protocol','Protocollo'],['length','Dimensione']];
const ncpsA09Sizes=[['50','50 righe'],['100','100 righe'],['all','Tutte le righe']];
const ncpsA09AllSize=Number.MAX_SAFE_INTEGER;
state.packetPageSize=50;
state.packetSortField='timestamp';
state.packetSortDir='asc';
let ncpsA09MenuOpen=null;

/* Only the table and its previous/next traversal use sorting; export and forensic
   filtering continue to use the original getPacketBrowser() and packet IDs. */
getPacketTableRows=function(){
  const packets=getPacketBrowser();
  const field=state.packetSortField||'timestamp', direction=state.packetSortDir==='desc'?-1:1;
  return packets.slice().sort((a,b)=>{
    let delta=0;
    if(field==='timestamp'){
      const aa=Number.isFinite(a.rel)?a.rel:null,bb=Number.isFinite(b.rel)?b.rel:null;
      if(aa===null&&bb!==null)return 1;
      if(bb===null&&aa!==null)return -1;
      delta=(aa||0)-(bb||0);
    } else if(field==='length')delta=(Number(a.length)||0)-(Number(b.length)||0);
    else delta=String(a[field]||'').localeCompare(String(b[field]||''),'it',{numeric:true,sensitivity:'base'});
    return delta?Math.sign(delta)*direction:a.id-b.id;
  });
};
function ncpsA09PageSize(){return state.packetPageSize===ncpsA09AllSize?'all':String(state.packetPageSize);}
function ncpsA09RefreshPagination(){
  const paging=ncpsA09('ncpsPagination');if(!paging)return;
  const total=getPacketBrowser().length;
  const visible=ncpsA09PageSize()!=='all'&&total>state.packetPageSize;
  paging.classList.toggle('hidden',!visible);
  paging.setAttribute('aria-hidden',String(!visible));
  ncpsA09('ncpsSizeValue').textContent=ncpsA09PageSize()==='all'?'Tutte':String(state.packetPageSize);
  ncpsA09('ncpsSizeToggle').setAttribute('aria-label','Righe per pagina: '+(ncpsA09PageSize()==='all'?'tutte':state.packetPageSize));
  const field=ncpsA09Fields.find(x=>x[0]===state.packetSortField);
  ncpsA09('ncpsSortValue').textContent=field?.[1]||'Timestamp';
  ncpsA09('ncpsSortToggle').setAttribute('aria-label','Ordina per '+(field?.[1]||'Timestamp')+' '+(state.packetSortDir==='desc'?'decrescente':'crescente'));
  ncpsA09('ncpsSortToggle').classList.toggle('ncps-a09-desc',state.packetSortDir==='desc');
}
function ncpsA09Menu(kind){return ncpsA09(kind==='sort'?'ncpsSortMenu':'ncpsSizeMenu');}
function ncpsA09Toggle(kind){return ncpsA09(kind==='sort'?'ncpsSortToggle':'ncpsSizeToggle');}
function ncpsA09CloseMenu(refocus=false){
  const kind=ncpsA09MenuOpen;
  for(const k of ['sort','size']){
    ncpsA09Menu(k).classList.add('hidden');
    ncpsA09Toggle(k).setAttribute('aria-expanded','false');
  }
  ncpsA09MenuOpen=null;
  if(refocus&&kind)ncpsA09Toggle(kind).focus({preventScroll:true});
}
function ncpsA09Position(kind){
  const menu=ncpsA09Menu(kind),b=ncpsA09Toggle(kind).getBoundingClientRect();
  const w=Math.min(kind==='sort'?256:205,innerWidth-16);
  menu.style.width=w+'px';menu.style.left=Math.max(8,Math.min(b.left,innerWidth-w-8))+'px';
  const menuHeight=Math.min(menu.scrollHeight||270,340);
  const below=innerHeight-b.bottom-9,above=b.top-9;
  const down=below>=menuHeight||below>=above;
  const height=Math.min(menuHeight,Math.max(80,down?below:above));
  menu.style.maxHeight=height+'px';
  menu.style.top=(down?b.bottom+7:Math.max(8,b.top-height-7))+'px';
}
function ncpsA09RenderMenus(){
  const fields=ncpsA09('ncpsSortFields'),directions=ncpsA09('ncpsSortDirections'),sizes=ncpsA09Menu('size');
  fields.innerHTML=ncpsA09Fields.map(([value,label])=>
    '<button type="button" class="ncps-a09-option" role="radio" aria-checked="'+String(value===state.packetSortField)+'" data-a09-sort="'+value+'"><span>'+label+'</span>'+ncpsA09Svg('check')+'</button>'
  ).join('');
  directions.innerHTML=[['asc','Crescente'],['desc','Decrescente']].map(([v,label])=>
    '<button type="button" class="ncps-a09-direction" role="radio" aria-checked="'+String(v===state.packetSortDir)+'" data-a09-dir="'+v+'">'+label+'</button>'
  ).join('');
  sizes.innerHTML='<div class="ncps-menu-kicker">RIGHE PER PAGINA</div>'+ncpsA09Sizes.map(([v,label])=>
    '<button type="button" class="ncps-a09-option" role="option" aria-selected="'+String(v===ncpsA09PageSize())+'" data-a09-size="'+v+'"><span>'+label+'</span>'+ncpsA09Svg('check')+'</button>'
  ).join('');
}
function ncpsA09OpenMenu(kind,focus=false){
  const close=ncpsA09MenuOpen===kind;
  ncpsA09CloseMenu();
  if(close)return;
  ncpsCloseMenus();
  ncpsA09RenderMenus();
  ncpsA09MenuOpen=kind;ncpsA09Menu(kind).classList.remove('hidden');
  ncpsA09Toggle(kind).setAttribute('aria-expanded','true');
  ncpsA09Position(kind);
  if(focus)ncpsA09Menu(kind).querySelector('[aria-checked="true"],[aria-selected="true"]')?.focus();
}
function ncpsA09ApplyTableChange(){
  state.packetPage=0;
  ncpsA09('packetRows').closest('.packet-table-scroll').scrollTop=0;
  renderPacketTable();ncpsA09RenderMenus();
}
function ncpsA09SearchCollapse(focus=false){
  if(!ncpsSearchOpen)return;
  ncpsToggleSearch(false,false);
  if(focus)ncpsA09('ncpsSearchToggle').focus({preventScroll:true});
}
function ncpsA09DecorateInspector(){
  const root=ncpsA09('packetInspectorContent'),p=state.selectedPacket;
  if(!p)return;
  const card=root.querySelector('.packet-header-card');
  if(card){
    card.classList.add('ncps-a09-summary');
    const stamp=Number.isFinite(p.ts)?formatTime(p.rel,true):'N/D';
    const sourceDesc=p.protocolSource==='port'?'Euristica porta':p.protocolSource==='payload'?'Payload compatibile':p.protocolSource==='synthetic'?'Demo sintetica':'Header';
    card.innerHTML='<div class="ncps-a09-summary-top"><span>PACCHETTO SELEZIONATO</span><strong>#'+formatN(p.id)+'</strong></div>'+
      '<div class="ncps-a09-summary-title"><h3>'+escapeHtml(p.info||p.protocol)+'</h3><span class="ncps-a09-proto" style="--pc:'+colorOf(p.protocol)+'">'+escapeHtml(p.protocol)+'</span></div>'+
      '<div class="ncps-a09-route"><span title="Sorgente">'+escapeHtml(p.src)+(p.srcPort?':'+p.srcPort:'')+'</span>'+ncpsA09Svg('arrow-right')+'<span title="Destinazione">'+escapeHtml(p.dst)+(p.dstPort?':'+p.dstPort:'')+'</span></div>'+
      '<div class="ncps-a09-main-metrics"><div><small>TIMESTAMP</small><strong>'+escapeHtml(stamp)+'</strong></div><div><small>DIMENSIONE</small><strong>'+formatN(p.length)+' B</strong></div></div>'+
      '<details class="ncps-a09-meta"><summary>Dettagli acquisizione'+ncpsA09Svg('chevrondown')+'</summary><div><span>Origine protocollo: '+escapeHtml(sourceDesc)+'</span><span>Byte catturati: '+formatN(p.capturedLen||p.raw?.length||0)+'</span></div></details>';
  }
  const area=root.querySelector('.inspector-buttons');
  if(!area)return;
  area.classList.add('ncps-a09-actions');
  const prev=area.querySelector('#prevSelected'),next=area.querySelector('#nextSelected');
  const graph=area.querySelector('#revealSelected'),mark=area.querySelector('#nc31MarkPacket');
  const follow=area.querySelector('#nc31FollowTCP');
  const nav=document.createElement('div');nav.className='ncps-a09-action-group ncps-a09-nav';
  const tools=document.createElement('div');tools.className='ncps-a09-action-group ncps-a09-tools';
  const assign=(node,label,icon)=>{
    if(!node)return;
    node.className='ncps-a09-icon-action'+(node.classList.contains('is-bookmarked')?' is-bookmarked':'');
    node.removeAttribute('title');node.setAttribute('aria-label',label);node.setAttribute('data-tip',label);
    node.innerHTML=ncpsA09Svg(icon);
  };
  assign(prev,'Pacchetto precedente','arrow-left');assign(next,'Pacchetto successivo','arrow-right');
  assign(graph,'Mostra nel grafo','graph-star');assign(mark,nc31CurrentBookmark()?'Rimuovi segno':'Segna pacchetto','bookmark');
  if(prev)nav.append(prev);if(next)nav.append(next);
  if(graph)tools.append(graph);if(mark)tools.append(mark);
  if(follow){
    const more=document.createElement('div');more.className='ncps-a09-more-wrap';
    const b=document.createElement('button');b.type='button';b.id='ncpsA09More';b.className='ncps-a09-icon-action';b.setAttribute('data-tip','Altre azioni');b.setAttribute('aria-label','Altre azioni');b.setAttribute('aria-expanded','false');b.setAttribute('aria-controls','ncpsA09MoreMenu');b.innerHTML=ncpsA09Svg('more');
    const list=document.createElement('div');list.id='ncpsA09MoreMenu';list.className='ncps-a09-more-menu hidden';
    follow.className='ncps-a09-more-option';follow.removeAttribute('title');follow.setAttribute('aria-label','Segui TCP');
    follow.innerHTML=ncpsA09Svg('flows')+'<span>Segui TCP</span>';
    list.append(follow);more.append(b,list);tools.append(more);
    b.onclick=()=>{const open=list.classList.toggle('hidden')===false;b.setAttribute('aria-expanded',String(open));};
    b.onkeydown=e=>{if(e.key==='ArrowDown'){e.preventDefault();list.classList.remove('hidden');b.setAttribute('aria-expanded','true');follow.focus();}};
    list.onkeydown=e=>{if(e.key==='Escape'){e.preventDefault();list.classList.add('hidden');b.setAttribute('aria-expanded','false');b.focus();}};
  }
  area.replaceChildren(nav,tools);
}
function ncpsA09Bind(){
  const search=ncpsA09('packetSearch');
  ncpsA09('ncpsSearchToggle').onclick=()=>{
    if(ncpsSearchOpen)ncpsA09SearchCollapse(true);
    else ncpsToggleSearch(true);
  };
  const syncQuery=()=>ncpsA09('ncpsSearchWrap').classList.toggle('has-query',Boolean(search.value.trim()));
  search.addEventListener('input',syncQuery);
  ncpsA09('ncpsSearchClear').addEventListener('click',syncQuery);
  search.addEventListener('keydown',e=>{
    if(e.key==='Enter'){e.preventDefault();ncpsA09SearchCollapse(true);}
  });
  for(const kind of ['sort','size']){
    ncpsA09Toggle(kind).onclick=()=>ncpsA09OpenMenu(kind);
    ncpsA09Toggle(kind).onkeydown=e=>{
      if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();ncpsA09OpenMenu(kind,true);}
      if(e.key==='Escape')ncpsA09CloseMenu(true);
    };
  }
  ncpsA09Menu('sort').onclick=e=>{
    const f=e.target.closest('[data-a09-sort]'),d=e.target.closest('[data-a09-dir]');
    if(f){state.packetSortField=f.dataset.a09Sort;ncpsA09ApplyTableChange();}
    if(d){state.packetSortDir=d.dataset.a09Dir;ncpsA09ApplyTableChange();}
  };
  ncpsA09Menu('size').onclick=e=>{
    const size=e.target.closest('[data-a09-size]');if(!size)return;
    state.packetPageSize=size.dataset.a09Size==='all'?ncpsA09AllSize:Number(size.dataset.a09Size);
    ncpsA09ApplyTableChange();ncpsA09CloseMenu(true);
  };
  document.addEventListener('pointerdown',e=>{
    if(ncpsA09MenuOpen&&!
      ncpsA09Menu(ncpsA09MenuOpen).contains(e.target)&&!ncpsA09Toggle(ncpsA09MenuOpen).contains(e.target))ncpsA09CloseMenu();
    if(ncpsSearchOpen&&!ncpsA09('ncpsSearchWrap').contains(e.target))ncpsA09SearchCollapse();
    const menu=ncpsA09('ncpsA09MoreMenu');
    if(menu&&!menu.classList.contains('hidden')&&!e.target.closest('.ncps-a09-more-wrap')){
      menu.classList.add('hidden');ncpsA09('ncpsA09More')?.setAttribute('aria-expanded','false');
    }
  });
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'&&ncpsA09MenuOpen){e.preventDefault();ncpsA09CloseMenu(true);}
    if(e.key==='Escape'&&ncpsA09('ncpsA09MoreMenu')&&!ncpsA09('ncpsA09MoreMenu').classList.contains('hidden')){
      ncpsA09('ncpsA09MoreMenu').classList.add('hidden');ncpsA09('ncpsA09More')?.focus();
    }
  });
  for(const kind of ['sort','size']){
    ncpsA09Menu(kind).addEventListener('keydown',e=>{
      if(!['ArrowDown','ArrowUp','Home','End'].includes(e.key))return;
      const opts=[...ncpsA09Menu(kind).querySelectorAll('button')];if(!opts.length)return;
      e.preventDefault();const at=Math.max(0,opts.indexOf(document.activeElement));
      const next=e.key==='Home'?0:e.key==='End'?opts.length-1:(at+(e.key==='ArrowDown'?1:-1)+opts.length)%opts.length;
      opts[next].focus();
    });
  }
  for(const id of ['ncpsProtoToggle','ncpsFilterToggle'])ncpsA09(id).addEventListener('click',()=>ncpsA09CloseMenu());
  window.addEventListener('resize',()=>{if(ncpsA09MenuOpen)ncpsA09Position(ncpsA09MenuOpen);});
  syncQuery();ncpsA09RenderMenus();ncpsA09RefreshPagination();
}
const ncpsA09OldWireUI=wireUI;
wireUI=function(){ncpsA09OldWireUI();ncpsA09Bind();};
const ncpsA09OldTable=renderPacketTable;
renderPacketTable=function(){ncpsA09OldTable();ncpsA09RefreshPagination();};
const ncpsA09OldInspector=renderPacketInspector;
renderPacketInspector=function(){ncpsA09OldInspector();ncpsA09DecorateInspector();};
