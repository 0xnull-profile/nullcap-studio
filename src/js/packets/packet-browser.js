'use strict';
/* A08 UI adapters. Keep the original hidden inputs and packet/forensic engine authoritative. */
let ncpsMenuOpen=null,ncpsSearchOpen=false;
const ncpsEl=id=>document.getElementById(id);
function ncpsSync(){
  const native=ncpsEl('packetProto');if(!native)return;
  const value=native.value||'ALL';
  ncpsEl('ncpsProtoValue').textContent=value==='ALL'?'Tutti':value;
  ncpsEl('ncpsProtoToggle').setAttribute('aria-label','Protocollo: '+(value==='ALL'?'Tutti':value));
  const count=Number(ncpsEl('pastOnly').checked)+Number(ncpsEl('sensitiveOnly').checked);
  ncpsEl('ncpsFilterCount').textContent=String(count);ncpsEl('ncpsFilterCount').classList.toggle('hidden',count===0);
  ncpsEl('ncpsFilterToggle').classList.toggle('has-filter',count>0);
  ncpsEl('toggleAdvanced').classList.toggle('is-active',Boolean(state.advancedExpr)||ncpsEl('toggleAdvanced').getAttribute('aria-expanded')==='true');
  ncpsEl('ncpsSearchWrap').classList.toggle('has-query',Boolean(ncpsEl('packetSearch').value.trim()));
}
function ncpsToggleSearch(open,focus=true){
  ncpsSearchOpen=!!open;
  ncpsEl('ncpsSearchWrap').classList.toggle('is-open',ncpsSearchOpen);
  ncpsEl('ncpsSearchToggle').setAttribute('aria-expanded',String(ncpsSearchOpen));
  ncpsEl('packetSearch').tabIndex=ncpsSearchOpen?0:-1;
  if(ncpsSearchOpen&&focus)requestAnimationFrame(()=>ncpsEl('packetSearch').focus());
}
function ncpsCloseMenus(refocus=false){
  const active=ncpsMenuOpen;
  for(const kind of ['proto','filter']){
    ncpsEl(kind==='proto'?'ncpsProtoMenu':'ncpsFilterMenu').classList.add('hidden');
    ncpsEl(kind==='proto'?'ncpsProtoToggle':'ncpsFilterToggle').setAttribute('aria-expanded','false');
  }
  ncpsMenuOpen=null;
  if(refocus&&active)ncpsEl(active==='proto'?'ncpsProtoToggle':'ncpsFilterToggle').focus();
}
function ncpsMenuPlace(kind){
  const btn=ncpsEl(kind==='proto'?'ncpsProtoToggle':'ncpsFilterToggle'),menu=ncpsEl(kind==='proto'?'ncpsProtoMenu':'ncpsFilterMenu');
  const r=btn.getBoundingClientRect(),w=Math.min(kind==='proto'?260:310,window.innerWidth-18);
  menu.style.width=w+'px';menu.style.left=Math.max(9,Math.min(r.left,window.innerWidth-w-9))+'px';
  const target=Math.min(menu.scrollHeight||260,360),bottom=window.innerHeight-r.bottom-12,top=r.top-12,down=bottom>=target||bottom>=top;
  const h=Math.min(target,Math.max(65,down?bottom:top));menu.style.maxHeight=h+'px';
  menu.style.top=(down?r.bottom+7:Math.max(8,r.top-h-7))+'px';
}
function ncpsRenderProtocols(){
  const select=ncpsEl('packetProto'),menu=ncpsEl('ncpsProtoMenu');
  const counts=new Map();state.packets.forEach(p=>counts.set(p.protocol,(counts.get(p.protocol)||0)+1));
  menu.innerHTML='<div class="ncps-menu-kicker">FILTRA PER PROTOCOLLO</div>'+[...select.options].map(o=>{
    const v=o.value,c=v==='ALL'?state.packets.length:counts.get(v)||0,selected=v===select.value;
    return '<button type="button" role="option" tabindex="-1" class="ncps-option" data-ncps-proto="'+escapeHtml(v)+'" aria-selected="'+String(selected)+'" style="--pc:'+colorOf(v)+'"><i class="ncps-dot" aria-hidden="true"></i><span>'+escapeHtml(v==='ALL'?'Tutti i protocolli':v)+'</span><span class="ncps-opt-count">'+formatN(c)+'</span><svg aria-hidden="true"><use href="#i-check"/></svg></button>';
  }).join('');
  for(const opt of menu.querySelectorAll('[data-ncps-proto]')){
    opt.onclick=()=>{select.value=opt.dataset.ncpsProto;select.dispatchEvent(new Event('change',{bubbles:true}));ncpsSync();ncpsCloseMenus(true);};
    opt.onkeydown=e=>{
      const options=[...menu.querySelectorAll('[role="option"]')],idx=options.indexOf(opt);
      if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();options[(idx+(e.key==='ArrowDown'?1:-1)+options.length)%options.length].focus();}
      else if(e.key==='Home'||e.key==='End'){e.preventDefault();options[e.key==='Home'?0:options.length-1].focus();}
      else if(e.key==='Enter'||e.key===' '){e.preventDefault();opt.click();}
      else if(e.key==='Escape'){e.preventDefault();ncpsCloseMenus(true);}
    };
  }
}
function ncpsOpenMenu(kind,focus=false){
  const wasOpen=ncpsMenuOpen===kind;ncpsCloseMenus();if(wasOpen)return;
  if(kind==='proto')ncpsRenderProtocols();ncpsMenuOpen=kind;
  ncpsEl(kind==='proto'?'ncpsProtoMenu':'ncpsFilterMenu').classList.remove('hidden');
  ncpsEl(kind==='proto'?'ncpsProtoToggle':'ncpsFilterToggle').setAttribute('aria-expanded','true');
  ncpsMenuPlace(kind);
  if(focus)(kind==='proto'?ncpsEl('ncpsProtoMenu').querySelector('[aria-selected="true"]'):ncpsEl('ncpsFilterMenu').querySelector('input'))?.focus();
}
function ncpsInspector(open){
  if(!open&&document.querySelector('.packet-inspector')?.classList.contains('is-expanded'))collapseInspector();
  ncpsEl('ncpsLayout').classList.toggle('ncps-inspector-collapsed',!open);
  ncpsEl('ncpsReopen').classList.toggle('hidden',open);
  ncpsEl('ncpsReopen').setAttribute('aria-expanded',String(open));
  if(!open)ncpsEl('ncpsReopen').focus();
}
function ncpsDecorateTable(){
  const rows=[...ncpsEl('packetRows').querySelectorAll('tr[data-packet-id]')];
  for(const row of rows){
    row.tabIndex=0;row.setAttribute('role','button');row.setAttribute('aria-label','Apri pacchetto numero '+row.dataset.packetId);row.setAttribute('aria-pressed',String(row.classList.contains('is-selected')));
    row.onkeydown=e=>{
      if(e.key==='Enter'||e.key===' '){e.preventDefault();row.click();ncpsEl('packetRows').querySelector('tr.is-selected')?.focus({preventScroll:true});}
      else if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();rows[rows.indexOf(row)+(e.key==='ArrowDown'?1:-1)]?.focus();}
    };
  }
}
function ncpsBind(){
  ncpsToggleSearch(false,false);
  ncpsEl('ncpsSearchToggle').onclick=()=>{if(!ncpsSearchOpen)ncpsToggleSearch(true);else if(!ncpsEl('packetSearch').value){ncpsToggleSearch(false,false);ncpsEl('ncpsSearchToggle').focus();}else ncpsEl('packetSearch').focus();};
  ncpsEl('ncpsSearchClear').onclick=()=>{const inp=ncpsEl('packetSearch');inp.value='';inp.dispatchEvent(new Event('input',{bubbles:true}));inp.focus();};
  ncpsEl('packetSearch').addEventListener('keydown',e=>{if(e.key==='Escape'){e.preventDefault();if(e.target.value){e.target.value='';e.target.dispatchEvent(new Event('input',{bubbles:true}));}else{ncpsToggleSearch(false,false);ncpsEl('ncpsSearchToggle').focus();}}});
  ncpsEl('ncpsProtoToggle').onclick=()=>ncpsOpenMenu('proto');
  ncpsEl('ncpsFilterToggle').onclick=()=>ncpsOpenMenu('filter');
  ncpsEl('ncpsProtoToggle').onkeydown=e=>{if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();if(ncpsMenuOpen!=='proto')ncpsOpenMenu('proto',true);}else if(e.key==='Escape')ncpsCloseMenus(true);};
  ncpsEl('ncpsFilterToggle').onkeydown=e=>{if(e.key==='ArrowDown'){e.preventDefault();if(ncpsMenuOpen!=='filter')ncpsOpenMenu('filter',true);}else if(e.key==='Escape')ncpsCloseMenus(true);};
  ncpsEl('ncpsFilterMenu').onkeydown=e=>{if(e.key==='Escape'){e.preventDefault();ncpsCloseMenus(true);}};
  ncpsEl('packetProto').addEventListener('change',ncpsSync);
  ncpsEl('pastOnly').addEventListener('change',ncpsSync);
  ncpsEl('sensitiveOnly').addEventListener('change',ncpsSync);
  ncpsEl('toggleAdvanced').addEventListener('click',()=>{ncpsCloseMenus();requestAnimationFrame(ncpsSync);});
  ncpsEl('ncpsCloseInspector').onclick=()=>ncpsInspector(false);
  ncpsEl('ncpsReopen').onclick=()=>ncpsInspector(true);
  document.addEventListener('pointerdown',e=>{
    if(!ncpsMenuOpen)return;
    const id=ncpsMenuOpen==='proto'?'ncpsProto':'ncpsFilter';
    if(!ncpsEl(id+'Menu').contains(e.target)&&!ncpsEl(id+'Toggle').contains(e.target))ncpsCloseMenus();
  });
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&ncpsMenuOpen){e.preventDefault();ncpsCloseMenus(true);}});
  window.addEventListener('resize',()=>{if(ncpsMenuOpen)ncpsMenuPlace(ncpsMenuOpen);});
  document.addEventListener('scroll',e=>{if(ncpsMenuOpen&&e.target!==ncpsEl('ncpsProtoMenu')&&e.target!==ncpsEl('ncpsFilterMenu'))ncpsCloseMenus();},true);
  ncpsSync();
}
const ncpsPreviousWireUI=wireUI;
wireUI=function(){ncpsPreviousWireUI();ncpsBind();};
const ncpsPreviousRenderPacketTable=renderPacketTable;
renderPacketTable=function(){ncpsPreviousRenderPacketTable();ncpsDecorateTable();ncpsSync();};
