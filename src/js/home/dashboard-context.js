'use strict';
/* A29: UI-only enhancement to the two lower Homepage panels.
 * The original ncRunDashboard remains responsible for all capture-derived
 * values, so we reuse its DOM values and existing navigation rather than
 * recalculating evidence, classification or forensics. */
const nc29ContextInfo={anchor:null,popover:null,pinned:false,closeTimer:null};
function nc29StopInfoClose(){
  if(nc29ContextInfo.closeTimer!==null){clearTimeout(nc29ContextInfo.closeTimer);nc29ContextInfo.closeTimer=null;}
}
function nc29CloseInfo(){
  nc29StopInfoClose();
  if(nc29ContextInfo.anchor?.isConnected)nc29ContextInfo.anchor.setAttribute('aria-expanded','false');
  if(nc29ContextInfo.popover)nc29ContextInfo.popover.hidden=true;
  nc29ContextInfo.anchor=null;nc29ContextInfo.pinned=false;
}
function nc29InfoPosition(){
  const {anchor,popover}=nc29ContextInfo;
  if(!anchor?.isConnected||!popover||popover.hidden){nc29CloseInfo();return;}
  const r=anchor.getBoundingClientRect(),width=Math.min(325,window.innerWidth-20);
  popover.style.width=width+'px';
  const h=popover.offsetHeight;
  let top=r.bottom+7;
  if(top+h>window.innerHeight-10&&r.top-h-7>=10)top=r.top-h-7;
  popover.style.top=Math.max(10,Math.min(window.innerHeight-h-10,top))+'px';
  popover.style.left=Math.max(10,Math.min(window.innerWidth-width-10,r.right-width))+'px';
}
function nc29EnsurePopover(){
  if(nc29ContextInfo.popover)return nc29ContextInfo.popover;
  const p=document.createElement('div');p.id='nc29ContextPopover';p.className='nc29-context-popover';
  p.hidden=true;p.setAttribute('role','tooltip');
  p.addEventListener('pointerenter',nc29StopInfoClose);
  p.addEventListener('pointerleave',nc29ScheduleInfoClose);
  document.body.appendChild(p);nc29ContextInfo.popover=p;
  document.addEventListener('pointerdown',event=>{
    if(!nc29ContextInfo.anchor)return;
    if(nc29ContextInfo.anchor.contains(event.target)||p.contains(event.target))return;
    nc29CloseInfo();
  },true);
  document.addEventListener('keydown',event=>{
    if(event.key==='Escape'&&nc29ContextInfo.anchor){
      event.preventDefault();const a=nc29ContextInfo.anchor;nc29CloseInfo();a?.focus();
    }
  },true);
  window.addEventListener('resize',nc29InfoPosition);
  window.addEventListener('scroll',nc29InfoPosition,true);
  return p;
}
function nc29ScheduleInfoClose(event){
  if(!nc29ContextInfo.anchor||nc29ContextInfo.pinned)return;
  const next=event?.relatedTarget;
  if(next&&(nc29ContextInfo.anchor.contains(next)||nc29ContextInfo.popover?.contains(next)))return;
  nc29StopInfoClose();
  nc29ContextInfo.closeTimer=setTimeout(()=>{if(!nc29ContextInfo.pinned)nc29CloseInfo();},110);
}
function nc29OpenInfo(button,pinned=false){
  nc29StopInfoClose();
  const p=nc29EnsurePopover();
  if(nc29ContextInfo.anchor&&nc29ContextInfo.anchor!==button)nc29CloseInfo();
  nc29ContextInfo.anchor=button;nc29ContextInfo.pinned=!!pinned;
  p.replaceChildren();
  const heading=document.createElement('strong');heading.textContent=button.dataset.infoTitle||'Informazioni';
  const desc=document.createElement('p');desc.textContent=button.dataset.infoText||'';
  p.append(heading,desc);p.hidden=false;
  button.setAttribute('aria-expanded','true');
  nc29InfoPosition();
}
function nc29WireInfo(button){
  button.addEventListener('pointerenter',event=>{if(event.pointerType==='mouse'&&!nc29ContextInfo.pinned)nc29OpenInfo(button);});
  button.addEventListener('pointerleave',nc29ScheduleInfoClose);
  button.addEventListener('focus',()=>{if(!nc29ContextInfo.pinned)nc29OpenInfo(button);});
  button.addEventListener('blur',nc29ScheduleInfoClose);
  button.addEventListener('click',event=>{
    event.stopPropagation();
    if(nc29ContextInfo.anchor===button&&nc29ContextInfo.pinned)nc29CloseInfo();
    else nc29OpenInfo(button,true);
  });
}
function nc29ReworkTalkers(){
  const list=document.getElementById('dashTalkers');if(!list)return;
  list.classList.add('nc29-talkers-list');
  const leaders=state.hosts.slice(0,5),largest=Math.max(1,leaders[0]?.bytes||0);
  list.replaceChildren();
  if(!leaders.length){
    const empty=document.createElement('p');empty.className='nc29-empty';empty.textContent='Nessun host osservato.';list.append(empty);return;
  }
  for(let i=0;i<leaders.length;i++){
    const host=leaders[i];
    const label=String(host.label||host.id||'').trim();
    const hostId=String(host.id||'');
    const hasAlias=!!label&&label.toLowerCase()!==hostId.toLowerCase();
    const row=document.createElement('button');row.type='button';row.className='talker-row nc29-talker-row';
    row.dataset.host=hostId;
    row.setAttribute('aria-label',`Apri ${label||hostId} in Esplora rete. ${formatBytes(host.bytes)} di traffico osservato.`);
    const rank=document.createElement('span');rank.className='talker-rank';rank.textContent=String(i+1).padStart(2,'0');
    const data=document.createElement('span');data.className='talker-data';
    const name=document.createElement('span');name.className='talker-name';name.textContent=label||hostId;
    const secondary=document.createElement('span');secondary.className='talker-sub';
    secondary.textContent=(hasAlias?hostId+' · ':'')+(host.local?'Rete locale':'Endpoint esterno');
    const track=document.createElement('span');track.className='talker-track';
    const fill=document.createElement('i');fill.className='talker-fill';fill.style.width=Math.max(0,Math.min(100,host.bytes/largest*100)).toFixed(1)+'%';track.append(fill);
    data.append(name,secondary,track);
    const amount=document.createElement('span');amount.className='talker-volume';amount.textContent=formatBytes(host.bytes);
    row.append(rank,data,amount);row.addEventListener('click',()=>ncGoToHost(hostId));list.append(row);
  }
}
function nc29ReworkIndicators(){
  const list=document.getElementById('dashInsights');if(!list)return;
  nc29CloseInfo();
  // Preserve the exact calculated metrics and caveats from the A28.1 renderer.
  const old=[...list.querySelectorAll('.insight-item')].map(row=>({
    title:row.querySelector('.insight-body b')?.textContent||'',
    explanation:row.querySelector('.insight-body span')?.textContent||'',
    value:row.querySelector('.insight-value')?.textContent||''
  }));
  list.classList.add('nc29-insights-list');list.replaceChildren();
  const icons=['lock-keyhole','server','calendar-clock','vault'];
  old.forEach((entry,index)=>{
    const row=document.createElement('div');row.className='insight-item nc29-insight-item';
    const icon=document.createElement('span');icon.className='insight-icon';icon.innerHTML=ncIcon(icons[index]||'info');
    const body=document.createElement('span');body.className='insight-body';
    const title=document.createElement('b');title.textContent=entry.title;body.append(title);
    if(index===3){
      const link=document.createElement('button');link.type='button';link.className='nc29-loot-link';
      link.innerHTML='Apri Bottino <svg aria-hidden="true"><use href="#i-arrow"/></svg>';
      link.setAttribute('aria-label','Apri Bottino per esaminare i dati estratti');
      link.addEventListener('click',()=>setPage('loot'));body.append(link);
    }
    const value=document.createElement('strong');value.className='insight-value';value.textContent=entry.value;
    const info=document.createElement('button');info.type='button';info.className='nc29-info-button';
    info.setAttribute('aria-label','Informazioni: '+entry.title);
    info.setAttribute('aria-expanded','false');info.setAttribute('aria-controls','nc29ContextPopover');
    info.innerHTML='<svg aria-hidden="true"><use href="#i-info"/></svg>';
    info.dataset.infoTitle=entry.title;info.dataset.infoText=entry.explanation;
    nc29WireInfo(info);row.append(icon,body,value,info);list.append(row);
  });
}
const nc29PreviousRunDashboard=ncRunDashboard;
ncRunDashboard=function(...args){
  const outcome=nc29PreviousRunDashboard(...args);
  nc29ReworkTalkers();nc29ReworkIndicators();
  return outcome;
};
