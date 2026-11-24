'use strict';
/* A28. The interactive visualization is derived from the real, already decoded
 * packet protocol counts. No capture data or parser behavior is changed. */
const nc28ProtoUI={slices:[],hover:null,pinned:null,focused:null,generation:null};
const nc28SvgNS='http://www.w3.org/2000/svg';
const nc28DonutR=85;
const nc28DonutC=2*Math.PI*nc28DonutR;
function nc28EffectiveProtocol(){return nc28ProtoUI.hover||nc28ProtoUI.focused||nc28ProtoUI.pinned;}
function nc28Slice(proto){return nc28ProtoUI.slices.find(entry=>entry.proto===proto);}
function nc28HideTooltip(){const box=document.getElementById('nc28DonutTooltip');if(box)box.hidden=true;}
function nc28PositionTooltip(x,y){
  const tooltip=document.getElementById('nc28DonutTooltip');if(!tooltip||tooltip.hidden)return;
  const width=tooltip.offsetWidth,height=tooltip.offsetHeight;
  const left=Math.max(12,Math.min(window.innerWidth-width-12,x+13));
  let top=y-height-12;if(top<12)top=Math.min(window.innerHeight-height-12,y+15);
  tooltip.style.left=left+'px';tooltip.style.top=top+'px';
}
function nc28ShowTooltip(proto,event){
  const slice=nc28Slice(proto),tooltip=document.getElementById('nc28DonutTooltip');
  if(!slice||!tooltip){nc28HideTooltip();return;}
  tooltip.replaceChildren();
  const heading=document.createElement('b');heading.textContent=slice.proto;
  const value=document.createElement('span');value.textContent=formatN(slice.count)+' pacchetti | '+slice.percent.toFixed(1)+'%';
  tooltip.append(heading,value);tooltip.hidden=false;
  const rect=(event?.currentTarget||event?.target||document.getElementById('donutChart')).getBoundingClientRect();
  nc28PositionTooltip(Number.isFinite(event?.clientX)&&event.clientX>0?event.clientX:rect.left+rect.width/2,Number.isFinite(event?.clientY)&&event.clientY>0?event.clientY:rect.top+rect.height/2);
}
function nc28RefreshSelection(){
  const active=nc28EffectiveProtocol();
  const total=nc28ProtoUI.slices.reduce((sum,s)=>sum+s.count,0);
  const slice=nc28Slice(active);
  const main=document.getElementById('donutTotal'),caption=document.getElementById('nc28DonutCaption'),cta=document.getElementById('nc28ExploreSelected');
  if(main)main.textContent=slice?slice.proto:formatN(total);
  if(caption)caption.textContent=slice?slice.percent.toFixed(1)+'% | '+formatN(slice.count)+' PKT':'PACCHETTI';
  document.querySelectorAll('.nc28-donut-sector').forEach(el=>{
    const selected=!!active&&el.dataset.proto===active;
    el.classList.toggle('is-highlight',selected);
    el.classList.toggle('is-muted',!!active&&!selected);
    el.setAttribute('aria-pressed',String(nc28ProtoUI.pinned===el.dataset.proto));
  });
  document.querySelectorAll('#donutLegend .donut-legend-row').forEach(el=>{
    const selected=!!active&&el.dataset.proto===active;
    el.classList.toggle('is-highlight',selected);
    el.classList.toggle('is-muted',!!active&&!selected);
    el.setAttribute('aria-pressed',String(nc28ProtoUI.pinned===el.dataset.proto));
    el.title='Seleziona '+el.dataset.proto+'; usa Apri in Esplora rete per filtrare la mappa';
  });
  if(cta){cta.hidden=!nc28ProtoUI.pinned;cta.setAttribute('aria-label',nc28ProtoUI.pinned==='OTHER'?'Apri tutti i protocolli in Esplora rete':nc28ProtoUI.pinned?'Apri '+nc28ProtoUI.pinned+' in Esplora rete':'Apri il protocollo in Esplora rete');}
}
function nc28Transient(proto,event,mode){
  if(mode==='focus')nc28ProtoUI.focused=proto;
  else nc28ProtoUI.hover=proto;
  nc28RefreshSelection();
  if(proto)nc28ShowTooltip(proto,event);
  else nc28HideTooltip();
}
function nc28TogglePinned(proto,event){
  const wasPinned=nc28ProtoUI.pinned===proto;
  nc28ProtoUI.pinned=wasPinned?null:proto;
  if(wasPinned){nc28ProtoUI.hover=null;nc28ProtoUI.focused=null;}
  // A tap/click pins the sector; the original view-switch action remains via CTA.
  if(event?.pointerType==='touch'||event?.pointerType==='pen')nc28ProtoUI.hover=null;
  nc28RefreshSelection();
  if(nc28ProtoUI.pinned)nc28ShowTooltip(nc28ProtoUI.pinned,event);
  else nc28HideTooltip();
}
function nc28WireSector(el,proto){
  el.addEventListener('pointerenter',event=>{if(event.pointerType==='mouse')nc28Transient(proto,event,'hover');});
  el.addEventListener('pointermove',event=>{if(event.pointerType==='mouse')nc28PositionTooltip(event.clientX,event.clientY);});
  el.addEventListener('pointerleave',()=>{nc28ProtoUI.hover=null;nc28RefreshSelection();nc28HideTooltip();});
  el.addEventListener('focus',event=>nc28Transient(proto,event,'focus'));
  el.addEventListener('blur',()=>{nc28ProtoUI.focused=null;nc28RefreshSelection();nc28HideTooltip();});
  el.addEventListener('click',event=>nc28TogglePinned(proto,event));
  el.addEventListener('keydown',event=>{
    if(event.key==='Enter'||event.key===' '){event.preventDefault();nc28TogglePinned(proto,event);}
    if(event.key==='Escape'){event.preventDefault();nc28ProtoUI.pinned=null;nc28ProtoUI.focused=null;nc28ProtoUI.hover=null;nc28RefreshSelection();nc28HideTooltip();}
  });
}
function nc28RenderInteractiveDonut(){
  const svg=document.getElementById('nc28DonutSegments'),legend=document.getElementById('donutLegend'),chart=document.getElementById('donutChart'),cta=document.getElementById('nc28ExploreSelected');
  if(!svg||!legend||!chart)return;
  // Use the same top-five/OTHER segmentation as the existing dashboard.
  const stats=ncProtocolStats(),top=stats.slice(0,5),other=stats.slice(5).reduce((sum,p)=>sum+p[1],0);
  const rows=[...top,...(other?[['OTHER',other]]:[])];
  const total=state.packets.length;
  const generation=state.captureGeneration;
  const signature=rows.map(([p,n])=>p+':'+n).join('|')+':'+total;
  if(nc28ProtoUI.generation!==generation || nc28ProtoUI.signature!==signature){nc28ProtoUI.hover=null;nc28ProtoUI.pinned=null;nc28ProtoUI.focused=null;nc28HideTooltip();}
  nc28ProtoUI.generation=generation;nc28ProtoUI.signature=signature;
  nc28ProtoUI.slices=rows.map(([proto,count])=>({proto,count,percent:100*count/Math.max(1,total)}));
  chart.style.background='transparent';
  svg.replaceChildren();
  const track=document.createElementNS(nc28SvgNS,'circle');track.setAttribute('class','nc28-donut-track');track.setAttribute('cx','100');track.setAttribute('cy','100');track.setAttribute('r',String(nc28DonutR));svg.append(track);
  let acc=0;
  for(const slice of nc28ProtoUI.slices){
    const circle=document.createElementNS(nc28SvgNS,'circle');
    circle.setAttribute('class','nc28-donut-sector');circle.setAttribute('cx','100');circle.setAttribute('cy','100');circle.setAttribute('r',String(nc28DonutR));
    const length=nc28DonutC*slice.percent/100;
    // A28.1: a symmetric seam leaves a precise gap between sectors, including
    // the closing OTHER -> first-protocol boundary. All strokes stay 29px wide.
    const seam=Math.min(1.3,length*.14);
    const visibleLength=Math.max(.01,length-seam);
    circle.setAttribute('stroke-dasharray',visibleLength+' '+(nc28DonutC-visibleLength));
    circle.setAttribute('stroke-dashoffset',String(-nc28DonutC*acc/100-seam/2));
    circle.setAttribute('transform','rotate(-90 100 100)');
    circle.style.stroke=colorOf(slice.proto);
    circle.style.setProperty('--nc28-sector-color',colorOf(slice.proto));
    circle.dataset.proto=slice.proto;
    circle.setAttribute('role','button');circle.setAttribute('tabindex','0');
    circle.setAttribute('aria-label',slice.proto+': '+formatN(slice.count)+' pacchetti, '+slice.percent.toFixed(1)+' per cento');
    circle.setAttribute('aria-pressed','false');
    nc28WireSector(circle,slice.proto);svg.append(circle);acc+=slice.percent;
  }
  legend.querySelectorAll('.donut-legend-row').forEach(row=>{
    const proto=row.dataset.proto,slice=nc28Slice(proto);if(!slice)return;
    row.setAttribute('aria-label',slice.proto+': '+formatN(slice.count)+' pacchetti, '+slice.percent.toFixed(1)+' per cento. Seleziona per visualizzare i dettagli.');
    row.setAttribute('aria-pressed','false');
    row.onclick=null;
    // Replaces the legacy direct-jump click but preserves navigation in the CTA.
    nc28WireSector(row,proto);
  });
  if(cta){cta.onclick=()=>{
    if(!nc28ProtoUI.pinned)return;
    state.filter=nc28ProtoUI.pinned==='OTHER'?'ALL':nc28ProtoUI.pinned;renderProtocolFilters();setPage('explorer');updateSnapshot(true);drawGraph();nc28HideTooltip();
  };}
  nc28RefreshSelection();
}
// The original dashboard still calculates all KPIs, bars, talkers and context.
// Replace only the donut visualization, and retain source-derived counts.
const nc28PreviousRunDashboard=ncRunDashboard;
ncRunDashboard=function(...args){const result=nc28PreviousRunDashboard(...args);nc28RenderInteractiveDonut();return result;};
window.addEventListener('scroll',nc28HideTooltip,true);
/* A28.1 — A click outside a protocol sector/legend item returns to the full
 * packet total. This is intentionally independent of navigation and runs for
 * touch and mouse; a click in the donut hole also clears the selection. */
document.addEventListener('pointerdown',event=>{
  const target=event.target;
  if(target?.closest?.('.nc28-donut-sector, #donutLegend .donut-legend-row, #nc28ExploreSelected'))return;
  if(!nc28ProtoUI.pinned&&!nc28ProtoUI.hover&&!nc28ProtoUI.focused)return;
  nc28ProtoUI.pinned=null;
  nc28ProtoUI.hover=null;
  nc28ProtoUI.focused=null;
  const focused=document.activeElement;
  if(focused?.matches?.('.nc28-donut-sector, #donutLegend .donut-legend-row'))focused.blur();
  nc28HideTooltip();
  nc28RefreshSelection();
},true);
