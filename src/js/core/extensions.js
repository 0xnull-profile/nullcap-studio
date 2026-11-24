'use strict';
/* NullCap Studio 2.0 · 5-view investigation studio · client-side only */

PAGE_DESCRIPTIONS.overview = [
  'Homepage',
  'La cattura, <em>in un colpo d’occhio.</em>',
  'Indicatori, protocolli, protagonisti e andamento del traffico: la situazione in pochi secondi.'
];
PAGE_DESCRIPTIONS.loot = [
  'Bottino',
  'Le evidenze, <em>riportate alla luce.</em>',
  'Immagini, file, messaggi, contenuti API e audio ricostruibili dal traffico non cifrato.'
];
PAGE_DESCRIPTIONS.explorer = [
  'Esplora rete',
  'Ogni connessione ha <em>una storia.</em>',
  'Una mappa radiale che nasce con la cattura. Isola un evento, esplora il contesto, approfondisci.'
];
PAGE_DESCRIPTIONS.packets = [
  'Pacchetti',
  'Il dettaglio fa <em>la differenza.</em>',
  'Dal timestamp fino al singolo byte: traccia, filtra e ispeziona ogni frame.'
];
PAGE_DESCRIPTIONS.flows = [
  'Conversazioni',
  'Segui il filo <em>delle comunicazioni.</em>',
  'Ricostruisci il contesto degli scambi bidirezionali tra endpoint e porte.'
];
state.loot=[];
state.lootStatus='idle';
state.lootKind='ALL';
state.lootSearch='';
state.lootShowSecondary=false;
state.selectedLoot=null;
state.graphQuery='';
state.quickPacket=null;
state.timelineSelection=null;
state.audioURLs=[];
state.captureGeneration=0;

/* -------- The original ChronoWire radial force graph, with time-gated snapshots -------- */
function ncLayoutRadial(){
  const nodes=(typeof nc32GraphVisibleHostList==='function'?nc32GraphVisibleHostList():state.hosts.slice(0,MAX_HOSTS_GRAPH)),index=new Map(nodes.map((n,i)=>[n.id,i]));
  const edges=state.links.filter(e=>index.has(e.a)&&index.has(e.b));
  if(!nodes.length)return;
  const n=nodes.length, xs=[],ys=[];
  for(let i=0;i<n;i++){
    const phi=i*2.399963229728653,r=i===0?0:112+Math.sqrt(i/Math.max(1,n))*240;
    xs.push(Math.cos(phi)*r);ys.push(Math.sin(phi)*r*.76);
  }
  const fx=new Float64Array(n),fy=new Float64Array(n);
  const springs=edges.map(e=>({a:index.get(e.a),b:index.get(e.b),strength:Math.min(1,Math.sqrt(e.count)/10)}));
  const iterations=n>45?130:260;
  for(let it=0;it<iterations;it++){
    const cool=.54*(1-it/iterations)+.10;
    for(let i=0;i<n;i++)for(let j=i+1;j<n;j++){
      let dx=xs[i]-xs[j],dy=ys[i]-ys[j],d2=dx*dx+dy*dy+110;
      const d=Math.sqrt(d2),rep=3400/d2;
      fx[i]+=dx/d*rep;fy[i]+=dy/d*rep;fx[j]-=dx/d*rep;fy[j]-=dy/d*rep;
    }
    for(const e of springs){
      const i=e.a,j=e.b,dx=xs[j]-xs[i],dy=ys[j]-ys[i],d=Math.max(2,Math.hypot(dx,dy));
      const target=126+(1-e.strength)*72,pull=(d-target)*.0024*(.65+e.strength);
      fx[i]+=dx/d*pull;fy[i]+=dy/d*pull;fx[j]-=dx/d*pull;fy[j]-=dy/d*pull;
    }
    for(let i=0;i<n;i++){
      fx[i]-=xs[i]*.0015;fy[i]-=ys[i]*.0017;fx[i]*=.82;fy[i]*=.82;
      xs[i]=Math.max(-420,Math.min(420,xs[i]+Math.max(-6,Math.min(6,fx[i]))*cool));
      ys[i]=Math.max(-230,Math.min(230,ys[i]+Math.max(-6,Math.min(6,fy[i]))*cool));
    }
  }
  const meanX=xs.reduce((a,b)=>a+b,0)/n,meanY=ys.reduce((a,b)=>a+b,0)/n;
  nodes.forEach((h,i)=>{h.x=xs[i]-meanX;h.y=ys[i]-meanY;h.r=Math.max(7,Math.min(16,6+Math.log2(h.count+1)*1.05));});
}
const ncOriginalIndex=indexCapture;
indexCapture=function(){ncOriginalIndex();ncLayoutRadial();};
function ncGraphScale(){
  return Math.max(.13,Math.min((state.graphSize.w-64)/860,(state.graphSize.h-68)/470))*state.graphZoom;
}
function ncNodePoint(n){
  // The original packet-window snapshot contains copies of the hosts. Positions are
  // intentionally read from the canonical host map: nodes, edges, hit targets and
  // moving packets must all use identical live coordinates while dragging.
  const live=state.hostMap.get(n.id)||n;
  const k=ncGraphScale();
  return {x:state.graphSize.w/2+state.graphPan.x+live.x*k,y:state.graphSize.h/2+state.graphPan.y+live.y*k};
}
function ncHighlighted(n){
  const q=state.graphQuery;if(q&&!(n.id.toLowerCase().includes(q)||n.label.toLowerCase().includes(q)))return false;
  const sel=state.selected;
  if(sel.type==='node')return n.id===sel.id||state.snapshot.edges.some(e=>(e.a===n.id&&e.b===sel.id)||(e.b===n.id&&e.a===sel.id));
  if(sel.type==='edge'){let e=state.snapshot.edgeMap.get(sel.id);return e&&(e.a===n.id||e.b===n.id);}
  return true;
}
const ncOriginalDrawGraph=drawGraph;
drawGraph=function(now=performance.now()){
  const canvas=$('graphCanvas');if(!canvas)return;
  const ctx=canvas.getContext('2d'),{w,h}=state.graphSize;
  if(!w||!h)return;ctx.clearRect(0,0,w,h);
  const snapshot=state.snapshot,selected=state.selected,hover=state.graphHover;
  let pointById=new Map(snapshot.nodes.map(n=>[n.id,ncNodePoint(n)]));
  const activeSelected=selected.type==='node'||selected.type==='edge';
  const highlightIds=new Set();
  if(selected.type==='node')highlightIds.add(selected.id);
  if(selected.type==='edge'){let e=snapshot.edgeMap.get(selected.id);if(e){highlightIds.add(e.a);highlightIds.add(e.b);}}
  // Edges are straight and deliberately subdued as in the first ChronoWire map.
  for(const e of snapshot.edges){
    const a=pointById.get(e.a),b=pointById.get(e.b);if(!a||!b)continue;
    const isSelected=selected.type==='edge'&&selected.id===e.id;
    const isHovered=hover?.type==='edge'&&hover.id===e.id;
    const related=selected.type!=='node'||selected.id===e.a||selected.id===e.b;
    const searchOkay=!state.graphQuery||[e.a,e.b].some(id=>{
      const node=state.hostMap.get(id);return id.toLowerCase().includes(state.graphQuery)||node?.label?.toLowerCase().includes(state.graphQuery);
    });
    const fade=(!related&&activeSelected)||!searchOkay;
    const width=Math.max(1.05,Math.min(3.7,1+Math.log2(e.count+1)*.40));
    ctx.save();ctx.globalAlpha=fade?.11:1;
    if(isSelected||isHovered){ctx.shadowBlur=13;ctx.shadowColor=colorOf(dominantProto(e.protos));}
    ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);
    ctx.strokeStyle=isSelected||isHovered?'#86f4dc':'rgba(103,156,186,.46)';
    ctx.lineWidth=isSelected?width+2.2:isHovered?width+1.1:width;
    ctx.stroke();ctx.restore();
  }
  const t=now||performance.now();
  state.pulses=state.pulses.filter(x=>t-x.created<1100);
  for(const pulse of state.pulses){
    const a=pointById.get(pulse.p.src),b=pointById.get(pulse.p.dst);
    if(!a||!b)continue;
    const u=Math.max(0,Math.min(1,(t-pulse.created)/950)),x=a.x+(b.x-a.x)*u,y=a.y+(b.y-a.y)*u,col=colorOf(pulse.p.protocol);
    ctx.save();const gl=ctx.createRadialGradient(x,y,0,x,y,16);gl.addColorStop(0,rgba(col,.76));gl.addColorStop(1,rgba(col,0));ctx.fillStyle=gl;ctx.beginPath();ctx.arc(x,y,16,0,Math.PI*2);ctx.fill();ctx.beginPath();ctx.arc(x,y,3.1,0,Math.PI*2);ctx.fillStyle='#edfffc';ctx.fill();ctx.restore();
  }
  // Labels prefer the position below their node, with simple collision avoidance.
  let occupied=[];
  const drawNodes=snapshot.nodes.slice().sort((a,b)=>b.count-a.count);
  for(const n of drawNodes){
    const p=pointById.get(n.id),col=n.local?'#6fece2':'#b3a0ff';
    const rad=Math.max(6.2,Math.min(15.5,n.r*ncGraphScale()*.9+3.5));
    const focused=highlightIds.has(n.id),hovered=hover?.type==='node'&&hover.id===n.id;
    const fade=(activeSelected&&!ncHighlighted(n))||(state.graphQuery&&!ncHighlighted(n));
    ctx.save();ctx.globalAlpha=fade?.22:1;
    const halo=ctx.createRadialGradient(p.x,p.y,0,p.x,p.y,rad*2.65);
    halo.addColorStop(0,rgba(col,focused||hovered?.26:.18));halo.addColorStop(1,rgba(col,0));
    ctx.fillStyle=halo;ctx.beginPath();ctx.arc(p.x,p.y,rad*2.65,0,Math.PI*2);ctx.fill();
    if(focused||hovered){ctx.beginPath();ctx.arc(p.x,p.y,rad+5,0,Math.PI*2);ctx.strokeStyle=rgba(col,.8);ctx.lineWidth=1.4;ctx.stroke();}
    ctx.beginPath();ctx.arc(p.x,p.y,rad,0,Math.PI*2);ctx.fillStyle='#102c38';ctx.fill();ctx.strokeStyle=col;ctx.lineWidth=2;ctx.stroke();
    ctx.beginPath();ctx.arc(p.x,p.y,Math.max(2.9,rad*.48),0,Math.PI*2);ctx.fillStyle=col;ctx.fill();
    ctx.beginPath();ctx.arc(p.x,p.y,Math.max(1.4,rad*.21),0,Math.PI*2);ctx.fillStyle='#f2fffe';ctx.fill();
    // Human-defined identities are prioritized and shown above the node. The IP is
    // retained below a named host on hover/selection, so labels never hide evidence.
    const live=state.hostMap.get(n.id)||n;
    const named=Boolean(live.customLabel);
    let canLabel=snapshot.nodes.length<=25||drawNodes.indexOf(n)<22||focused||hovered||named;
    if(canLabel){
      const fs=w<550?9:10;
      ctx.font=`${named?700:620} ${fs}px Inter,system-ui,sans-serif`;
      const fullLabel=named?live.customLabel:shortAddr(n.id);
      let label=fullLabel;
      while(label.length>3&&ctx.measureText(label).width>Math.min(168,w*.37))label=label.slice(0,-2)+'…';
      const tw=ctx.measureText(label).width;
      let tx=Math.max(8,Math.min(w-tw-8,p.x-tw/2));
      const candidates=[p.y-rad-fs-11,p.y+rad+9];
      let ty=candidates.find(y=>y>30&&y<h-30&&!occupied.some(o=>tx<o.x+o.w+10&&tx+tw+10>o.x&&y<o.y+o.h+5&&y+fs+6>o.y));
      if(ty===undefined&&(focused||hovered||named))ty=Math.max(31,Math.min(h-31,p.y-rad-fs-11));
      if(ty!==undefined){
        if(named){
          ctx.fillStyle=focused?'rgba(35,98,97,.91)':'rgba(10,30,45,.86)';
          ctx.strokeStyle=focused?'rgba(121,246,223,.64)':'rgba(112,206,197,.29)';
          ctx.lineWidth=1;ctx.beginPath();ctx.roundRect(tx-7,ty-4,tw+14,fs+9,6);ctx.fill();ctx.stroke();
        }
        ctx.fillStyle=fade?'#67869d':focused||hovered?'#f1fffc':named?'#b2fff1':'#c8dbea';
        ctx.textAlign='left';ctx.textBaseline='top';ctx.fillText(label,tx,ty);
        occupied.push({x:tx-7,y:ty-4,w:tw+14,h:fs+10});
      }
      if(named&&(focused||hovered)){
        const ip=shortAddr(n.id);ctx.font='500 9px ui-monospace, Consolas, monospace';
        ctx.textAlign='center';ctx.fillStyle='#93abc0';ctx.fillText(ip,p.x,p.y+rad+9);
      }
    }
    ctx.restore();
  }
};
graphHitAt=function(x,y){
  for(let i=state.snapshot.nodes.length-1;i>=0;i--){const n=state.snapshot.nodes[i],p=ncNodePoint(n),r=Math.max(10,Math.min(20,n.r*ncGraphScale()+8));if(Math.hypot(x-p.x,y-p.y)<r)return {type:'node',id:n.id};}
  let best=null,dist=12;for(const e of state.snapshot.edges){const a=ncNodePoint(state.hostMap.get(e.a)),b=ncNodePoint(state.hostMap.get(e.b)),dx=b.x-a.x,dy=b.y-a.y;
    const t=Math.max(0,Math.min(1,((x-a.x)*dx+(y-a.y)*dy)/(dx*dx+dy*dy||1)));
    const d=Math.hypot(x-(a.x+dx*t),y-(a.y+dy*t));if(d<dist){best={type:'edge',id:e.id};dist=d;}}
  return best;
};
onGraphPointerMove=function(e){
  const r=$('graphCanvas').getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;
  const p=state.graphPointer;
  if(p&&(e.buttons||e.pointerType==='touch')){
    if(Math.hypot(x-p.x,y-p.y)>3)p.dragged=true;
    if(p.dragged){
      if(p.hit?.type==='node'){
        let node=state.hostMap.get(p.hit.id);if(node){
          if(!p.baseNode)p.baseNode={x:node.x,y:node.y};
          const scale=ncGraphScale();node.x=p.baseNode.x+(x-p.x)/scale;node.y=p.baseNode.y+(y-p.y)/scale;
        }
      }else{state.graphPan.x=p.baseX+x-p.x;state.graphPan.y=p.baseY+y-p.y;}
      $('graphCanvas').style.cursor='grabbing';drawGraph();return;
    }
  }
  const hit=graphHitAt(x,y);
  if(hit?.type!==state.graphHover?.type||hit?.id!==state.graphHover?.id){state.graphHover=hit;drawGraph();}
  graphTooltip(hit,x,y);$('graphCanvas').style.cursor=hit?'pointer':'grab';
};
const ncOriginalOnGraphClick=onGraphClick;
onGraphClick=function(hit){state.quickPacket=null;ncOriginalOnGraphClick(hit);};
const ncOriginalRenderFocus=renderFocus;
renderFocus=function(){
  if(state.page!=='explorer')return;
  const p=state.quickPacket;
  if(!p)return ncOriginalRenderFocus();
  const raw=p.raw||new Uint8Array(0),preview=Array.from(raw.slice(0,56),b=>b.toString(16).padStart(2,'0')).join(' ');
  $('focusContent').innerHTML=`<div class="focus-hero"><div class="focus-eyebrow">ISPEZIONE RAPIDA · FRAME #${p.id}<span class="live-dot"></span></div><h3>${escapeHtml(p.protocol)} · ${escapeHtml(p.info||'Frame acquisito')}</h3><p class="mono">${escapeHtml(p.src)}:${p.srcPort||'—'} → ${escapeHtml(p.dst)}:${p.dstPort||'—'}</p></div>
  <div class="quick-meta"><div><small>TIMESTAMP RELATIVO</small><strong>${formatTime(p.rel,true)}</strong></div><div><small>DIMENSIONE</small><strong>${formatBytes(p.length)}</strong></div><div><small>TRASPORTO</small><strong>${escapeHtml(p.transport)}</strong></div><div><small>TCP FLAGS</small><strong>${escapeHtml(p.flags||'—')}</strong></div></div>
  <div class="quick-title">ANTEPRIMA ESAD. <span>PRIMI ${Math.min(56,raw.length)} BYTE</span></div><div class="quick-hex">${escapeHtml(preview||'Byte non disponibili')}</div>
  <button class="quick-button" id="quickDeepInspect">Apri Packet Inspector completo ${ncIcon("arrow-right")}</button><button class="text-button" id="quickBack">${ncIcon("arrow-left")} Torna al contesto</button>`;
  $('quickDeepInspect').onclick=()=>openPacketById(p.id);
  $('quickBack').onclick=()=>{state.quickPacket=null;renderFocus();};
};
function ncQuickPacket(p){state.selected={type:null,id:null};state.quickPacket=p;renderFocus();drawGraph();}
const ncOriginalRenderActivities=renderActivities;
renderActivities=function(){ncOriginalRenderActivities();if(state.page!=='explorer')return;
  $('activityList').querySelectorAll('[data-event]').forEach(b=>{
    b.onclick=()=>ncQuickPacket(state.packets[Number(b.dataset.event)-1]);
    b.ondblclick=()=>openPacketById(Number(b.dataset.event));
  });
};
const ncOriginalUpdateSnapshot=updateSnapshot;
updateSnapshot=function(force=false){ncOriginalUpdateSnapshot(force);};

/* -------- Homepage charts computed solely from capture data -------- */
function ncProtocolStats(){const map=new Map();for(const p of state.packets)map.set(p.protocol,(map.get(p.protocol)||0)+1);return [...map].sort((a,b)=>b[1]-a[1]);}
function ncRunDashboard(){
  const packets=state.packets,total=packets.length,bytes=state.bytes,protos=ncProtocolStats();
  $('dashPackets').textContent=formatN(total);$('dashBytes').textContent=formatBytes(bytes);
  $('dashHosts').textContent=formatN(state.hosts.length);$('dashRemote').textContent=formatN(state.hosts.filter(h=>!h.local).length);
  $('dashFlows').textContent=formatN(state.flows.length);$('dashTopProtocol').textContent=protos[0]?.[0]||'—';
  $('dashDuration').textContent=state.undatedCount===state.packets.length?'N/D':formatTime(state.duration);$('dashPPS').textContent=(total/Math.max(1,state.duration)).toFixed(1);
  $('dashTrafficLabel').textContent=state.duration>0?formatTime(state.duration)+' · 20 BLOCCHI':'CATTURA ISTANTANEA';
  let counts=Array(20).fill(0),volumes=Array(20).fill(0);const duration=Math.max(.001,state.duration);
  for(const p of packets){if(!Number.isFinite(p.rel))continue;let idx=Math.min(19,Math.floor(p.rel/duration*20));counts[idx]++;volumes[idx]+=p.length;}
  const max=Math.max(1,...counts);
  $('trafficBars').innerHTML=counts.map((n,i)=>`<button class="traffic-column" style="--bar-height:${Math.max(2,n/max*95)}%" data-index="${i}" data-count="${n}" title="${formatTime(i/20*duration)} – ${formatTime((i+1)/20*duration,true)}: ${n} pacchetti · ${formatBytes(volumes[i])}" aria-label="Intervallo ${i+1}: ${n} pacchetti"></button>`).join('');
  $('trafficBars').querySelectorAll('button').forEach(b=>b.onclick=()=>{
    let i=+b.dataset.index;state.mode='cumulative';document.querySelectorAll('[data-mode]').forEach(x=>x.classList.toggle('is-selected',x.dataset.mode==='cumulative'));
    setPlayhead((i+1)/20*duration);setPage('explorer');
  });
  $('trafficAxis').innerHTML=`<span>00:00</span><span>${formatTime(duration*.25)}</span><span>${formatTime(duration*.5)}</span><span>${formatTime(duration*.75)}</span><span>${formatTime(duration)}</span>`;
  const top=protos.slice(0,5),other=protos.slice(5).reduce((n,e)=>n+e[1],0),slices=[...top,...(other?[['OTHER',other]]:[])],conic=[];let current=0;
  for(const [proto,num] of slices){const next=current+num/Math.max(1,total)*100;conic.push(`${colorOf(proto)} ${current.toFixed(2)}% ${next.toFixed(2)}%`);current=next;}
  $('donutChart').style.background=conic.length?`conic-gradient(${conic.join(',')})`:'conic-gradient(#1c3347 0 100%)';
  $('donutTotal').textContent=formatN(total);
  $('donutLegend').innerHTML=slices.map(([proto,n])=>`<button class="donut-legend-row" data-proto="${proto}" style="--segment:${colorOf(proto)}" title="Filtra ${escapeHtml(proto)} nella mappa"><i></i><span>${escapeHtml(proto)}</span><strong>${(100*n/Math.max(1,total)).toFixed(1)}%</strong></button>`).join('');
  $('donutLegend').querySelectorAll('button').forEach(b=>b.onclick=()=>{
    state.filter=b.dataset.proto;renderProtocolFilters();setPage('explorer');updateSnapshot(true);drawGraph();
  });
  const leaders=state.hosts.slice(0,5);const topBytes=Math.max(1,leaders[0]?.bytes||0);
  $('dashTalkers').innerHTML=leaders.map((h,i)=>`<button class="talker-row" data-host="${escapeHtml(h.id)}"><span class="talker-rank">${String(i+1).padStart(2,'0')}</span><span class="talker-data"><span class="talker-name">${escapeHtml(h.label)}</span><span class="talker-sub">${escapeHtml(h.id)} · ${h.local?'RETE LOCALE':'ENDPOINT ESTERNO'}</span><span class="talker-track"><i class="talker-fill" style="width:${(100*h.bytes/topBytes).toFixed(1)}%"></i></span></span><span class="talker-volume">${formatBytes(h.bytes)}</span></button>`).join('');
  $('dashTalkers').querySelectorAll('button').forEach(b=>b.onclick=()=>ncGoToHost(b.dataset.host));
  const tls=packets.filter(p=>['TLS','QUIC','SSH'].includes(p.protocol)).length;
  const topRemote=state.hosts.filter(h=>!h.local).length;
  const peak=Math.max(...counts),peakIndex=counts.indexOf(peak);
  const items=[
    {icon:'lock-keyhole',title:'Traffico su servizi cifrati',text:'Classificazione per protocollo/porta; non implica cifratura verificata del payload.',value:`${(100*tls/Math.max(1,total)).toFixed(1)}%`},
    {icon:'server',title:'Endpoint esterni individuati',text:'Indirizzi non appartenenti alle principali reti private.',value:formatN(topRemote)},
    {icon:'calendar-clock',title:'Intervallo più trafficato',text:`Da ${formatTime(peakIndex/20*duration,true)} a ${formatTime((peakIndex+1)/20*duration,true)}`,value:`${formatN(peak)} pkt`},
    {icon:'vault',title:'Dati estratti',text:'Evidenze rilevanti, elementi secondari consultabili nel Bottino.',value:formatN(state.loot.filter(x=>!x.secondary).length)}
  ];
  $('dashInsights').innerHTML=items.map(e=>`<div class="insight-item"><span class="insight-icon">${ncIcon(e.icon)}</span><span class="insight-body"><b>${escapeHtml(e.title)}</b><span>${escapeHtml(e.text)}</span></span><strong class="insight-value">${escapeHtml(e.value)}</strong></div>`).join('');
}
function ncGoToHost(host){
  const h=state.hostMap.get(host);if(!h)return;
  state.mode='cumulative';document.querySelectorAll('[data-mode]').forEach(x=>x.classList.toggle('is-selected',x.dataset.mode==='cumulative'));
  state.filter='ALL';renderProtocolFilters();setPlayhead(Math.min(state.duration,h.last+.001));
  state.quickPacket=null;state.selected={type:'node',id:host};setPage('explorer');renderFocus();drawGraph();
}

/* -------- Editor-style timeline: Shift-drag range selection -------- */
const ncOriginalDrawTimeline=drawTimeline;
drawTimeline=function(){ncOriginalDrawTimeline();const select=state.timelineSelection;if(!select)return;
 const canvas=$('timelineCanvas'),{w,h}=state.timelineSize;if(!w||!h)return;
 const ctx=canvas.getContext('2d'),x1=select.start/Math.max(.001,state.duration)*w,x2=select.end/Math.max(.001,state.duration)*w;
 const left=Math.min(x1,x2),right=Math.max(x1,x2);
 ctx.save();ctx.fillStyle='rgba(103,236,210,.115)';ctx.fillRect(left,0,Math.max(2,right-left),h);
 ctx.strokeStyle='#85f7e0';ctx.lineWidth=1.4;
 for(const x of [left,right]){ctx.beginPath();ctx.moveTo(x+.5,0);ctx.lineTo(x+.5,h);ctx.stroke();}
 ctx.restore();
};
function ncSelectTimeAt(e){const rect=$('timelineCanvas').getBoundingClientRect(),x=Math.max(0,Math.min(rect.width,e.clientX-rect.left));return rect.width?x/rect.width*state.duration:0;}
function ncUpdateTimelineSelection(){const sel=state.timelineSelection,valid=sel&&Math.abs(sel.end-sel.start)>.025;
 $('clearTimelineSelection').classList.toggle('hidden',!sel);
 $('analyzeTimelineSelection').classList.toggle('hidden',!valid);
 if(valid)$('analyzeTimelineSelection').innerHTML=`Analizza ${formatTime(Math.abs(sel.end-sel.start),true)} ${ncIcon('arrow-right')}`;
 drawTimeline();
}

/* Page lifecycle: charts & artifact gallery share the same capture, timeline only in Explorer. */
const ncOriginalSetPage=setPage;
setPage=function(page,resetScroll=true){
  ncOriginalSetPage(page,resetScroll);
  document.body.dataset.page=state.page;
  if(state.page==='overview')ncRunDashboard();
  if(state.page==='loot')ncRenderLoot();
  if(state.page==='explorer'){resizeTimeline();drawGraph();}
};
const ncOriginalRenderAll=renderAll;
renderAll=function(fit=false){ncOriginalRenderAll(fit);ncRunDashboard();if(state.page==='loot')ncRenderLoot();};
const ncOriginalApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  state.captureGeneration++;
  state.quickPacket=null;state.graphQuery='';state.timelineSelection=null;
  if($('graphSearch'))$('graphSearch').value='';
  ncRevokeLootURLs();state.loot=[];state.lootNextId=0;state.lootLowAccepted=0;state.lootNotIndexed=0;state.httpEvents=[];state.selectedLoot=null;state.lootKind='ALL';state.lootSearch='';state.lootShowSecondary=false;state.lootStatus='scanning';
  if($('lootSearch'))$('lootSearch').value='';
  ncOriginalApplyCapture(packets,options);
  ncUpdateTimelineSelection();
  setPage('overview');
  ncExtractLoot(state.captureGeneration);
};
const ncOriginalWireUI=wireUI;
wireUI=function(){
  ncOriginalWireUI();
  $('graphSearch').addEventListener('input',e=>{state.graphQuery=e.target.value.trim().toLowerCase();drawGraph();});
  $('dashToExplorer').onclick=()=>{state.filter='ALL';renderProtocolFilters();setPage('explorer');};
  $('lootSearch').oninput=e=>{state.lootSearch=e.target.value.trim().toLowerCase();ncRenderLoot();};
  $('lootShowSecondary').onchange=e=>{state.lootShowSecondary=e.target.checked;ncRenderLoot();};
  $('lootTabs').querySelectorAll('[data-loot-kind]').forEach(b=>b.onclick=()=>{state.lootKind=b.dataset.lootKind;ncRenderLoot();});
  $('clearTimelineSelection').onclick=()=>{state.timelineSelection=null;ncUpdateTimelineSelection();};
  $('analyzeTimelineSelection').onclick=()=>{
    const s=state.timelineSelection;if(!s)return;
    openPacketScope({type:'time',start:Math.min(s.start,s.end),end:Math.max(s.start,s.end)});
  };
  const timeCanvas=$('timelineCanvas');
  timeCanvas.addEventListener('pointerdown',e=>{
    if(!e.shiftKey)return;
    e.preventDefault();e.stopImmediatePropagation();
    pauseReplay();let at=ncSelectTimeAt(e);state.timelineSelection={start:at,end:at,dragging:true};
    timeCanvas.setPointerCapture(e.pointerId);ncUpdateTimelineSelection();
  },true);
  timeCanvas.addEventListener('pointermove',e=>{
    if(!state.timelineSelection?.dragging)return;
    e.preventDefault();e.stopImmediatePropagation();state.timelineSelection.end=ncSelectTimeAt(e);ncUpdateTimelineSelection();
  },true);
  const endSelect=e=>{
    if(!state.timelineSelection?.dragging)return;
    e.preventDefault();e.stopImmediatePropagation();state.timelineSelection.dragging=false;
    ncUpdateTimelineSelection();
  };
  timeCanvas.addEventListener('pointerup',endSelect,true);timeCanvas.addEventListener('pointercancel',endSelect,true);
  $('timelineViewport').addEventListener('wheel',e=>{
    if(!e.ctrlKey&&!e.altKey)return;
    e.preventDefault();
    let zoom=state.timelineZoom*(e.deltaY<0?1.2:1/1.2);
    state.timelineZoom=Math.max(1,Math.min(12,zoom));$('timelineZoom').value=state.timelineZoom.toFixed(2);resizeTimeline();
  },{passive:false});
  document.addEventListener('keydown',e=>{if(e.code==='Escape'&&state.timelineSelection){state.timelineSelection=null;ncUpdateTimelineSelection();}},true);
  document.body.dataset.page='overview';
};
