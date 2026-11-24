'use strict';
/* NullCap Studio 3.2 — Deep Analysis. Offline, native frames only. */

/* Extended graph visibility: cap remains 75, but a pinned or subnet host does not
   silently disappear behind the global top-by-volume ranking. */
state.nc32Pinned=new Set();
state.nc32Subnet='ALL';
state.nc32TimelineMetric='packets';
state.nc32ImportRun=null;
function nc32SubnetOf(ip){
  if(RX_IPV4.test(ip)){const a=ip.split('.').map(Number);if(a.length===4&&a.every(x=>x>=0&&x<=255))return a.slice(0,3).join('.')+'.0/24';}
  if(ip.includes(':'))return 'IPv6 (subnet non determinata)';
  return 'Altri endpoint';
}
function nc32GraphVisibleHostList(){
  const pool=state.nc32Subnet==='ALL'?state.hosts:state.hosts.filter(h=>nc32SubnetOf(h.id)===state.nc32Subnet);
  const pinned=pool.filter(h=>state.nc32Pinned.has(h.id));
  const rest=pool.filter(h=>!state.nc32Pinned.has(h.id));
  return [...pinned,...rest].slice(0,MAX_HOSTS_GRAPH);
}
function nc32GraphVisibleIds(){return new Set(nc32GraphVisibleHostList().map(h=>h.id));}
function nc32SubnetOptions(){
  let counts=new Map();for(const h of state.hosts){const subnet=nc32SubnetOf(h.id);counts.set(subnet,(counts.get(subnet)||0)+1);}
  const el=$('nc32Subnet'),values=[...counts].sort((a,b)=>b[1]-a[1]);
  el.innerHTML='<option value="ALL">Tutte le reti ('+state.hosts.length+')</option>'+values.map(([name,n])=>`<option value="${escapeHtml(name)}">${escapeHtml(name)} (${n})</option>`).join('');
  el.value=state.nc32Subnet;if(el.value!==state.nc32Subnet){state.nc32Subnet='ALL';el.value='ALL';}
}
function nc32GraphRefresh(){ncLayoutRadial();updateSnapshot(true);drawGraph();renderFocus();}
function nc32UpdatePin(){const el=$('nc32PinHost');if(!el)return;const ip=state.aliasSelectedIP,pinned=ip&&state.nc32Pinned.has(ip);el.disabled=!ip;el.innerHTML=ncIcon(pinned?'pin-off':'pin')+' '+(pinned?'Rimuovi dalla mappa':'Fissa sulla mappa');el.setAttribute('aria-pressed',pinned?'true':'false');}
const nc32OldSelectHost=nc3SelectHost;
nc3SelectHost=function(ip){nc32OldSelectHost(ip);nc32UpdatePin();};

/* A per-capture timeline notebook; limited metadata, never raw payloads. */
const nc32NewCase=nc31NewCase;
nc31NewCase=function(id){const out=nc32NewCase(id);out.timelineMarks=[];return out;};
const nc32SafeCase=nc31SafeCase;
nc31SafeCase=function(input,id){const out=nc32SafeCase(input,id);if(Array.isArray(input?.timelineMarks)){
  out.timelineMarks=input.timelineMarks.slice(0,100).filter(x=>x&&Number.isFinite(x.time)&&x.time>=0&&x.time<=state.duration&&typeof x.name==='string')
    .map(x=>({time:+x.time.toFixed(4),name:x.name.slice(0,70)}));
  }return out;};
function nc32Marks(){return state.investigation?.timelineMarks||[];}
function nc32RenderMarkOptions(){
  const list=nc32Marks(),sel=$('nc32MarkSelect');if(!sel)return;const previous=sel.value;
  sel.innerHTML='<option value="">Segnalibri ('+list.length+')</option>'+list.map((x,i)=>`<option value="${i}">${escapeHtml(x.name)} · ${formatTime(x.time,true)}</option>`).join('');
  if(previous&&Number(previous)<list.length)sel.value=previous;$('nc32MarkRemove').disabled=!sel.value;
}
async function nc32MarkAdd(){
  if(!state.packets.length||!Number.isFinite(state.duration)||state.duration<=0){notify('Timeline priva di eventi datati','Non è possibile creare un segnalibro.',true);return;}
  if(nc32Marks().length>=100){notify('Limite segnalibri raggiunto','Massimo 100 per indagine.',true);return;}
  const fallback='Evento '+formatTime(state.playhead,true);const name=await nc26Prompt('Nome del segnalibro nella timeline',fallback);if(name===null)return;
  state.investigation.timelineMarks.push({time:+state.playhead.toFixed(4),name:String(name).trim().slice(0,70)||fallback});nc31SaveCase();nc32RenderMarkOptions();drawTimeline();
}
const nc32PreviousDrawTimeline=drawTimeline;
drawTimeline=function(){nc32PreviousDrawTimeline();const canvas=$('timelineCanvas'),width=state.timelineSize.w,height=state.timelineSize.h;if(!width)return;
  const marks=nc32Marks();if(!marks.length)return;const ctx=canvas.getContext('2d');ctx.save();
  for(const mark of marks){const x=(state.duration?mark.time/state.duration:0)*width;
    ctx.strokeStyle='rgba(244,193,117,.92)';ctx.fillStyle='#efc183';ctx.lineWidth=1;ctx.setLineDash([3,3]);ctx.beginPath();ctx.moveTo(x,23);ctx.lineTo(x,height);ctx.stroke();ctx.setLineDash([]);
    ctx.beginPath();ctx.moveTo(x-5,23);ctx.lineTo(x+5,23);ctx.lineTo(x,30);ctx.closePath();ctx.fill();
  }
  ctx.restore();};

/* Selected capture bytes for export: row filters apply only on the Pacchetti page,
   explicit timeline selection applies from other views. */
function nc32SelectedPackets(){
  if(state.page==='packets')return getPacketBrowser();
  const range=state.timelineSelection;
  if(range&&Math.abs(range.end-range.start)>.025){const lo=Math.min(range.start,range.end),hi=Math.max(range.start,range.end);return state.packets.filter(p=>Number.isFinite(p.rel)&&p.rel>=lo&&p.rel<=hi);}
  return state.packets;
}
function nc32WritePcap(packets){
  if(!packets.length)throw Error('Nessun frame selezionato');const type=packets[0].linkType;
  if(packets.some(p=>!p.raw?.length||p.linkType!==type||!Number.isFinite(p.ts)))throw Error('Sono presenti link-layer differenti, byte mancanti o timestamp assenti. Utilizzare PCAPNG.');
  const size=24+packets.reduce((n,p)=>n+16+p.raw.length,0),b=new Uint8Array(size),d=new DataView(b.buffer);
  d.setUint32(0,0xa1b2c3d4,true);d.setUint16(4,2,true);d.setUint16(6,4,true);d.setUint32(16,65535,true);d.setUint32(20,type,true);
  let at=24;for(const p of packets){let sec=Math.floor(p.ts),usec=Math.round((p.ts-sec)*1e6);if(usec>=1e6){sec++;usec-=1e6;}
    if(sec<0||sec>0xffffffff)throw Error('Timestamp fuori dal campo PCAP classico. Utilizzare PCAPNG.');
    d.setUint32(at,sec,true);d.setUint32(at+4,usec,true);d.setUint32(at+8,p.raw.length,true);d.setUint32(at+12,Math.max(p.raw.length,p.length||0),true);at+=16;b.set(p.raw,at);at+=p.raw.length;
  }return b;
}
function nc32WritePcapng(packets){
  if(!packets.length)throw Error('Nessun frame selezionato');if(packets.some(p=>!p.raw?.length))throw Error('Alcuni frame selezionati sono privi di byte grezzi: esportazione annullata per evitare omissioni silenziose.');const chunks=[];let size=0;
  const push=chunk=>{chunks.push(chunk);size+=chunk.length;};
  const block=(type,length)=>{const b=new Uint8Array(length),d=new DataView(b.buffer);d.setUint32(0,type,true);d.setUint32(4,length,true);d.setUint32(length-4,length,true);return b;};
  let lastType=null;
  for(const p of packets){if(!p.raw?.length)continue;
    if(lastType!==p.linkType){lastType=p.linkType;
      const shb=block(0x0a0d0d0a,28),hd=new DataView(shb.buffer);hd.setUint32(8,0x1a2b3c4d,true);hd.setUint16(12,1,true);hd.setUint16(14,0,true);hd.setBigInt64(16,-1n,true);push(shb);
      const idb=block(1,20),dv=new DataView(idb.buffer);dv.setUint16(8,lastType,true);dv.setUint32(12,65535,true);push(idb);
    }
    const captured=p.raw.length,aligned=(captured+3)&~3,dated=Number.isFinite(p.ts);
    const bytes=block(dated?6:3,(dated?32:16)+aligned),d=new DataView(bytes.buffer);
    if(dated){const ticks=BigInt(Math.max(0,Math.round(p.ts*1e6)));d.setUint32(8,0,true);d.setUint32(12,Number((ticks>>32n)&0xffffffffn),true);d.setUint32(16,Number(ticks&0xffffffffn),true);d.setUint32(20,captured,true);d.setUint32(24,Math.max(captured,p.length||0),true);bytes.set(p.raw,28);}
    else{d.setUint32(8,Math.max(captured,p.length||0),true);bytes.set(p.raw,12);}
    push(bytes);
  }
  if(!chunks.length)throw Error('Non sono disponibili frame grezzi');const combined=new Uint8Array(size);let cursor=0;for(const chunk of chunks){combined.set(chunk,cursor);cursor+=chunk.length;}return combined;
}
async function nc32ExportCapture(){
  const packets=nc32SelectedPackets();if(!packets.length){notify('Nessun frame da esportare','Modifica i filtri o la selezione temporale.',true);return;}
  if(packets.some(p=>p.hasSensitiveData)&&!await nc26Confirm('I frame selezionati contengono credenziali o token potenzialmente in chiaro. Il file PCAP esportato li conserverà. Procedere?'))return;
  try{let data,format='pcap';try{data=nc32WritePcap(packets);}catch(err){data=nc32WritePcapng(packets);format='pcapng';}
    const name=`nullcap-${state.page==='packets'?'filtrati':state.timelineSelection?'intervallo':'cattura'}-${new Date().toISOString().slice(0,10)}.${format}`;
    nc31DownloadFile(new Blob([data],{type:'application/octet-stream'}),name);
    notify(state.isDemo?'Frame demo esportati':'Frame originali esportati',`${formatN(packets.length)} pacchetti · ${format.toUpperCase()}${state.isDemo?' · byte sintetici':''}${format==='pcapng'?' · compatibilità con formati misti/timestamp assenti':''}`);
  }catch(err){notify('Esportazione non riuscita',String(err.message||err),true);}
}

/* Parser executed off the UI thread. Worker transfers the source buffer back once
   and returns only metadata + slice offsets (not one copy per frame). */
function nc32WorkerSource(){
  const defs=[read16,read32,ipv4,mac,ipv6,protoFor,decodeDNS,decodeTransport,decodeIP,decodeFrame,makePacket,parsePcap,parsePcapng,parseCapture];
  return `'use strict';\nconst MAX_PACKETS=${MAX_PACKETS};\n`+defs.map(fn=>fn.toString()).join('\n')+`
self.onmessage=e=>{const {buffer,name}=e.data;try{const parsed=parseCapture(buffer,name);const packets=parsed.packets.map(p=>{const {raw,...rest}=p;return {...rest,rawOffset:raw.byteOffset,rawLength:raw.byteLength};});self.postMessage({ok:true,buffer,parsed:{...parsed,packets}},[buffer]);}catch(err){self.postMessage({ok:false,error:String(err?.message||err)});}};`;
}
function nc32ImportUpdate(text){const el=$('nc32ImportBar');if(el)el.classList.remove('hidden');const label=$('nc32ImportText');if(label)label.textContent=text;$('statusText').textContent=text;}
function nc32ParseCaptureAsync(buffer,name){
  const run=state.nc32ImportRun;if(!run||run.cancelled)return Promise.reject(Error('Importazione annullata'));
  if(typeof Worker==='undefined'||typeof Blob==='undefined')return Promise.resolve({parsed:parseCapture(buffer,name),buffer});
  return new Promise((resolve,reject)=>{
    let url,worker,ended=false;
    const finish=(err,result)=>{if(ended)return;ended=true;run.activeReject=null;run.worker=null;try{worker?.terminate();}catch(_){}if(url)URL.revokeObjectURL(url);err?reject(err):resolve(result);};
    try{url=URL.createObjectURL(new Blob([nc32WorkerSource()],{type:'text/javascript'}));worker=new Worker(url);run.worker=worker;run.activeReject=()=>finish(Error('Importazione annullata'));
      worker.onmessage=e=>{const msg=e.data;if(!msg?.ok){finish(Error(msg?.error||'Errore nel parser'));return;}
        const bytes=new Uint8Array(msg.buffer);
        const parsed={...msg.parsed,packets:msg.parsed.packets.map(({rawOffset,rawLength,...rest})=>({...rest,raw:bytes.subarray(rawOffset,rawOffset+rawLength)}))};
        finish(null,{parsed,buffer:msg.buffer});
      };
      worker.onerror=e=>{finish(Error('Worker di parsing non disponibile: '+(e.message||'errore sconosciuto')));};
      worker.postMessage({name,buffer},[buffer]);
    }catch(err){if(worker)finish(err);else{if(url)URL.revokeObjectURL(url);resolve({parsed:parseCapture(buffer,name),buffer});}}
  });
}
const nc32OriginalLoadFiles=loadFiles;
loadFiles=async function(files){
  const chosen=[...files].filter(Boolean);if(!chosen.length)return;
  if(state.nc32ImportRun){notify('Importazione già avviata','Annullala prima di iniziarne un’altra.',true);return;}
  const run={cancelled:false,worker:null,activeReject:null};state.nc32ImportRun=run;pauseReplay();
  let all=[],warnings=[],formats=new Set(),bytes=0,digests=[],accepted=[];
  try{
    for(let i=0;i<chosen.length;i++){
      const f=chosen[i];if(run.cancelled)break;
      if(f.size>MAX_FILE_BYTES){warnings.push(f.name+' supera il limite di 160 MB');continue;}
      if(all.length>=MAX_PACKETS){warnings.push('Limite di '+MAX_PACKETS+' pacchetti raggiunto');break;}
      try{
        nc32ImportUpdate(`Lettura ${i+1}/${chosen.length}: ${f.name}`);
        const original=await f.arrayBuffer();if(run.cancelled)break;
        nc32ImportUpdate(`Parsing offline ${i+1}/${chosen.length}: ${f.name} · ${formatBytes(f.size)}`);
        const {parsed,buffer}=await nc32ParseCaptureAsync(original,f.name);if(run.cancelled)break;
        nc32ImportUpdate(`Indicizzazione ${i+1}/${chosen.length}: ${formatN(parsed.packets.length)} frame`);
        digests.push(await nc31HashBuffer(buffer));accepted.push(f);formats.add(parsed.format);bytes+=f.size;
        const remaining=MAX_PACKETS-all.length;all.push(...parsed.packets.slice(0,remaining));
        if(parsed.truncated||parsed.packets.length>remaining)warnings.push('Importazione troncata: '+f.name);
        if(parsed.unsupported)warnings.push(`${parsed.unsupported} frame non decodificati in ${f.name}`);
        if(parsed.undated)warnings.push(`${parsed.undated} frame privi di timestamp in ${f.name}`);
      }catch(err){if(run.cancelled)break;warnings.push('File non importato: '+f.name);notify('Errore importazione '+f.name,String(err.message||err),true);}
    }
    if(run.cancelled){notify('Importazione annullata','La cattura precedente è rimasta disponibile.');return;}
    if(!all.length){notify('Nessun pacchetto disponibile','Verifica il formato e il link-layer.',true);return;}
    nc32ImportUpdate('Costruzione delle viste e analisi delle evidenze...');
    const name=chosen.length===1?chosen[0].name:`${chosen.length} catture`;
    applyCapture(all,{name,format:[...formats].join(' + '),warnings,captureId:'sha256-files:'+digests.join(':'),sourceFiles:accepted});
    notify('Importazione completata',`${formatN(all.length)} frame · ${formatBytes(bytes)} · parsing su Worker quando supportato.`);
  }finally{state.nc32ImportRun=null;$('nc32ImportBar')?.classList.add('hidden');if(!all.length)$('statusText').textContent=state.source+' · '+formatN(state.packets.length)+' pacchetti';}
};

/* TCP diagnostics: observations and approximate indicators, not definitive retransmissions. */
function nc32TCPSummary(flow){
  const last=new Map(),examples=[],limit=12000;let retrans=0,gaps=0,reset=0,syn=null,synRtt=null,measured=0;
  for(const p of flow.packets.slice(0,limit)){
    if(p.transport!=='TCP'||!p.raw?.length)continue;
    const layer=nc32BaseInspectLayers(p).find(x=>x.name==='Transmission Control Protocol');if(!layer)continue;
    const o=layer.off,raw=p.raw;if(o+20>raw.length)continue;
    const flags=raw[o+13],seq=read32(raw,o+4),ack=read32(raw,o+8),payload=Math.max(0,p.payloadBytes||0);
    const dir=p.src+'|'+p.srcPort+'>'+p.dst+'|'+p.dstPort;
    if(flags&4){reset++;if(examples.length<7)examples.push({id:p.id,label:'RST'});}
    if(flags&2&&!(flags&16))syn={src:p.src,seq,rel:p.rel};
    if((flags&18)===18&&syn&&p.src!==syn.src&&ack===(syn.seq+1)>>>0&&Number.isFinite(p.rel)&&Number.isFinite(syn.rel)){synRtt=(p.rel-syn.rel)*1000;syn=null;}
    if(payload){measured++;const expected=last.get(dir);
      if(expected!==undefined){const delta=seq-expected;if(delta<0&&Math.abs(delta)<1e9){retrans++;if(examples.length<7)examples.push({id:p.id,label:'Possibile sovrapposizione SEQ'});}
        else if(delta>0&&delta<1e9){gaps++;if(examples.length<7)examples.push({id:p.id,label:'Discontinuità SEQ'});}}
      last.set(dir,Math.max(expected===undefined?seq:expected,seq+payload));
    }
  }
  return {retrans,gaps,reset,synRtt,measured,examples,sampled:flow.packets.length>limit};
}
const nc32OldRenderFlowInspector=renderFlowInspector;
renderFlowInspector=function(){nc32OldRenderFlowInspector();const flow=state.flowMap.get(state.selectedFlow);if(!flow||flow.transport!=='TCP')return;
  const summary=nc32TCPSummary(flow),el=$('flowInspectorContent');if(!el)return;
  const region=document.createElement('section');region.className='nc32-tcp-diagnostics';region.innerHTML=`<h4>DIAGNOSTICA TCP · 3.2</h4>
    <div class="nc32-diagnostic-grid"><div><b>${formatN(summary.retrans)}</b><small>Sovrapposizioni SEQ compatibili con ritrasmissioni</small></div>
    <div><b>${formatN(summary.gaps)}</b><small>Discontinuità SEQ (perdita o fuori ordine)</small></div>
    <div><b>${formatN(summary.reset)}</b><small>Segmenti TCP con flag RST</small></div>
    <div><b>${summary.synRtt!=null&&summary.synRtt>=0?summary.synRtt.toFixed(2)+' ms':'N/D'}</b><small>Intervallo SYN → SYN/ACK osservato</small></div></div>
    ${summary.examples.map(p=>`<button class="nc313-evidence-link" data-nc32-tcp="${p.id}"><b>Frame #${p.id}</b><span>${escapeHtml(p.label)}</span></button>`).join('')}
    <p>Statistiche sui ${formatN(summary.measured)} segmenti con payload osservati${summary.sampled?' (prime 12.000 trame, analisi parziale)':''}. I numeri sono euristici: catture parziali, riordino e wrap della sequenza possono creare falsi positivi. Nessuna diagnosi di affidabilità del servizio è implicita.</p>`;
  el.append(region);region.querySelectorAll('[data-nc32-tcp]').forEach(b=>b.onclick=()=>openPacketById(Number(b.dataset.nc32Tcp)));
};

const nc32PreviousApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  state.nc32Pinned=new Set();state.nc32Subnet='ALL';state.nc32TimelineMetric='packets';$('nc32TimelineMetric').value='packets';
  nc32PreviousApplyCapture(packets,options);
  nc32SubnetOptions();nc32RenderMarkOptions();nc32UpdatePin();resizeTimeline();drawTimeline();
};
window.NullCap.applyCapture=applyCapture;
window.NullCap.deepAnalysis={protocolLayers:nc32ProtocolLayers,tcpSummary:nc32TCPSummary,writePcap:nc32WritePcap,writePcapng:nc32WritePcapng,selectedPackets:nc32SelectedPackets,subnetOf:nc32SubnetOf};
const nc32PreviousWireUI=wireUI;
wireUI=function(){nc32PreviousWireUI();
  $('exportCapture').onclick=nc32ExportCapture;
  $('nc32CancelImport').onclick=()=>{const run=state.nc32ImportRun;if(!run)return;run.cancelled=true;if(run.activeReject)run.activeReject();nc32ImportUpdate('Annullamento richiesto...');};
  $('nc32Subnet').onchange=e=>{state.nc32Subnet=e.target.value;state.selected={type:null,id:null};nc32GraphRefresh();};
  $('nc32PinHost').onclick=()=>{const ip=state.aliasSelectedIP;if(!ip)return;if(state.nc32Pinned.has(ip))state.nc32Pinned.delete(ip);else state.nc32Pinned.add(ip);
    nc32UpdatePin();nc32GraphRefresh();notify('Mappa aggiornata',state.nc32Pinned.has(ip)?'Host fissato nella mappa (nel limite dei 75 nodi).':'Host rimosso dai fissati.');};
  $('nc32TimelineMetric').onchange=e=>{state.nc32TimelineMetric=e.target.value;drawTimeline();};
  $('nc32MarkAdd').onclick=nc32MarkAdd;
  $('nc32MarkSelect').onchange=e=>{const i=Number(e.target.value);$('nc32MarkRemove').disabled=!e.target.value;if(e.target.value&&nc32Marks()[i])setPlayhead(nc32Marks()[i].time);};
  $('nc32MarkRemove').onclick=()=>{const el=$('nc32MarkSelect');if(!el.value)return;nc32Marks().splice(Number(el.value),1);nc31SaveCase();nc32RenderMarkOptions();el.value='';$('nc32MarkRemove').disabled=true;drawTimeline();};
};
