'use strict';
/* NullCap Studio 4.0 — passive, offline, evidence-based forensic workspace.
   This module does not contact endpoints, validate credentials remotely, or
   export captured secrets in its case manifests and generated reports. */
const NC40_MAX_CAPTURES=6;
const NC40_MAX_RAW_BYTES=260*1024*1024;
const NC40_EVENT_LIMIT=350;
const NC40_REPORT_EVENT_LIMIT=450;
const NC40_CASE_FORMAT='NullCap forensic workspace';
const nc40={captures:[],active:null,tab:'events',selected:null,title:'Indagine senza titolo',analyst:'',summary:'',annotations:Object.create(null),captureNotes:Object.create(null),expected:[],busy:false,compareResult:null,revision:0};
PAGE_DESCRIPTIONS.forensic=['Forensic Workspace','From packets to <em>evidence.</em>','Correliamo osservazioni, confrontiamo catture e documentiamo le evidenze senza verdetti automatici.'];
const nc40Unique=items=>[...new Set(items.filter(x=>x!==null&&x!==undefined&&x!==''))];
const nc40Clean=v=>String(v??'').replace(/\p{C}/gu,' ').trim();
const nc40Short=(v,max=180)=>nc40Clean(v).slice(0,max);
function nc40Route(route){let text=nc40Clean(route||'/').split(/[?#]/)[0];return text.slice(0,130)||'/';}
function nc40Epoch(p){return Number.isFinite(p?.ts)?p.ts:null;}
function nc40Date(ts){return Number.isFinite(ts)?new Date(ts*1000).toISOString().replace('T',' ').replace('Z',' UTC'):'Senza timestamp';}
function nc40FrameTime(slot,id){return nc40Epoch(slot.packets[Number(id)-1]);}
function nc40PacketIds(arr,limit=24){return nc40Unique((arr||[]).filter(x=>Number.isInteger(Number(x))&&Number(x)>0).map(Number)).slice(0,limit);}
function nc40Slot(id){return nc40.captures.find(c=>c.id===id)||null;}
function nc40Label(slot){return slot?slot.name+(slot.isDemo?' (demo)':''):'';}
function nc40ByteCount(){return nc40.captures.reduce((n,s)=>n+s.bytes,0);}
function nc40BuildSlotSummary(slot){
  const hosts=new Set(),services=new Set(),protocols=new Set(),seen=new Set();let payload=0,dated=0;
  for(const p of slot.packets){
    hosts.add(p.src);hosts.add(p.dst);protocols.add(p.protocol||'OTHER');
    if(p.dstPort>0&&p.transport==='TCP'||p.dstPort>0&&p.transport==='UDP')services.add(p.transport+'/'+p.dst+'/'+p.dstPort);
    if(Number.isFinite(p.ts))dated++;payload+=p.length||0;
    if(seen.size<50000)seen.add((p.src||'')+'|'+(p.dst||''));
  }
  return {hosts,services,protocols,frames:slot.packets.length,payload,dated,relations:seen.size};
}
function nc40RegisterCapture(packets,options={}){
  const id=state.captureId,name=state.source;
  if(!options.isDemo&&nc40.captures.length===1&&nc40.captures[0].isDemo)nc40.captures.length=0;
  let slot=nc40Slot(id);
  const updating=Boolean(slot);
  if(!slot&&nc40.captures.length>=NC40_MAX_CAPTURES){
    nc40.active=null;notify('Limite workspace',`La cattura è aperta, ma non registrata nel caso: massimo ${NC40_MAX_CAPTURES} acquisizioni.`,true);return null;
  }
  if(!slot){slot={id,name,packets:state.packets,format:state.format,isDemo:!!state.isDemo,bytes:0,loadedAt:new Date().toISOString(),signals:[],events:[],ready:false,revision:0};nc40.captures.push(slot);}
  else{slot.name=name;slot.packets=state.packets;slot.format=state.format;slot.isDemo=!!state.isDemo;slot.signals=[];slot.events=[];slot.ready=false;slot.revision++;}
  if(!Object.prototype.hasOwnProperty.call(nc40.captureNotes,id))nc40.captureNotes[id]=nc40Short(state.investigation?.notes||'',8000);
  if(options.sourceFiles?.length)slot.sourceFiles=Array.from(options.sourceFiles);
  slot.bytes=slot.packets.reduce((sum,p)=>sum+(p.raw?.byteLength||0),0);
  slot.start=state.start;slot.end=state.end;slot.captureWarnings=state.warnings.slice(0,15);
  slot.stats=nc40BuildSlotSummary(slot);
  slot.signals=nc40PacketSignals(slot);
  slot.events=nc40BuildEvents(slot,[]);
  nc40.active=slot.id;nc40.revision++;
  if(!updating&&nc40.captures.length===2){$('nc40Baseline').value=nc40.captures[0].id;$('nc40Candidate').value=slot.id;}
  nc40Refresh();return slot;
}
function nc40Signal(slot,rule,level,heading,explanation,limits,frames,metrics={}){
  const ids=nc40PacketIds(frames,25),p=slot.packets[ids[0]-1];
  const key=rule+'|'+nc40Short(metrics.host||metrics.src||'')+'|'+nc40Short(metrics.dst||'')+'|'+String(ids[0]||'');
  return {key,id:slot.id+':signal:'+key,captureId:slot.id,type:'indicator',rule,level,title:heading,detail:explanation,limits,frameIds:ids,metrics,time:nc40Epoch(p),why:'Regola locale '+rule+'; osservazioni limitate ai frame disponibili',confidence:'Segnale descrittivo, non verdetto di sicurezza'};
}
function nc40SlidingWindow(rows,seconds,threshold,getKey){
  // Deterministic two-pointer scan, bounded by observed timestamps; undated frames excluded.
  rows.sort((a,b)=>a.ts-b.ts||a.id-b.id);
  let best=null,start=0,counts=new Map();
  for(let end=0;end<rows.length;end++){
    const row=rows[end],value=getKey(row);counts.set(value,(counts.get(value)||0)+1);
    while(start<end&&row.ts-rows[start].ts>seconds){const k=getKey(rows[start]);const n=counts.get(k)-1;if(!n)counts.delete(k);else counts.set(k,n);start++;}
    if(counts.size>=threshold&&(!best||counts.size>best.distinct))best={distinct:counts.size,start,end};
  }
  return best?{distinct:best.distinct,rows:rows.slice(best.start,best.end+1)}:null;
}
function nc40PacketSignals(slot){
  const packets=slot.packets,signals=[],syn=new Map(),reset=new Map(),dns=new Map();
  // Observed SYNs without ACK -> many distinct destination ports of one pair in 60 seconds.
  for(const p of packets){
    if(!Number.isFinite(p.ts))continue;
    if(p.transport==='TCP'&&p.flags?.includes('SYN')&&!p.flags.includes('ACK')){
      const k=p.src+'\0'+p.dst;let a=syn.get(k);if(!a){a=[];syn.set(k,a);}a.push({ts:p.ts,id:p.id,port:p.dstPort});
    }
    if(p.transport==='TCP'&&p.flags?.includes('RST')){
      const k=p.src+'\0'+p.dst;let a=reset.get(k);if(!a){a=[];reset.set(k,a);}a.push({ts:p.ts,id:p.id});
    }
    if((p.protocol==='DNS'||p.protocol==='MDNS')&&/^Query DNS · |^Query DNS$/i.test(p.info||'')){
      const q=String(p.info||'').split(' · ').slice(1).join(' · ').toLowerCase();
      if(q){let a=dns.get(p.src);if(!a){a=[];dns.set(p.src,a);}a.push({ts:p.ts,id:p.id,name:q});}
    }
  }
  for(const [key,entries] of syn){const best=nc40SlidingWindow(entries,60,10,r=>r.port);if(!best)continue;
    const [src,dst]=key.split('\0');const ids=best.rows.length<=24?best.rows.map(x=>x.id):[...best.rows.slice(0,12),...best.rows.slice(-12)].map(x=>x.id);
    signals.push(nc40Signal(slot,'TCP_PORT_FANOUT','medium','Molte porte raggiunte con SYN',
      `${best.distinct} porte TCP di destinazione distinte raggiunte con SYN senza ACK dallo stesso client verso lo stesso host in 60 secondi.`,
      'Può essere monitoraggio, software legittimo o una cattura parziale. Non dimostra una scansione né il completamento delle connessioni.',ids,{src,dst,ports:best.distinct,seconds:60}));
  }
  for(const [key,entries] of reset){entries.sort((a,b)=>a.ts-b.ts);let start=0,best=null;
    for(let end=0;end<entries.length;end++){while(start<end&&entries[end].ts-entries[start].ts>60)start++;if(end-start+1>=8&&(!best||end-start+1>best.count))best={count:end-start+1,rows:entries.slice(start,end+1)};}
    if(!best)continue;const [src,dst]=key.split('\0');signals.push(nc40Signal(slot,'TCP_RST_BURST','info','Serie di reset TCP',
      `${best.count} segmenti con flag RST dallo stesso host verso una destinazione in 60 secondi.`,
      'I reset possono dipendere da operazioni normali, timeout, politiche di servizio e perdita di traffico.',best.rows.slice(0,24).map(x=>x.id),{src,dst,resets:best.count}));
  }
  for(const [src,entries] of dns){const best=nc40SlidingWindow(entries,120,12,r=>r.name);if(!best)continue;
    signals.push(nc40Signal(slot,'DNS_QUERY_VARIETY','info','Elevata varietà di query DNS',
      `${best.distinct} nomi distinti cercati da uno stesso client in 120 secondi.`,
      'Aggiornamenti, navigazione e software legittimo possono produrre query numerose. I nomi DNS non vengono interpretati come indicatori di compromissione.',best.rows.slice(0,24).map(x=>x.id),{src,distinctNames:best.distinct}));
  }
  const totals=new Map();for(const p of packets){if(!p.src||!p.dst)continue;const key=p.src+'\0'+p.dst;let row=totals.get(key);if(!row){row={src:p.src,dst:p.dst,bytes:0,ids:[]};totals.set(key,row);}row.bytes+=p.length||0;if(row.ids.length<18)row.ids.push(p.id);}
  for(const row of totals.values())if(row.bytes>=15*1024*1024){signals.push(nc40Signal(slot,'HIGH_TRANSFER_VOLUME','info','Trasferimento voluminoso osservato',
    `${formatBytes(row.bytes)} da ${row.src} a ${row.dst} nell'intera cattura.`,
    'Volume elevato non implica esfiltrazione. Il conteggio include intestazioni e possibili ritrasmissioni.',row.ids,{src:row.src,dst:row.dst,bytes:row.bytes}));}
  return signals.slice(0,150);
}
function nc40AuthSignals(slot,loot){
  const findings=loot.filter(a=>a.authFinding&&!a.secondary&&
    (a.authDirection==='request'&&(a.authIsLogin||a.authEvidence)||a.authDirection==='response'&&a.authResponseCredential));
  const signals=[];for(const asset of findings.slice(0,180)){
    const ids=nc40PacketIds([...(asset.packetIds||[]),...(asset.httpResponseFrameIds||[])],24);
    const route=nc40Route(asset.httpRequestRoute||'');const outcome=nc313OutcomeLabel(asset);
    const returned=asset.authDirection==='response';
    const detail=returned?'La risposta del server restituisce campi identificati come credenziali in chiaro.':
      `Credenziali o token HTTP in chiaro nella richiesta; analisi del tentativo: ${outcome}.`;
    signals.push(nc40Signal(slot,returned?'CLEARTEXT_SERVER_CREDENTIAL':'CLEARTEXT_AUTH','high',
      (returned?'Credenziali nella risposta HTTP':'Autenticazione HTTP in chiaro')+' · '+route,
      detail,'L’esposizione dei dati è osservabile nei frame; la validità delle credenziali non è provata automaticamente. Non vengono inseriti valori segreti negli indicatori.',ids,
      {src:asset.src,dst:asset.dst,outcome:returned?'Non applicabile':outcome,credentialExposed:true}));
  }
  return signals;
}
function nc40DnsTcpChains(slot){
  // Passive, bounded correlation: a DNS A record delivered to an observed client
  // followed by an outgoing SYN from the same client to that exact IPv4 address.
  // This is temporal/IP coincidence, not proof of DNS causality.
  const synByPair=new Map();
  for(const p of slot.packets){
    if(p.transport!=='TCP'||!Number.isFinite(p.ts)||!p.flags?.includes('SYN')||p.flags.includes('ACK'))continue;
    const key=p.src+'\0'+p.dst;
    if(!synByPair.has(key))synByPair.set(key,[]);
    synByPair.get(key).push(p);
  }
  for(const rows of synByPair.values())rows.sort((a,b)=>a.ts-b.ts||a.id-b.id);
  const events=[];let inspected=0;
  for(const p of slot.packets){
    if(events.length>=36||inspected>=1500)break;
    if(p.transport!=='UDP'||p.srcPort!==53||!Number.isFinite(p.ts))continue;
    inspected++;
    const payload=ncPayloadInfo(p)?.bytes;
    if(!payload||payload.length<12||payload.length>4096||!(payload[2]&0x80)||(payload[3]&15)!==0)continue;
    const decoded=nc32DnsMessage(payload,0);
    if(!decoded||decoded.fields.some(f=>f.name==='Integrità'))continue;
    for(const field of decoded.fields.filter(f=>/^Risposta \d+ · /.test(f.name))){
      if(events.length>=36)break;
      const match=/^tipo 1 · TTL \d+s · (\d{1,3}(?:\.\d{1,3}){3})$/.exec(field.value);
      if(!match)continue;
      const answerIp=match[1],client=p.dst,name=nc40Short(field.name.replace(/^Risposta \d+ · /,''),100);
      const rows=synByPair.get(client+'\0'+answerIp);
      if(!rows?.length)continue;
      let lo=0,hi=rows.length;
      while(lo<hi){const mid=(lo+hi)>>1;if(rows[mid].ts<p.ts)lo=mid+1;else hi=mid;}
      const syn=rows[lo];if(!syn||syn.ts-p.ts>120)continue;
      const seconds=Math.round((syn.ts-p.ts)*1000)/1000;
      events.push({id:slot.id+':dns-tcp:'+p.id+':'+syn.id,eventId:'dns-tcp:'+p.id+':'+syn.id,
        captureId:slot.id,type:'network',title:'Risposta DNS seguita da SYN TCP · '+name,
        detail:`Il server DNS ha restituito un record A per ${name} (${answerIp}) al client ${client}; ${seconds} s dopo è stato osservato un SYN TCP dallo stesso client verso quell’IP.`,
        time:syn.ts,frameIds:[p.id,syn.id],level:'info',src:client,dst:answerIp,
        confidence:'Correlazione temporale e di indirizzo, causalità non verificabile',
        reasons:[`Frame #${p.id}: risposta DNS A per ${name} → ${answerIp}, destinata a ${client}.`,`Frame #${syn.id}: SYN TCP da ${client} verso ${answerIp}.`],
        limits:['Non prova che il browser o il processo abbia utilizzato quella risposta DNS.',
          'Cache DNS, processi distinti, NAT, risposte multiple e pacchetti mancanti possono creare coincidenze.',
          'Non conferma un handshake riuscito, un’applicazione utilizzata o contenuti trasferiti.']});
    }
  }
  return events;
}
function nc40BuildEvents(slot,loot){
  const events=[];
  for(const signal of slot.signals){events.push({...signal,eventId:'signal:'+signal.key});}
  for(const asset of loot){
    if(asset.secondary)continue;
    const ids=nc40PacketIds([...(asset.packetIds||[]),...(asset.httpResponseFrameIds||[])],24);
    if(asset.authFinding){
      if(asset.authDirection==='response'&&asset.authResponseCredential){
        events.push({id:slot.id+':server-credential:'+asset.id,eventId:'server-credential:'+asset.id,captureId:slot.id,type:'artifact',
          title:'Credenziali esposte dalla risposta HTTP',detail:'Valori di tipo credenziale osservati nella risposta del server. La loro validità non è determinabile.',
          time:nc40FrameTime(slot,ids[0]),frameIds:ids,level:'high',limits:'La presenza di un campo credenziale non prova che sia utilizzabile; consultare i byte originali per conferma.',src:asset.src,dst:asset.dst});
        continue;
      }
      if(asset.authDirection!=='request'||(!asset.authIsLogin&&!asset.authEvidence))continue;
      const route=nc40Route(asset.httpRequestRoute||'');
      const evidence=asset.authEvidence||null;
      const outcomes={strong:'Indizi forti di accesso',probable:'Accesso probabile',failed:'Accesso rifiutato',unknown:'Esito non determinabile'};
      events.push({id:slot.id+':auth:'+asset.id,eventId:'auth:'+asset.id,captureId:slot.id,type:'auth',title:(asset.authIsLogin?'Login HTTP · ':'Autenticazione HTTP diretta · ')+route,
        detail:'Trasmissione di credenziali HTTP in chiaro; '+(outcomes[asset.authOutcome]||'esito da verificare').toLowerCase(),
        label:outcomes[asset.authOutcome]||'Esito non determinabile',time:nc40FrameTime(slot,ids[0]),frameIds:ids,
        confidence:asset.authConfidence||'non determinabile',level:asset.authOutcome==='strong'?'medium':asset.authOutcome==='failed'?'info':'high',
        reasons:(evidence?.favor||[]).slice(0,8),opposing:(evidence?.against||[]).slice(0,8),limits:(evidence?.limits||[]).slice(0,7),
        traces:(evidence?.traces||[]).slice(0,15).map(x=>({frameId:x.frameId,responseFrameId:x.responseFrameId,request:nc40Short(String(x.request||'').split('?')[0]),status:x.status||null,why:nc40Short(x.why,240)})),
        src:asset.src,dst:asset.dst});
    }else if(['image','file','email','audio'].includes(asset.kind)){
      events.push({id:slot.id+':artifact:'+asset.id,eventId:'artifact:'+asset.id,captureId:slot.id,type:'artifact',
        title:`${ncKindLabel(asset.kind)} · ${nc40Short(asset.title,90)}`,detail:'Artefatto ricostruito; aprire il Bottino per esaminare byte, completezza e provenienza.',
        time:nc40FrameTime(slot,ids[0]),frameIds:ids,level:asset.status==='partial'?'medium':'info',
        limits:'La ricostruzione può essere parziale: controllare gli stream e i frame di origine.',src:asset.src,dst:asset.dst});
    }
  }
  events.push(...nc40DnsTcpChains(slot));
  // Lightweight network anchors per capture, even before its artefact scan finishes.
  const firstPacket=slot.packets.find(p=>Number.isFinite(p.ts));
  if(firstPacket)events.push({id:slot.id+':network:first',eventId:'network:first',captureId:slot.id,type:'network',title:'Inizio traffico osservato',detail:'Primo pacchetto datato disponibile nella cattura.',time:firstPacket.ts,frameIds:[firstPacket.id],level:'info',limits:'Non equivale all’inizio reale della comunicazione.'});
  return events.sort((a,b)=>(a.time??Infinity)-(b.time??Infinity)||String(a.eventId).localeCompare(String(b.eventId)));
}
function nc40ScanCompleted(){
  const slot=nc40Slot(state.captureId);if(!slot||slot.id!==nc40.active)return;
  if(state.lootStatus!=='done'&&state.lootStatus!=='limited'&&state.lootStatus!=='error')return;
  if(slot.ready&&slot.scanGeneration===state.captureGeneration)return;
  slot.ready=true;slot.scanGeneration=state.captureGeneration;
  slot.signals=[...nc40PacketSignals(slot),...nc40AuthSignals(slot,state.loot||[])];
  slot.events=nc40BuildEvents(slot,state.loot||[]);
  slot.lootTotal=(state.loot||[]).length;slot.partial=state.lootStatus!=='done';
  nc40Refresh();
}
function nc40AllSignals(){return nc40.captures.flatMap(slot=>slot.signals||[]).sort((a,b)=>(a.time??Infinity)-(b.time??Infinity));}
function nc40AllEvents(){return nc40.captures.flatMap(slot=>slot.events||[]).sort((a,b)=>(a.time??Infinity)-(b.time??Infinity));}
function nc40SaveFields(){
  nc40.title=nc40Short($('nc40CaseTitle').value,100)||'Indagine senza titolo';
  nc40.analyst=nc40Short($('nc40Analyst').value,100);
  nc40.summary=nc40Short($('nc40Summary').value,5000);
}
function nc40RestoreFields(){
  $('nc40CaseTitle').value=nc40.title;$('nc40Analyst').value=nc40.analyst;$('nc40Summary').value=nc40.summary;
}
function nc40PopulateSelect(id,items,preferred){
  const el=$(id),previous=preferred??el.value;
  const hasAll=id==='nc40EventScope'||id==='nc40SignalScope';
  const choices=(hasAll?[['all','Tutte le catture']]:[]).concat(items.map(s=>[s.id,nc40Label(s)]));
  el.replaceChildren(...choices.map(([value,title])=>{const option=document.createElement('option');option.value=value;option.textContent=title;return option;}));
  el.value=choices.some(([value])=>value===previous)?previous:(hasAll?'all':choices[0]?.[0]||'');
}
function nc40Refresh(){
  const slots=nc40.captures,oldBase=$('nc40Baseline')?.value,oldCandidate=$('nc40Candidate')?.value;
  if(!$('nc40CaptureList'))return;
  $('nc40CaptureTotal').textContent=slots.length+' / '+NC40_MAX_CAPTURES+' catture';
  $('nc40CaptureList').innerHTML=slots.map(slot=>`<button type="button" class="nc40-capture-item ${nc40.active===slot.id?'is-active':''}" data-nc40-capture="${escapeHtml(slot.id)}" title="Apri la cattura nel Packet Browser e nelle altre viste">
    <span class="nc40-capture-title"><strong>${escapeHtml(nc40Label(slot))}</strong>${nc40.active===slot.id?'<em>ATTIVA</em>':''}</span>
    <small>${formatN(slot.stats.frames)} frame · ${formatBytes(slot.bytes)} byte grezzi · ${escapeHtml(slot.format)} · ${slot.ready?'Analisi completata':(nc40.active===slot.id?'In analisi':'Analisi approfondita non ancora eseguita')}</small>
    <small>${escapeHtml(slot.id.startsWith('sha256-files:')?'SHA-256 '+slot.id.slice(13,27)+'…':'Identificatore provvisorio / demo')}</small></button>`).join('');
  if(!slots.length)$('nc40CaptureList').innerHTML='<div class="nc40-empty">Importa una cattura PCAP/PCAPNG per iniziare.</div>';
  const unresolved=nc40.expected.filter(e=>!nc40Slot(e.id));
  $('nc40CaseStatus').textContent=unresolved.length?`${unresolved.length} acquisizioni elencate nel caso JSON non sono ancora state importate: aggiungi i relativi PCAP/PCAPNG.`:
    `Metadati locali · ${slots.length} acquisizioni in memoria · nessun payload nei file del caso`;
  nc40PopulateSelect('nc40EventScope',slots);
  nc40PopulateSelect('nc40SignalScope',slots);
  nc40PopulateSelect('nc40Baseline',slots,oldBase||slots[0]?.id);
  nc40PopulateSelect('nc40Candidate',slots,oldCandidate||slots[1]?.id||slots[0]?.id);
  nc40RenderTab();
}
function nc40SetTab(tab){
  if(!['events','signals','compare','report'].includes(tab))return;
  nc40.tab=tab;
  $('nc40Tabs').querySelectorAll('[data-nc40-tab]').forEach(btn=>{const on=btn.dataset.nc40Tab===tab;btn.classList.toggle('is-active',on);btn.setAttribute('aria-selected',on?'true':'false');});
  for(const key of ['Events','Signals','Compare','Report'])$('nc40Tab'+key).classList.toggle('hidden',key.toLowerCase()!==tab);
  nc40RenderTab();
}
function nc40RenderTab(){
  if(nc40.tab==='events')nc40RenderEvents();
  if(nc40.tab==='signals')nc40RenderSignals();
  if(nc40.tab==='compare')nc40RenderCompare();
  if(nc40.tab==='report')nc40RenderReportPreview();
  $('nc40SignalCount').textContent=String(nc40AllSignals().length);
  nc40RenderDetail();
}
function nc40EventMeta(item){const slot=nc40Slot(item.captureId);return `${nc40Date(item.time)} · ${nc40Label(slot)} · ${item.frameIds?.length||0} riferimenti frame`;}
function nc40RenderEvents(){
  const q=$('nc40EventSearch').value.trim().toLowerCase(),scope=$('nc40EventScope').value,type=$('nc40EventType').value;
  const all=nc40AllEvents(),filtered=all.filter(e=>(scope==='all'||e.captureId===scope)&&(type==='all'||e.type===type)&&
    (!q||[e.title,e.detail,e.rule,e.src,e.dst,nc40Label(nc40Slot(e.captureId))].some(v=>String(v||'').toLowerCase().includes(q))));
  $('nc40EventsCount').textContent=formatN(filtered.length)+' / '+formatN(all.length);
  const shown=filtered.slice(0,NC40_EVENT_LIMIT);
  $('nc40EventList').innerHTML=shown.map(e=>{
    const severity=e.type==='indicator'?`<span class="nc40-chip ${e.level}">${escapeHtml(({high:'EVIDENZA',medium:'DA APPROFONDIRE',info:'INFORMATIVO'})[e.level]||e.level)}</span>`:
      `<span class="nc40-chip">${escapeHtml(({auth:'LOGIN',artifact:'ARTEFATTO',network:'RETE'})[e.type]||'EVENTO')}</span>`;
    return `<button type="button" class="nc40-event ${nc40.selected===e.id?'is-active':''}" data-nc40-event="${escapeHtml(e.id)}"><span class="nc40-event-head">${severity}<span class="nc40-event-meta">${Number.isFinite(e.time)?escapeHtml(nc40Date(e.time)):'SENZA ORARIO'}</span></span><strong>${escapeHtml(e.title)}</strong><small>${escapeHtml(e.detail)}</small><span class="nc40-event-meta">${escapeHtml(nc40Label(nc40Slot(e.captureId)))} · ${e.frameIds?.length||0} frame collegati</span></button>`;
  }).join('')||'<div class="nc40-empty">Nessun evento corrispondente. Gli episodi HTTP appariranno al termine dell’analisi della cattura.</div>';
  if(filtered.length>shown.length)$('nc40EventList').insertAdjacentHTML('beforeend',`<div class="nc40-empty">Mostrati ${shown.length} di ${filtered.length} eventi. Usa ambito, tipo o ricerca per restringere la vista.</div>`);
}
function nc40RenderSignals(){
  const scope=$('nc40SignalScope').value,level=$('nc40SignalSeverity').value,all=nc40AllSignals();
  const signals=all.filter(e=>(scope==='all'||e.captureId===scope)&&(level==='all'||e.level===level));
  $('nc40SignalsHead').textContent=formatN(signals.length)+' segnali';
  $('nc40SignalList').innerHTML=signals.slice(0,NC40_EVENT_LIMIT).map(e=>`<button type="button" class="nc40-event ${nc40.selected===e.id?'is-active':''}" data-nc40-event="${escapeHtml(e.id)}"><span class="nc40-event-head"><span class="nc40-chip ${e.level}">${escapeHtml(({high:'EVIDENZA ESPOSTA',medium:'DA APPROFONDIRE',info:'INFORMATIVO'})[e.level])}</span><span class="nc40-event-meta">${escapeHtml(e.rule)}</span></span><strong>${escapeHtml(e.title)}</strong><small>${escapeHtml(e.detail)}</small><span class="nc40-event-meta">${escapeHtml(nc40Label(nc40Slot(e.captureId)))} · ${e.frameIds.length} frame campionati</span></button>`).join('')||'<div class="nc40-empty">Nessun indicatore soddisfa i criteri. L’assenza di segnali non implica l’assenza di problemi.</div>';
  if(signals.length>NC40_EVENT_LIMIT)$('nc40SignalList').insertAdjacentHTML('beforeend',`<div class="nc40-empty">Vista limitata a ${NC40_EVENT_LIMIT} di ${signals.length} segnali. Filtra la cattura o la priorità.</div>`);
}
function nc40FindSelected(){return nc40AllEvents().find(e=>e.id===nc40.selected)||nc40AllSignals().find(e=>e.id===nc40.selected)||null;}
function nc40RenderDetail(){
  const item=nc40FindSelected(),el=$('nc40Detail');
  if(!item){el.innerHTML='<div class="nc40-empty">Seleziona un evento o un indicatore per vedere criteri, motivazioni, limiti e frame sorgente. Le credenziali non vengono duplicate in questa vista.</div>';return;}
  const slot=nc40Slot(item.captureId),key=item.captureId+'|'+item.eventId,note=nc40.annotations[key]||'';
  const reasons=[...(item.reasons||[])];if(item.type==='indicator')reasons.push(item.detail);
  const obstacles=[...(item.opposing||[])];
  const limits=typeof item.limits==='string'?[item.limits]:item.limits||[];
  const list=(title,entries)=>entries.length?`<h4>${title}</h4><ul>${entries.map(x=>`<li>${escapeHtml(x)}</li>`).join('')}</ul>`:'';
  const frames=nc40PacketIds([...(item.frameIds||[]),...(item.traces||[]).flatMap(t=>[t.frameId,t.responseFrameId])],40);
  el.innerHTML=`<span class="nc40-chip ${item.level||'info'}">${escapeHtml(item.type==='indicator'?item.rule:item.type.toUpperCase())}</span><h3>${escapeHtml(item.title)}</h3>
    <p>${escapeHtml(item.detail)}</p><div class="nc40-detail-info"><b>Acquisizione:</b> ${escapeHtml(nc40Label(slot))}<br><b>Tempo:</b> ${escapeHtml(nc40Date(item.time))}<br><b>Metodo:</b> ${escapeHtml(item.type==='auth'?'Correlazione HTTP passiva della 3.1.3':item.type==='indicator'?item.why:'Ricostruzione e riferimento ai frame')}<br>${item.confidence?'<b>Confidenza:</b> '+escapeHtml(item.confidence):''}</div>
    ${list('INDIZI A FAVORE',reasons)}${list('ELEMENTI CONTRARI',obstacles)}${list('LIMITI DELLA CONCLUSIONE',limits)}
    ${item.traces?.length?'<h4>SEQUENZA DI AUTENTICAZIONE</h4><div class="nc40-detail-info">'+item.traces.map(x=>`<div>Frame #${escapeHtml(x.frameId||'?')}${x.responseFrameId?' → #'+escapeHtml(x.responseFrameId):''} · ${escapeHtml(x.request||'')} ${x.status?'· HTTP '+escapeHtml(x.status):''}<br>${escapeHtml(x.why||'')}</div>`).join('<hr style="border:0;border-top:1px solid #ffffff12;margin:8px 0">')+'</div>':''}
    <h4>PACCHETTI SORGENTE (${frames.length}${(item.frameIds||[]).length>frames.length?' campionati':''})</h4><div class="nc40-detail-links">${frames.slice(0,30).map(id=>`<button type="button" data-nc40-frame="${id}" data-nc40-slot="${escapeHtml(item.captureId)}">Frame #${id}</button>`).join('')||'<span class="nc40-subtle">Nessun frame associato</span>'}</div>
    <label class="nc40-detail-note">Annotazione dell'analista (metadato, non altera il PCAP)<textarea id="nc40Annotation" maxlength="1200" placeholder="Ipotesi, verifiche da effettuare, conclusioni ancora aperte..."></textarea></label><p class="nc40-subtle">L’annotazione viene mantenuta nella sessione corrente e può essere esportata nel caso JSON. Non inserire credenziali reali nelle note.</p>`;
  $('nc40Annotation').value=note;
  $('nc40Annotation').addEventListener('input',e=>{nc40.annotations[key]=e.target.value.slice(0,1200);});
  el.querySelectorAll('[data-nc40-frame]').forEach(btn=>btn.onclick=()=>nc40OpenFrame(btn.dataset.nc40Slot,Number(btn.dataset.nc40Frame)));
}
function nc40Choose(id){nc40.selected=id;nc40RenderTab();if(window.matchMedia('(max-width:860px)').matches)$('nc40Detail').scrollIntoView({block:'nearest',behavior:'smooth'});}
function nc40Activate(id,keepForensic=true){
  const slot=nc40Slot(id);if(!slot)return false;
  if(nc40.active===id&&state.captureId===id)return true;
  applyCapture(slot.packets,{captureId:slot.id,name:slot.name,format:slot.format,isDemo:slot.isDemo,warnings:slot.captureWarnings});
  if(Object.prototype.hasOwnProperty.call(nc40.captureNotes,id)&&nc40.captureNotes[id]&&state.investigation&&!state.investigation.notes){state.investigation.notes=nc40.captureNotes[id];nc31SaveCase();}
  if(keepForensic)setPage('forensic');
  return true;
}
function nc40OpenFrame(id,frame){if(nc40.active!==id)nc40Activate(id,false);openPacketById(frame);}
function nc40DescribeCompare(a,b){
  if(!a||!b||a.id===b.id)return null;
  const left=a.stats,right=b.stats;
  const only=(source,reference)=>[...source].filter(x=>!reference.has(x)).sort();
  return {a:a.id,b:b.id,nameA:a.name,nameB:b.name,
    packetsA:left.frames,packetsB:right.frames,bytesA:left.payload,bytesB:right.payload,
    hostsA:left.hosts.size,hostsB:right.hosts.size,
    newHosts:only(right.hosts,left.hosts),missingHosts:only(left.hosts,right.hosts),
    newProtocols:only(right.protocols,left.protocols),missingProtocols:only(left.protocols,right.protocols),
    newServices:only(right.services,left.services),missingServices:only(left.services,right.services),
    overlapHosts:[...right.hosts].filter(x=>left.hosts.has(x)).length,
    warning:'Confronto tra due insiemi di pacchetti: le differenze possono dipendere da durata, punto di cattura, traffico mancante e ora dei sistemi. "Solo in B" non implica comparsa cronologica o rischio.'};
}
function nc40RenderCompare(){
  const a=nc40Slot($('nc40Baseline').value),b=nc40Slot($('nc40Candidate').value),root=$('nc40CompareOutput');
  if(!a||!b||a.id===b.id){nc40.compareResult=null;root.innerHTML='<div class="nc40-empty">Per confrontare, aggiungi almeno due acquisizioni e seleziona catture diverse come A e B. Non è necessario che condividano lo stesso intervallo temporale.</div>';return;}
  const res=nc40DescribeCompare(a,b);nc40.compareResult=res;
  const delta=(v)=>v>0?'+'+formatN(v):formatN(v);
  const boxes=[['Pacchetti A',formatN(res.packetsA)],['Pacchetti B',formatN(res.packetsB)+' ('+delta(res.packetsB-res.packetsA)+')'],
    ['Byte A',formatBytes(res.bytesA)],['Byte B',formatBytes(res.bytesB)],['Host in comune',formatN(res.overlapHosts)],['Host solo in B',formatN(res.newHosts.length)]];
  const blocks=[['Host solo in B',res.newHosts],['Host solo in A',res.missingHosts],['Protocolli solo in B',res.newProtocols],['Protocolli solo in A',res.missingProtocols],['Servizi TCP/UDP solo in B',res.newServices],['Servizi TCP/UDP solo in A',res.missingServices]];
  root.innerHTML=`<div class="nc40-compare-cards">${boxes.map(([label,value])=>`<div class="nc40-compare-card"><strong>${escapeHtml(value)}</strong><small>${escapeHtml(label)}</small></div>`).join('')}</div>
    <div class="nc40-compare-lists">${blocks.map(([heading,values])=>`<div class="nc40-compare-list"><h4>${escapeHtml(heading)} (${formatN(values.length)})</h4>${values.length?'<ul>'+values.slice(0,100).map(x=>`<li>${escapeHtml(x)}</li>`).join('')+'</ul>':'<p>Nessuna differenza osservata.</p>'}${values.length>100?'<p>Mostrati 100 valori; il JSON report conserva il conteggio aggregato.</p>':''}</div>`).join('')}</div><p class="nc40-subtle" style="padding:2px 17px 12px">${escapeHtml(res.warning)}</p>`;
}
function nc40SafeExportEvent(e,hosts){
  const ev={captureId:e.captureId,type:e.type,title:nc40Short(e.title,220),description:nc40Short(e.detail,450),
    time:nc40Date(e.time),timestamp:Number.isFinite(e.time)?e.time:null,frames:nc40PacketIds(e.frameIds,25),
    rule:e.rule||null,level:e.level||'info',confidence:nc40Short(e.confidence||'',150),
    reasons:(e.reasons||[]).slice(0,10).map(x=>nc40Short(x,350)),
    opposing:(e.opposing||[]).slice(0,10).map(x=>nc40Short(x,350)),
    limits:(typeof e.limits==='string'?[e.limits]:e.limits||[]).slice(0,10).map(x=>nc40Short(x,350))};
  if(hosts){ev.source=e.src||e.metrics?.src||null;ev.destination=e.dst||e.metrics?.dst||null;}
  const note=nc40.annotations[e.captureId+'|'+e.eventId];if($('nc40ReportNotes').checked&&note)ev.analystNote=nc40Short(note,1200);
  if(e.traces?.length)ev.trace=e.traces.slice(0,20).map(t=>({request:nc40Short(t.request,160),status:t.status||null,frameId:t.frameId,responseFrameId:t.responseFrameId,why:nc40Short(t.why,300)}));
  return ev;
}
function nc40ReadCaptureNote(slot){
  if(slot.id===state.captureId)return String(state.investigation?.notes||'');
  try{const saved=nc31ReadCase(slot.id);return typeof saved?.notes==='string'?saved.notes:nc40.captureNotes[slot.id]||'';}
  catch{return nc40.captureNotes[slot.id]||'';}
}
function nc40CaseData(){
  nc40SaveFields();return {format:NC40_CASE_FORMAT,version:1,createdAt:new Date().toISOString(),
    case:{title:nc40.title,analyst:nc40.analyst,summary:nc40.summary},
    dossier:typeof nc24ExportDossier==='function'?nc24ExportDossier():null,
    captures:nc40.captures.map(s=>({captureId:s.id,name:s.name,format:s.format,packetCount:s.packets.length,
      sha256:s.id.startsWith('sha256-files:')?s.id.slice(13):null,
      captureNotes:s.id===state.captureId?nc40Short(state.investigation?.notes||'',8000):nc40Short(nc40ReadCaptureNote(s),8000)})),
    annotations:Object.fromEntries(Object.entries(nc40.annotations).slice(0,500).map(([key,val])=>[key,nc40Short(val,1200)])),
    warning:'Solo metadati e note fornite dall’analista. Nessun payload e nessuna password/token intercettata. Le catture originali vanno reimportate e identificate tramite SHA-256.'};
}
function nc40ExportCase(){
  const data=nc40CaseData(),json=JSON.stringify(data,null,2);
  nc31DownloadFile(new Blob([json],{type:'application/json;charset=utf-8'}),'nullcap-4-caso.json');
  notify('Caso esportato','Metadati, hash delle catture e annotazioni; nessun payload salvato.');
}
async function nc40ImportCase(file){
  if(!file)return;
  if(file.size>4*1024*1024){notify('Manifest troppo grande','Il file JSON di indagine deve essere inferiore a 4 MB.',true);return;}
  try{
    const obj=JSON.parse(await file.text());
    if(obj?.format!==NC40_CASE_FORMAT||obj.version!==1||!obj.case||!Array.isArray(obj.captures))throw Error('Formato caso non riconosciuto');
    if(obj.captures.length>NC40_MAX_CAPTURES)throw Error('Il caso contiene più catture del limite supportato');
    if(obj.captures.some(x=>typeof x.captureId!=='string'||x.captureId.length>600))throw Error('Identificatore cattura non valido');
    nc40.title=nc40Short(obj.case.title,100)||nc40.title;
    nc40.analyst=nc40Short(obj.case.analyst,100);
    nc40.summary=nc40Short(obj.case.summary,5000);
    nc40.expected=obj.captures.map(x=>({id:x.captureId,name:nc40Short(x.name,220)}));
    for(const item of obj.captures){
      if(typeof item.captureNotes==='string')nc40.captureNotes[item.captureId]=nc40Short(item.captureNotes,8000);
      if(item.captureId===state.captureId&&state.investigation&&typeof item.captureNotes==='string'){state.investigation.notes=nc40.captureNotes[item.captureId];nc31SaveCase();}
    }
    nc40.annotations=Object.create(null);
    for(const [key,val] of Object.entries(obj.annotations||{}).slice(0,500)){
      if(key.length>800||typeof val!=='string')continue;
      nc40.annotations[key]=nc40Short(val,1200);
    }
    nc40RestoreFields();if(typeof nc24ImportDossier==='function')nc24ImportDossier(obj.dossier);nc40Refresh();
    const missing=nc40.expected.filter(x=>!nc40Slot(x.id)).length;
    notify('Caso importato',missing?`Metadati ripristinati; mancano ${missing} catture. Reimportale per attivare i riferimenti ai frame.`:'Metadati ripristinati e catture già disponibili.');
  }catch(err){notify('Importazione del caso non riuscita',String(err.message||err),true);}
}
function nc40ReportData(){
  nc40SaveFields();const withHosts=$('nc40ReportHosts').checked,allEvents=nc40AllEvents(),events=allEvents.slice(0,NC40_REPORT_EVENT_LIMIT);
  const signals=nc40AllSignals();
  const compare=nc40DescribeCompare(nc40Slot($('nc40Baseline').value),nc40Slot($('nc40Candidate').value));
  const comparison=compare?{...compare,
    newHostCount:compare.newHosts.length,missingHostCount:compare.missingHosts.length,
    newServiceCount:compare.newServices.length,missingServiceCount:compare.missingServices.length,
    newHosts:withHosts?compare.newHosts:[],missingHosts:withHosts?compare.missingHosts:[],
    newServices:withHosts?compare.newServices:[],missingServices:withHosts?compare.missingServices:[],
    addressListsIncluded:withHosts}:null;
  return {format:'NullCap forensic report',version:1,generatedAt:new Date().toISOString(),
    case:{title:nc40.title,analyst:nc40.analyst,summary:nc40.summary},
    methodology:'Analisi offline e passiva su PCAP/PCAPNG. Indicatori a regole sogliate. Esito HTTP derivato dalla correlazione richiesta/risposta/sessione, senza accesso attivo a servizi.',
    captures:nc40.captures.map(s=>({name:s.name,format:s.format,sha256:s.id.startsWith('sha256-files:')?s.id.slice(13):null,
      id:s.id,frames:s.stats.frames,bytesOfFrames:s.stats.payload,datedFrames:s.stats.dated,
      hostCount:s.stats.hosts.size,serviceCount:s.stats.services.size,
      start:s.stats.dated?nc40Date(s.start):null,end:s.stats.dated?nc40Date(s.end):null,
      analysis:s.ready?(s.partial?'parziale':'completata'):'non ancora completata',warnings:s.captureWarnings})),
    totals:{captures:nc40.captures.length,events:allEvents.length,indicators:signals.length,eventsIncluded:events.length},
    events:events.map(e=>nc40SafeExportEvent(e,withHosts)),
    indicators:signals.slice(0,600).map(e=>nc40SafeExportEvent(e,withHosts)),
    comparison,
    limitations:['I frame senza timestamp non sono ordinabili cronologicamente con precisione.',
      'Eventi fra diverse acquisizioni dipendono dalla sincronizzazione degli orologi, che non viene verificata.',
      'NAT, porte riutilizzate, pacchetti mancanti o cifrati possono compromettere l’associazione delle transazioni.',
      'Gli indicatori sono osservazioni e non dimostrano attacchi o la validità delle credenziali.',
      'I report non contengono i byte originali, password, token, cookie o contenuti ricostruiti. Le annotazioni inserite manualmente sono a carico dell’analista.',
      ...(allEvents.length>events.length?[`Eventi elencati: ${events.length} su ${allEvents.length}; usa la vista locale per consultarli tutti con filtri.`]:[]),
      ...(signals.length>600?[`Indicatori esportati: 600 su ${signals.length}. La lista non è esaustiva.`]:[])]};
}
function nc40ReportHTML(report){
  const h=escapeHtml;
  const l=entries=>'<ul>'+entries.map(s=>`<li>${h(s)}</li>`).join('')+'</ul>';
  const captureRows=report.captures.map(c=>`<tr><td>${h(c.name)}<small>${h(c.format)}</small></td><td>${formatN(c.frames)}</td><td>${h(c.sha256||'N/D · demo o buffer non verificato')}</td><td>${h(c.analysis)}</td></tr>`).join('');
  const events=report.events.map(e=>`<article class="event"><div class="tags"><b>${h(e.type.toUpperCase())}</b> · ${h(e.time)} · ${h(e.captureId.slice(0,28))}</div><h3>${h(e.title)}</h3><p>${h(e.description)}</p>
    ${e.source||e.destination?`<p>Host: ${h(e.source||'?')} → ${h(e.destination||'?')}</p>`:''}
    <p>Frame: ${h(e.frames.join(', ')||'N/D')} · Confidenza: ${h(e.confidence||'non attribuita')}</p>
    ${e.reasons.length?'<h4>Motivi</h4>'+l(e.reasons):''}${e.opposing.length?'<h4>Contrari</h4>'+l(e.opposing):''}${e.limits.length?'<h4>Limiti</h4>'+l(e.limits):''}
    ${e.analystNote?`<blockquote><b>Nota analista:</b> ${h(e.analystNote)}</blockquote>`:''}</article>`).join('');
  const summary=report.case.summary?h(report.case.summary).replace(/\n/g,'<br>'):'Non specificato.';
  const indicators=report.indicators.slice(0,90).map(e=>`<tr><td>${h(e.rule||'N/D')}</td><td>${h(e.level)}</td><td>${h(e.description)}<small>Acquisizione: ${h(e.captureId.slice(0,30))} · Frame: ${h(e.frames.join(', ')||'N/D')}</small></td><td>${h(e.limits.join(' · ')||'N/D')}</td></tr>`).join('');
  const compare=report.comparison;
  const compareBlock=compare?`<p>A: <b>${h(compare.nameA)}</b> (${formatN(compare.packetsA)} frame) · B: <b>${h(compare.nameB)}</b> (${formatN(compare.packetsB)} frame).</p>
    <p>Host solo in B: <b>${formatN(compare.newHostCount)}</b> · Host solo in A: <b>${formatN(compare.missingHostCount)}</b><br>Servizi solo in B: <b>${formatN(compare.newServiceCount)}</b> · Servizi solo in A: <b>${formatN(compare.missingServiceCount)}</b></p>
    ${['newProtocols','missingProtocols','newHosts','missingHosts','newServices','missingServices'].map(k=>compare[k].length?'<h4>'+h(({newProtocols:'Protocolli solo in B',missingProtocols:'Protocolli solo in A',newHosts:'Host solo in B',missingHosts:'Host solo in A',newServices:'Servizi solo in B',missingServices:'Servizi solo in A'})[k])+'</h4>'+l(compare[k].slice(0,50)):'' ).join('')}
    ${!compare.addressListsIncluded?'<p class="muted">Indirizzi e liste dei servizi omessi per scelta di esportazione; i conteggi restano visibili.</p>':''}<p class="muted">${h(compare.warning)}</p>`:'<p>Per un confronto servono almeno due catture distinte.</p>';
  return `<!DOCTYPE html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${h(report.case.title)} | NullCap 4.0</title>
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; base-uri 'none'">
    <style>*,*:before,*:after{box-sizing:border-box}body{background:#fff;color:#162331;font:13px/1.6 Arial,sans-serif;max-width:950px;margin:30px auto;padding:0 20px}h1{font-size:30px;color:#153c48}h2{margin-top:35px;border-bottom:2px solid #d5e7e7;padding-bottom:9px;color:#245968}h3{font-size:14px;margin:6px 0}h4{margin:12px 0 5px;color:#355f6b}p{overflow-wrap:anywhere}small{display:block;color:#6c808a;font-size:10px}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{border-bottom:1px solid #e2eaed;text-align:left;padding:8px;vertical-align:top;overflow-wrap:anywhere}th{background:#eaf2f3}table.sources td:nth-child(3){font:9px/1.5 monospace;word-break:break-all}.metrics{display:flex;flex-wrap:wrap;gap:12px}.metric{border:1px solid #dae8ec;border-radius:7px;padding:12px;flex:1;min-width:135px}.metric strong{font-size:22px;display:block}.metric small{font-size:11px}.event{break-inside:avoid;border:1px solid #d8e6ea;padding:12px;margin:11px 0;border-radius:7px}.event p{margin:5px 0}.tags{color:#487584;font:10px/1.5 monospace}blockquote{margin:10px 0;padding:8px 11px;background:#f1f7f8;border-left:3px solid #5aadb0;white-space:pre-wrap}ul{margin:5px 0 12px;padding-left:21px}li{overflow-wrap:anywhere}.muted{color:#637883}footer{border-top:2px solid #d5e7e7;margin-top:30px;padding:10px 0;color:#657681;font-size:11px}@media print{body{margin:0;max-width:none;padding:0;font-size:11px}h2{break-after:avoid}.event{break-inside:avoid}@page{size:A4;margin:17mm}}</style></head>
    <body><header><div class="tags">NULLCAP STUDIO 4.0 · FORENSIC WORKSPACE · REPORT OFFLINE</div><h1>${h(report.case.title)}</h1><p>Analista: ${h(report.case.analyst||'Non indicato')}<br>Generato: ${h(report.generatedAt)}<br>Metodo: ${h(report.methodology)}</p></header>
    <h2>1. Contesto e annotazioni</h2><p>${summary}</p><h2>2. Acquisizioni e catena di riferimento</h2>
    <table class="sources"><thead><tr><th>File</th><th>Frame</th><th>SHA-256 sorgente</th><th>Stato</th></tr></thead><tbody>${captureRows}</tbody></table>
    <p class="muted">Gli hash rappresentano i file originali letti dal browser (ordine importazione per gruppi di file). Non costituiscono una firma digitale, una verifica di custodia o una prova di integrità indipendente.</p>
    <h2>3. Riepilogo</h2><div class="metrics"><div class="metric"><strong>${formatN(report.totals.captures)}</strong><small>Catture</small></div><div class="metric"><strong>${formatN(report.totals.events)}</strong><small>Eventi ricostruiti</small></div><div class="metric"><strong>${formatN(report.totals.indicators)}</strong><small>Indicatori osservativi</small></div></div>
    <h2>4. Confronto tra catture</h2>${compareBlock}
    <h2>5. Indicatori spiegabili</h2><p>Regola, osservazione e limiti dichiarati; gli indicatori non costituiscono verdetti. Elencati ${formatN(Math.min(90,report.indicators.length))} su ${formatN(report.totals.indicators)} (il JSON può contenerne fino a 600).</p>
    <table><thead><tr><th>Regola</th><th>Livello</th><th>Osservazione e provenienza</th><th>Limiti</th></tr></thead><tbody>${indicators||'<tr><td colspan="4">Nessun indicatore rilevato.</td></tr>'}</tbody></table>
    <h2>6. Evidenze e sequenze temporali</h2><p>Elencati ${formatN(report.events.length)} eventi dei ${formatN(report.totals.events)} disponibili. I riferimenti #frame sono locali alla relativa cattura.</p>${events||'<p>Nessun evento ricostruito.</p>'}
    <h2>7. Limiti e cautele interpretative</h2>${l(report.limitations)}<footer>Report offline NullCap Studio 4.0. Per verificare il contenuto e la provenienza, aprire i PCAP/PCAPNG originali e consultare i frame citati.</footer></body></html>`;
}
function nc40RenderReportPreview(){const r=nc40ReportData(),root=$('nc40ReportPreview');
  root.innerHTML=`<strong>Anteprima del report · ${escapeHtml(r.case.title)}</strong><p>${formatN(r.totals.captures)} catture · ${formatN(r.totals.events)} eventi · ${formatN(r.totals.indicators)} indicatori · ${formatN(r.totals.eventsIncluded)} eventi inclusi nel documento.</p><p>Riferimenti SHA-256 dei file disponibili, motivazioni e limiti, note dell’analista${$('nc40ReportNotes').checked?' incluse':' escluse'}. Le password e i token estratti non vengono copiati.</p><p>Per generare un PDF usa <b>Apri stampa / PDF</b> e scegli la stampante PDF del browser.</p>`;
}
function nc40DownloadReport(format){const data=nc40ReportData(),suffix='nullcap-4-report';
  if(format==='json'){nc31DownloadFile(new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'}),suffix+'.json');notify('Evidenze esportate','JSON strutturato senza payload o segreti estratti.');return;}
  const html=nc40ReportHTML(data);
  if(format==='print'){
    const popup=window.open('','_blank');if(!popup){notify('Finestra di stampa bloccata','Abilita i popup temporaneamente oppure esporta l’HTML e stampalo dal browser.',true);return;}
    popup.document.open();popup.document.write(html);popup.document.close();popup.focus();popup.addEventListener('load',()=>popup.print(),{once:true});return;
  }
  nc31DownloadFile(new Blob([html],{type:'text/html;charset=utf-8'}),suffix+'.html');notify('Report HTML esportato','Aprilo in un browser per la stampa o la conversione in PDF.');
}
async function nc40AddCaptureFiles(files){
  const chosen=Array.from(files||[]).filter(Boolean);if(!chosen.length)return;
  if(nc40.busy||state.nc32ImportRun){notify('Importazione già avviata','Completa o annulla l’importazione corrente.',true);return;}
  nc40.busy=true;
  const run={cancelled:false,worker:null,activeReject:null};state.nc32ImportRun=run;
  let inserted=0;
  try{
    for(let i=0;i<chosen.length;i++){
      const file=chosen[i];if(run.cancelled)break;
      if(nc40.captures.length>=NC40_MAX_CAPTURES){notify('Limite del caso raggiunto','Massimo sei catture. Gli ulteriori file non sono stati importati.',true);break;}
      if(file.size>MAX_FILE_BYTES){notify('File troppo grande',file.name+' supera il limite di 160 MB.',true);continue;}
      if(nc40ByteCount()+file.size>NC40_MAX_RAW_BYTES){notify('Limite memoria del workspace',`Massimo ${formatBytes(NC40_MAX_RAW_BYTES)} di byte grezzi aggregati; la cattura corrente non è stata aggiunta.`,true);break;}
      try{
        nc32ImportUpdate(`Forensic · ${i+1}/${chosen.length} · lettura ${file.name}`);
        const bytes=await file.arrayBuffer();if(run.cancelled)break;
        nc32ImportUpdate(`Forensic · parsing di ${file.name}`);
        const {parsed,buffer}=await nc32ParseCaptureAsync(bytes,file.name);if(run.cancelled)break;
        if(!parsed.packets.length){notify('Cattura senza pacchetti decodificabili',file.name,true);continue;}
        if(parsed.packets.length>MAX_PACKETS){notify('Limite frame',`Sono indicizzati solo i primi ${MAX_PACKETS} pacchetti della cattura.`,true);}
        const digest=await nc31HashBuffer(buffer);if(run.cancelled)break;
        const id='sha256-files:'+digest;
        if(nc40Slot(id)){notify('Cattura già presente',file.name+' è già disponibile nel caso.');continue;}
        const warnings=[];
        if(parsed.truncated)warnings.push('Importazione troncata');
        if(parsed.unsupported)warnings.push(`${parsed.unsupported} frame non decodificati`);
        if(parsed.undated)warnings.push(`${parsed.undated} frame senza timestamp`);
        applyCapture(parsed.packets.slice(0,MAX_PACKETS),{name:file.name,format:parsed.format,captureId:id,warnings,sourceFiles:[file]});
        inserted++;
      }catch(err){if(run.cancelled)break;notify('File non importato',nc40Short(file.name+': '+(err.message||err),260),true);}
    }
    if(run.cancelled)notify('Importazione annullata',`Caricate ${inserted} acquisizioni prima dell’annullamento.`);
    else if(inserted)notify('Catture aggiunte al caso',`${inserted} nuove acquisizioni disponibili. Le analisi HTTP più profonde vengono eseguite quando attivi una cattura.`);
  }finally{state.nc32ImportRun=null;nc40.busy=false;$('nc32ImportBar')?.classList.add('hidden');nc40Refresh();setPage('forensic');}
}
const nc40PreviousApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  nc40PreviousApplyCapture(packets,options);
  nc40RegisterCapture(packets,options);
};
window.NullCap.applyCapture=applyCapture;
const nc40PreviousLootRender=ncRenderLoot;
ncRenderLoot=function(){nc40PreviousLootRender();nc40ScanCompleted();};
const nc40PreviousSetPage=setPage;
setPage=function(page,resetScroll=true){nc40PreviousSetPage(page,resetScroll);if(page==='forensic'){nc40RenderTab();}};
const nc40PreviousWireUI=wireUI;
wireUI=function(){nc40PreviousWireUI();
  $('nc40Tabs').addEventListener('click',e=>{const b=e.target.closest('[data-nc40-tab]');if(b)nc40SetTab(b.dataset.nc40Tab);});
  $('nc40EventList').addEventListener('click',e=>{const b=e.target.closest('[data-nc40-event]');if(b)nc40Choose(b.dataset.nc40Event);});
  $('nc40SignalList').addEventListener('click',e=>{const b=e.target.closest('[data-nc40-event]');if(b)nc40Choose(b.dataset.nc40Event);});
  $('nc40CaptureList').addEventListener('click',e=>{const b=e.target.closest('[data-nc40-capture]');if(b)nc40Activate(b.dataset.nc40Capture);});
  $('nc40AddCapture').onclick=()=>$('nc40AddFiles').click();
  $('nc40AddFiles').onchange=async e=>{const files=Array.from(e.target.files);e.target.value='';await nc40AddCaptureFiles(files);};
  $('nc40EventScope').onchange=nc40RenderEvents;$('nc40EventType').onchange=nc40RenderEvents;$('nc40EventSearch').oninput=nc40RenderEvents;
  $('nc40SignalScope').onchange=nc40RenderSignals;$('nc40SignalSeverity').onchange=nc40RenderSignals;
  $('nc40Baseline').onchange=nc40RenderCompare;$('nc40Candidate').onchange=nc40RenderCompare;
  $('nc40CompareRun').onclick=nc40RenderCompare;
  $('nc40CaseTitle').oninput=e=>{nc40.title=nc40Short(e.target.value,100);if(nc40.tab==='report')nc40RenderReportPreview();};
  $('nc40Analyst').oninput=e=>{nc40.analyst=nc40Short(e.target.value,100);if(nc40.tab==='report')nc40RenderReportPreview();};
  $('nc40Summary').oninput=e=>{nc40.summary=nc40Short(e.target.value,5000);nc40RenderReportPreview();};
  $('nc40ReportNotes').onchange=nc40RenderReportPreview;$('nc40ReportHosts').onchange=nc40RenderReportPreview;
  $('nc40ExportCase').onclick=nc40ExportCase;
  $('nc40ImportCase').onclick=()=>$('nc40ImportCaseFile').click();
  $('nc40ImportCaseFile').onchange=async e=>{const file=e.target.files[0];e.target.value='';await nc40ImportCase(file);};
  $('nc40ReportHtml').onclick=()=>nc40DownloadReport('html');
  $('nc40ReportJson').onclick=()=>nc40DownloadReport('json');
  $('nc40ReportPrint').onclick=()=>nc40DownloadReport('print');
};
window.NullCap.forensic={getWorkspace:()=>nc40,compare:nc40DescribeCompare,packetSignals:nc40PacketSignals,
  allEvents:nc40AllEvents,allSignals:nc40AllSignals,reportData:nc40ReportData,reportHTML:nc40ReportHTML,
  openCapture:nc40Activate,addFiles:nc40AddCaptureFiles,exportCase:nc40CaseData};
