'use strict';
/* A10/A12 presentation for the source-preserving TCP reassembler.
   Never interprets stream segments as application-level messages. */
const nca10Selects={
  mode:{native:'streamMode',toggle:'nca10ModeToggle',value:'nca10ModeValue',menu:'nca10ModeMenu',name:'Vista'},
  direction:{native:'streamDirection',toggle:'nca10DirectionToggle',value:'nca10DirectionValue',menu:'nca10DirectionMenu',name:'Direzione'}
};
let nca10OpenMenu=null;
let nca10NotePinned=null;
const nca10SVG=name=>'<svg aria-hidden="true"><use href="#i-'+name+'"/></svg>';

function nca10CloseNotes(){
  for(const node of document.querySelectorAll('#streamModal .nca10-note.is-pinned')){
    node.classList.remove('is-pinned');node.querySelector('.nca10-note-trigger')?.setAttribute('aria-expanded','false');
  }
  nca10NotePinned=null;
}
function nca10CloseMenus(refocus=false){
  const was=nca10OpenMenu;
  for(const [,meta] of Object.entries(nca10Selects)){
    $(meta.menu)?.classList.add('hidden');$(meta.toggle)?.setAttribute('aria-expanded','false');
  }
  $('nca10ExportMenu')?.classList.add('hidden');$('nca10ExportToggle')?.setAttribute('aria-expanded','false');
  nca10OpenMenu=null;
  if(refocus&&was){
    const id=was==='export'?'nca10ExportToggle':nca10Selects[was].toggle;
    $(id)?.focus({preventScroll:true});
  }
}
window.nca10InterceptStreamEscape=function(e){
  if(nca10OpenMenu){e.preventDefault();e.stopImmediatePropagation();nca10CloseMenus(true);return true;}
  if(nca10NotePinned){e.preventDefault();e.stopImmediatePropagation();nca10CloseNotes();return true;}
  return false;
};
function nca10SyncSelect(kind){
  const meta=nca10Selects[kind],select=$(meta.native),value=$(meta.value),menu=$(meta.menu),button=$(meta.toggle);
  if(!select||!menu)return;
  const label=select.selectedOptions[0]?.textContent||select.value;
  value.textContent=label;button.setAttribute('aria-label',meta.name+': '+label);
  menu.innerHTML='<div class="nca10-menu-title">'+meta.name.toUpperCase()+'</div>'+[...select.options].map(o=>
    '<button type="button" role="option" aria-selected="'+(o.value===select.value)+'" data-a10-value="'+escapeHtml(o.value)+'"><span>'+escapeHtml(o.textContent)+'</span><svg class="nca10-selected-check" aria-hidden="true"><use href="#i-check"/></svg></button>'
  ).join('');
}
function nca10OpenSelector(kind,focusOption=false){
  const already=nca10OpenMenu===kind;
  nca10CloseMenus();nca10CloseNotes();if(already)return;
  nca10SyncSelect(kind);
  const meta=nca10Selects[kind];$(meta.menu).classList.remove('hidden');$(meta.toggle).setAttribute('aria-expanded','true');
  nca10OpenMenu=kind;
  if(focusOption)($(meta.menu).querySelector('[aria-selected="true"]')||$(meta.menu).querySelector('button'))?.focus();
}
function nca10Choose(kind,value){
  const meta=nca10Selects[kind],select=$(meta.native);
  if(![...select.options].some(o=>o.value===value))return;
  select.value=value;
  nca10CloseMenus(true);
  // The unchanged original v31.js handler controls rendering and the render budget.
  select.dispatchEvent(new Event('change',{bubbles:true}));
  nca10SyncSelect(kind);
}
function nca10OpenExport(focus=false){
  const already=nca10OpenMenu==='export';nca10CloseMenus();nca10CloseNotes();if(already)return;
  $('nca10ExportMenu').classList.remove('hidden');$('nca10ExportToggle').setAttribute('aria-expanded','true');nca10OpenMenu='export';
  if(focus)$('nca10ExportMenu').querySelector('button')?.focus();
}
function nca10NoteHTML(kind,title,items){
  const warning=kind==='warning';
  const caption=warning?'Avvisi ('+items.length+')':'Informazioni';
  const id='nca10'+(warning?'Warning':'Info')+'Popover';
  return '<div class="nca10-note '+(warning?'is-warning':'')+'" data-a10-note="'+kind+'">'+
    '<button type="button" class="nca10-note-trigger" aria-expanded="false" aria-controls="'+id+'" aria-label="'+caption+'">'+nca10SVG(warning?'alert':'info')+'</button>'+
    '<span class="nca10-note-caption">'+caption+'</span>'+
    '<div class="nca10-popover" id="'+id+'" role="tooltip"><strong>'+escapeHtml(title)+'</strong>'+
    items.map(t=>'<p>'+escapeHtml(t)+'</p>').join('')+'</div></div>';
}
function nca10SyncStream(){
  if(!nc31Stream)return;
  const s=nc31Stream;
  $('nca10EndpointA').textContent=s.a.ip+':'+s.a.port;
  $('nca10EndpointB').textContent=s.b.ip+':'+s.b.port;
  $('nca10FrameCount').textContent=formatN(s.counters.packets);
  $('nca10BytesA').textContent=formatBytes(s.limits.a);
  $('nca10BytesB').textContent=formatBytes(s.limits.b);
  if($('nca12Quality')){
    const cls=s.quality==='ambiguous'?'is-ambiguous':s.quality==='partial'?'is-partial':'is-contiguous';
    const label=s.quality==='ambiguous'?'Ricostruzione ambigua':s.quality==='partial'?'Ricostruzione parziale':'Continuità verificata';
    $('nca12Quality').className='nca12-quality '+cls;
    $('nca12Quality').textContent=label;
    $('nca12Coverage').textContent=s.counters.gaps+' lacune · '+s.counters.duplicate+' duplicati · '+s.counters.conflicts+' conflitti';
  }
  const alerts=s.warnings.filter(x=>/lacune|sovrappost|ritrasmess|Limite di|mancanti|tronc|incomplet|ambig|conflitt|inizia|senza SYN|RST|non verificat|parziale/i.test(x));
  const information=s.warnings.filter(x=>!alerts.includes(x));
  $('nca10Notices').innerHTML=(alerts.length?nca10NoteHTML('warning','Avvisi sulla ricostruzione',alerts):'')+
    (information.length?nca10NoteHTML('info','Informazioni e limiti',information):'');
  for(const kind of Object.keys(nca10Selects))nca10SyncSelect(kind);
  nca10CloseMenus();nca10CloseNotes();
}
// Render events as left/right aligned TCP *segments*, never as invented messages.
// Preserve every gap, packet ID, relative timestamp and the unmodified bytes.
nc31RenderStream=function(){
  const stream=nc31Stream;if(!stream)return;
  const dir=$('streamDirection').value,mode=$('streamMode').value,content=$('streamContent');
  const events=stream.events.filter(ev=>dir==='both'||ev.dir===dir);
  content.replaceChildren();
  const guide=document.createElement('div');guide.className='nca10-chat-guide';
  guide.innerHTML='<span class="nca10-chat-guide-a">A → B · Segmenti inviati</span><span class="nca10-chat-guide-b">B → A · Segmenti ricevuti</span>';
  content.append(guide);
  let budget=nc31StreamRenderBudget,remaining=false,shown=0;
  const maxRows=Math.min(1800,280+Math.floor(Math.max(0,nc31StreamRenderBudget-NC31_STREAM_RENDER_INITIAL)/NC31_STREAM_RENDER_STEP)*280);
  for(let idx=0;idx<events.length;idx++){
    const ev=events[idx];
    if(idx>=maxRows){remaining=true;break;}
    if(ev.kind==='gap'){
      const gap=document.createElement('div');gap.className='nc31-stream-gap nca10-stream-gap';
      const side=ev.dir==='a'?'A → B':'B → A';
      gap.innerHTML=nca10SVG('alert')+'<strong>Lacuna '+escapeHtml(side)+'</strong> · '+formatN(ev.size)+' byte mancanti prima del frame #'+formatN(ev.packetId);
      content.append(gap);continue;
    }
    if(budget<=0){remaining=true;break;}
    const cap=mode==='hex'?Math.floor(budget/4):budget;
    if(cap<16){remaining=true;break;}
    const chunk=ev.bytes.subarray(0,Math.min(ev.bytes.length,cap));
    const row=document.createElement('div');row.className='nca10-chat-row '+(ev.dir==='b'?'is-b':'is-a');
    const btn=document.createElement('button');btn.type='button';btn.className='nc31-stream-segment'+(ev.dir==='b'?' reverse':'');
    btn.dataset.streamPacket=String(ev.packetId);
    btn.setAttribute('aria-label','Apri frame #'+ev.packetId+', direzione '+(ev.dir==='a'?'A verso B':'B verso A'));
    const meta=document.createElement('div');meta.className='nc31-segment-meta';
    const text=document.createElement('strong');text.textContent=ev.dir==='a'?'A → B':'B → A';
    const stamp=document.createElement('span');stamp.className='nca10-segment-details';
    stamp.textContent='Frame #'+ev.packetId+' · '+formatN(ev.bytes.length)+' B'+(Number.isFinite(ev.rel)?' · T+'+formatTime(ev.rel,true):' · Tempo N/D');
    meta.append(text,stamp);
    const pre=document.createElement('pre');pre.textContent=nc31ReadableBytes(chunk,mode);
    if(Number.isFinite(ev.seq))btn.title='SEQ '+ev.seq+' · Intervallo relativo '+ev.start+'–'+ev.end+' · Frame '+(ev.packetIds||[ev.packetId]).join(', ');
    btn.append(meta,pre);
    btn.addEventListener('click',()=>{nc31CloseStream();openPacketById(ev.packetId);});
    row.append(btn);content.append(row);
    shown+=chunk.length;budget-=mode==='hex'?chunk.length*4:chunk.length;
    if(chunk.length<ev.bytes.length){remaining=true;break;}
  }
  if(!shown&&!events.some(ev=>ev.kind==='gap')){
    const empty=document.createElement('div');empty.className='nc31-stream-empty';
    empty.textContent='Non sono presenti byte applicativi in questa direzione.';content.append(empty);
  }
  $('streamShowMore').classList.toggle('hidden',!remaining);
};
const nca10OldOpen=nc31OpenStream;
nc31OpenStream=function(packet){
  nca10OldOpen(packet);
  if(!$('streamModal').classList.contains('hidden'))nca10SyncStream();
};
window.NullCap.openTCPStream=nc31OpenStream;
const nca10OldClose=nc31CloseStream;
nc31CloseStream=function(){nca10CloseMenus();nca10CloseNotes();nca10OldClose();};

async function nca10ExportBoth(){
  const s=nc31Stream;if(!s)return;
  const toggle=$('nca10ExportToggle');toggle.disabled=true;
  try{
    // Separate, lossless files. Never interleave unframed data from opposite directions.
    const first=new Blob(s.assembled.a,{type:'application/octet-stream'});
    const second=new Blob(s.assembled.b,{type:'application/octet-stream'});
    const manifest={format:'NullCap TCP stream export',version:2,exportType:'byte osservati deduplicati, intervalli TCP ricostruiti',
      bytePolicy:'First-observed wins; overlapping conflicting bytes are NOT silently treated as verified.',
      completeness:s.quality,sessionInfo:s.sessionInfo,
      warning:'I file .bin concatenano esclusivamente gli intervalli osservati per direzione. In presenza di lacune NON rappresentano un unico stream continuo: consultare ranges e runs.',
      endpointA:s.a,endpointB:s.b,sessionStartFrame:s.session[0]?.id??null,
      payloads:{'A-B':{name:'payload-A-B.bin',size:first.size},'B-A':{name:'payload-B-A.bin',size:second.size}},
      framesInSession:s.counters.packets,counters:s.counters,warnings:s.warnings,
      fragmentIssues:s.fragmentIssues,
      directions:Object.fromEntries(['a','b'].map(dir=>{
        const side=s.reconstruction[dir],ranges=side.ranges;
        let fileOffset=0;
        const provenance=ranges.map(r=>{
          const entry={sequenceStart:r.seq,relativeStart:r.start,relativeEnd:r.end,
            fileOffset,fileLength:r.bytes.length,frame:r.packetId,frames:r.packetIds};
          fileOffset+=r.bytes.length;return entry;
        });
        return [dir==='a'?'A-B':'B-A',{
          sequenceAnchor:side.anchor,observedBytes:side.unique,
          contiguousRanges:side.runs.map(run=>({relativeStart:run.start,relativeEnd:run.end,
            fileOffset:run.offset,byteLength:run.end-run.start})),
          gaps:side.gaps,overlapBytes:side.overlapBytes,duplicateFrames:side.duplicateFrames,
          conflicts:side.conflicts,truncated:side.truncated||side.capturedTruncated,provenance
        }];
      })),
      note:'Solo byte originali e osservati. Sequenze e conflitti ricostruiti in modo conservativo, lacune non colmate. Cifratura invariata; non sono messaggi applicativi.',
      events:s.events.map(ev=>({kind:ev.kind,direction:ev.dir==='a'?'A-B':'B-A',frame:ev.packetId,
        relativeTime:Number.isFinite(ev.rel)?ev.rel:null,sequence:ev.seq??null,relativeStart:ev.start??null,relativeEnd:ev.end??null,frames:ev.packetIds??[ev.packetId],
        byteLength:ev.kind==='gap'?ev.size:ev.bytes.length}))
    };
    const json=new Blob([JSON.stringify(manifest,null,2)],{type:'application/json;charset=utf-8'});
    const files=[['payload-A-B.bin',first],['payload-B-A.bin',second],['stream-manifest.json',json]];
    const entries=[];
    for(const [name,blob] of files)entries.push({name,blob,crc:await nc401CRC(blob)});
    const archive=nc401Zip(entries);
    nc31DownloadFile(archive,'nullcap-tcp-stream-'+(s.session[0]?.id??'capture')+'.zip');
    notify('Stream esportato','ZIP con A → B, B → A e metadati dei frame · '+formatBytes(archive.size));
  }catch(err){notify('Esportazione non riuscita',String(err?.message||err),true);}
  finally{toggle.disabled=false;}
}
function nca10BindStream(){
  for(const [kind,meta] of Object.entries(nca10Selects)){
    $(meta.toggle).addEventListener('click',()=>nca10OpenSelector(kind));
    $(meta.toggle).addEventListener('keydown',e=>{
      if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();nca10OpenSelector(kind,true);}
    });
    $(meta.menu).addEventListener('click',e=>{
      const item=e.target.closest('[data-a10-value]');if(item)nca10Choose(kind,item.dataset.a10Value);
    });
    $(meta.menu).addEventListener('keydown',e=>{
      if(!['ArrowDown','ArrowUp','Home','End'].includes(e.key))return;
      const options=[...$(meta.menu).querySelectorAll('button')];if(!options.length)return;
      e.preventDefault();const at=Math.max(0,options.indexOf(document.activeElement));
      const next=e.key==='Home'?0:e.key==='End'?options.length-1:(at+(e.key==='ArrowDown'?1:-1)+options.length)%options.length;
      options[next].focus();
    });
    $(meta.native).addEventListener('change',()=>nca10SyncSelect(kind));
  }
  $('nca10ExportToggle').addEventListener('click',()=>nca10OpenExport());
  $('nca10ExportToggle').addEventListener('keydown',e=>{
    if(e.key==='ArrowDown'){e.preventDefault();nca10OpenExport(true);}
  });
  $('nca10ExportMenu').addEventListener('click',e=>{
    const item=e.target.closest('[data-a10-export]');if(!item)return;
    const choice=item.dataset.a10Export;nca10CloseMenus(true);
    if(choice==='both')void nca10ExportBoth();else if(choice==='a'||choice==='b')nc31DownloadStream(choice);
  });
  $('nca10ExportMenu').addEventListener('keydown',e=>{
    if(!['ArrowDown','ArrowUp','Home','End'].includes(e.key))return;
    const opts=[...$('nca10ExportMenu').querySelectorAll('button')];e.preventDefault();
    const at=Math.max(0,opts.indexOf(document.activeElement));
    const next=e.key==='Home'?0:e.key==='End'?opts.length-1:(at+(e.key==='ArrowDown'?1:-1)+opts.length)%opts.length;
    opts[next].focus();
  });
  $('streamModal').addEventListener('click',e=>{
    const trigger=e.target.closest('.nca10-note-trigger');
    if(trigger){
      const holder=trigger.closest('.nca10-note');const pinned=holder.classList.contains('is-pinned');
      nca10CloseNotes();nca10CloseMenus();
      if(!pinned){holder.classList.add('is-pinned');trigger.setAttribute('aria-expanded','true');nca10NotePinned=holder;}
    }
  });
  document.addEventListener('pointerdown',e=>{
    if($('streamModal').classList.contains('hidden'))return;
    if(nca10OpenMenu){
      const element=nca10OpenMenu==='export'?$('nca10ExportMenu'):$(nca10Selects[nca10OpenMenu].menu);
      const trigger=nca10OpenMenu==='export'?$('nca10ExportToggle'):$(nca10Selects[nca10OpenMenu].toggle);
      if(!element.contains(e.target)&&!trigger.contains(e.target))nca10CloseMenus();
    }
    if(nca10NotePinned&&!nca10NotePinned.contains(e.target))nca10CloseNotes();
  });
  // Closing a modal also resets any transient inner menus; no state leaks between openings.
  nca10CloseMenus();
}
const nca10PreviousWireUI=wireUI;
wireUI=function(){nca10PreviousWireUI();nca10BindStream();};
